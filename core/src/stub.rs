//! The local stub resolver: plain DNS on loopback in, RFC 8484 DoH out.
//!
//! This is the whole reason a Windows 10 client has to be an application at all. Windows 10 has
//! no native DoH — the cmdlets are simply absent from the `DnsClient` module — and our nodes do
//! not answer plain `:53` from the internet (`PLAIN53_PUBLIC` defaults to `no`), so pointing an
//! adapter straight at the resolver addresses on that build yields not "unencrypted DNS" but no
//! DNS at all. The adapter points here instead.
//!
//! **The stub is deliberately transparent.** It does not parse, cache, or rewrite queries: the
//! wire-format message that arrives on 127.0.0.1 is the exact body POSTed upstream, and the
//! upstream body is the exact answer written back. Flags, EDNS options and the DNSSEC bits pass
//! through untouched, which means the answer a client sees is the one the resolver produced —
//! including the split-horizon answers for the AI-API names, which are made at the dnsdist edge.
//! The only message this module ever composes itself is a SERVFAIL when the upstream is
//! unreachable.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::config::{self, DOH_URL, RESOLVER_HOST, STUB_V4, UPSTREAM_TIMEOUT_SECS};

const DNS_PORT: u16 = 53;
const DNS_MESSAGE: &str = "application/dns-message";
/// EDNS0 buffers commonly advertise 4096; anything larger belongs on TCP.
const MAX_UDP: usize = 4096;
const MAX_TCP: usize = 65535;

#[derive(Default)]
pub struct Stats {
    pub queries: AtomicU64,
    pub errors: AtomicU64,
    pub last_error: Mutex<Option<String>>,
}

impl Stats {
    fn record_error(&self, e: impl std::fmt::Display) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        let text = e.to_string();
        log::warn!("upstream query failed: {text}");
        if let Ok(mut slot) = self.last_error.lock() {
            *slot = Some(text);
        }
    }

    pub fn snapshot(&self) -> (u64, u64, Option<String>) {
        (
            self.queries.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
            self.last_error.lock().ok().and_then(|g| g.clone()),
        )
    }
}

/// How long `stop` lets queries already on their way upstream finish before cancelling them.
///
/// Short, because the stub stops only after the adapters no longer point at it: whoever asked
/// these queries has been handed their previous DNS and is not waiting on us any more.
const STOP_GRACE: Duration = Duration::from_secs(1);

pub struct StubHandle {
    shutdown: watch::Sender<bool>,
    listeners: JoinSet<()>,
    pub listening: Vec<SocketAddr>,
}

impl StubHandle {
    /// Stops every listener and returns once their sockets are closed.
    ///
    /// Returning as soon as the signal was sent is what made a settings change leave protection
    /// off: `App::set_settings` stops and immediately starts again, and a socket still held by a
    /// query waiting on its upstream failed the new bind with 10048. Each listener gives its
    /// queries `STOP_GRACE` and then cancels them; the outer limit only guards that reasoning.
    pub async fn stop(mut self) {
        let _ = self.shutdown.send(true);
        let limit = STOP_GRACE * 3;
        let joined = tokio::time::timeout(limit, async {
            while self.listeners.join_next().await.is_some() {}
        })
        .await;
        if joined.is_err() {
            log::error!("the stub's listeners did not stop within {limit:?}; abandoning them");
            self.listeners.abort_all();
        }
    }
}

/// Lets a listener's tasks finish for up to `STOP_GRACE`, then cancels the rest and waits for them
/// to be gone. A cancelled task drops everything it holds, and that includes the socket.
async fn drain(mut tasks: JoinSet<()>) {
    let deadline = tokio::time::Instant::now() + STOP_GRACE;
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(_)) => {}
            Ok(None) => return,
            Err(_) => {
                log::info!("cancelling {} request(s) still in flight at stop", tasks.len());
                tasks.shutdown().await;
                return;
            }
        }
    }
}

/// How many failed queries in a row mean "this is not a blip".
///
/// Low on purpose: when the upstream is gone every query fails, so five of them is a second or
/// two. What keeps this from becoming a retry storm is not the count but the cooldown inside
/// [`crate::endpoints`], which survives a reboot.
const FAILURES_BEFORE_RESCUE: u32 = 5;

/// The part of the stub that notices the resolver has gone away and goes looking for it.
///
/// It owns the sending half of the client channel, which is what makes recovery possible at all:
/// the addresses are fixed when the HTTPS clients are built, so a new address list means new
/// clients, and every serving task has to start using them without being restarted.
struct Recovery {
    failures: AtomicU32,
    /// One rescue at a time. Without this, a machine with no DNS spawns one per failed query.
    searching: AtomicBool,
    client: watch::Sender<Upstream>,
}

impl Recovery {
    fn new(client: watch::Sender<Upstream>) -> Self {
        Self {
            failures: AtomicU32::new(0),
            searching: AtomicBool::new(false),
            client,
        }
    }

    fn success(&self) {
        self.failures.store(0, Ordering::Relaxed);
    }

    fn failure(self: &Arc<Self>) {
        let n = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= FAILURES_BEFORE_RESCUE && n % FAILURES_BEFORE_RESCUE == 0 {
            self.search();
        }
    }

    /// Ask the outside world where the resolver went, and start using the answer.
    fn search(self: &Arc<Self>) {
        if self.searching.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            if crate::endpoints::rescue().await {
                me.rebuild();
            }
            me.searching.store(false, Ordering::SeqCst);
        });
    }

    /// Replace the HTTPS clients with ones aimed at the current address list.
    fn rebuild(&self) {
        match Upstream::build(&config::bootstrap_addrs()) {
            Ok(upstream) => {
                let _ = self.client.send(upstream);
                self.failures.store(0, Ordering::Relaxed);
                log::info!("upstream client rebuilt for the new address list");
            }
            Err(e) => log::warn!("could not rebuild the upstream client: {e:#}"),
        }
    }
}

/// How many addresses one query may try before it gives up and answers SERVFAIL.
///
/// The rest of the list is walked by the queries that follow, not by this one: Windows abandons a
/// server after about two seconds, so a query that tried every address would be answering nobody.
const TRIES_PER_QUERY: usize = 3;

/// A dead address should cost a fraction of the time Windows is prepared to wait.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);

/// One HTTPS client per address, and which of them answered last.
///
/// **One address per client, because reqwest only moves on when a TCP connect fails.** Handed a
/// list, it returns a failed TLS handshake as the answer instead of trying the next address — and a
/// released address now serving somebody else's HTTPS on 443 accepts the connection and fails the
/// handshake, which is exactly the case this list exists for. Measured: a cache naming a GitHub
/// address failed every query with the compiled-in addresses right behind it.
#[derive(Clone)]
pub(crate) struct Upstream {
    routes: Arc<Vec<Client>>,
    preferred: Arc<AtomicUsize>,
}

impl Upstream {
    fn build(addrs: &[SocketAddr]) -> Result<Self> {
        let routes = addrs
            .iter()
            .map(|addr| build_client(*addr))
            .collect::<Result<Vec<_>>>()?;
        if routes.is_empty() {
            anyhow::bail!("no resolver address to connect to");
        }
        Ok(Self {
            routes: Arc::new(routes),
            preferred: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// One query, starting from the address that answered last.
    async fn forward(&self, query: &[u8]) -> Result<Vec<u8>> {
        let n = self.routes.len();
        let start = self.preferred.load(Ordering::Relaxed) % n;
        let tries = n.min(TRIES_PER_QUERY);
        let mut last = None;
        for k in 0..tries {
            let i = (start + k) % n;
            match post(&self.routes[i], query).await {
                Ok(answer) => {
                    if k > 0 {
                        self.preferred.store(i, Ordering::Relaxed);
                    }
                    return Ok(answer);
                }
                Err(e) => last = Some(e),
            }
        }
        self.preferred
            .store((start + tries) % n, Ordering::Relaxed);
        Err(last.unwrap_or_else(|| anyhow::anyhow!("no resolver address was tried")))
    }
}

fn build_client(addr: SocketAddr) -> Result<Client> {
    Client::builder()
        .use_rustls_tls()
        .https_only(true)
        // **No proxy, ever, and this was measured rather than reasoned about.** `reqwest` reads
        // `HTTPS_PROXY` from the environment by default. On a machine where something had set it —
        // a developer shell, a VPN client, a corporate login script — every DoH request became a
        // `CONNECT` to that proxy, the proxy refused to tunnel to our address, and the client
        // reported `tunnel error: unsuccessful`. From the outside that is a machine with no DNS at
        // all, and nothing on screen says why.
        //
        // A proxy is also incompatible with what this client is: the resolver's addresses are
        // pinned into the binary so that resolving `dns.dns-ai.ru` can never loop back through us,
        // and a proxy would resolve the name itself — the one thing the pinning exists to prevent.
        .no_proxy()
        // The addresses, handed to the HTTP client directly. This is what keeps the bootstrap from
        // looping back into ourselves once the adapter points at 127.0.0.1; `RESOLVER_HOST` is
        // still what the certificate is checked against, and it is still compiled in — the list
        // below may be refreshed from the network, the name it is checked against never is
        // (`crate::endpoints`).
        .resolve(RESOLVER_HOST, addr)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(Duration::from_secs(UPSTREAM_TIMEOUT_SECS))
        .pool_idle_timeout(Duration::from_secs(90))
        .user_agent(concat!("dns-ai-client/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("could not build the HTTPS client")
}

/// Binds the loopback listeners and starts serving.
///
/// Failing to bind IPv4 is fatal and says so: something else already owns UDP/53 (Internet
/// Connection Sharing, Hyper-V/WSL/Docker, a WinNAT reserved port range). Failing to bind IPv6 is
/// a warning — plenty of machines have it switched off, and that is not our business to fix.
pub async fn start(ipv6: bool, stats: Arc<Stats>) -> Result<StubHandle> {
    let mut targets = vec![SocketAddr::new(IpAddr::V4(STUB_V4), DNS_PORT)];
    if ipv6 {
        targets.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), DNS_PORT));
    }
    let upstream = Upstream::build(&config::bootstrap_addrs())?;
    let (handle, client, recovery) = listen(targets, upstream, stats).await?;
    refresh(client, recovery);
    Ok(handle)
}

/// The binding and serving half of [`start`], on whatever addresses it is given — so a test can
/// run it on a free port instead of taking 53 from the resolver this machine is actually using.
async fn listen(
    targets: Vec<SocketAddr>,
    upstream: Upstream,
    stats: Arc<Stats>,
) -> Result<(StubHandle, watch::Receiver<Upstream>, Arc<Recovery>)> {
    let (client_tx, client) = watch::channel(upstream);
    let recovery = Arc::new(Recovery::new(client_tx));
    let (tx, _) = watch::channel(false);

    let mut listening = Vec::new();
    let mut listeners = JoinSet::new();
    for addr in targets {
        let required = addr.is_ipv4();
        match bind_pair(addr).await {
            Ok((udp, tcp)) => {
                listening.push(addr);
                listeners.spawn(serve_udp(
                    udp,
                    client.clone(),
                    stats.clone(),
                    recovery.clone(),
                    tx.subscribe(),
                ));
                listeners.spawn(serve_tcp(
                    tcp,
                    client.clone(),
                    stats.clone(),
                    recovery.clone(),
                    tx.subscribe(),
                ));
                log::info!("stub listening on {addr} (UDP and TCP)");
            }
            Err(e) if required => {
                return Err(e).with_context(|| {
                    format!(
                        "cannot listen on {addr} — another program already owns port {}",
                        addr.port()
                    )
                })
            }
            Err(e) => log::warn!("not listening on {addr}: {e:#}"),
        }
    }

    let handle = StubHandle {
        shutdown: tx,
        listeners,
        listening,
    };
    Ok((handle, client, recovery))
}

/// Opens the upstream connection before anything is waiting on it.
///
/// Measured, not theoretical: the first query after «Включить защиту» used to time out. The HTTPS
/// connection is established lazily, so that query paid a TCP handshake, a TLS handshake and an
/// HTTP/2 preface — and Windows' resolver gives up on a server at around two seconds and reports
/// nothing at all. To the user the client had just broken DNS.
///
/// Detached on purpose: enabling must not wait for the network, and a warm-up that fails changes
/// nothing except that the next query pays what it would have paid anyway.
///
/// **It also keeps the answer now, and that is the cheapest half of the whole update mechanism.**
/// The query it has always sent is `dns.dns-ai.ru A` — which is precisely the list of addresses
/// this client should be connecting to, answered by the resolver itself over a connection already
/// authenticated as `RESOLVER_HOST`. Reading it costs one parse of bytes we were throwing away,
/// involves no third party, and cannot go stale the way a hand-maintained copy of the addresses
/// would (`crate::endpoints`).
///
/// A failure here is the other half: it is the first evidence that the addresses this build knows
/// about have stopped being where the resolver is, so it starts the search rather than waiting for
/// five user queries to fail first.
fn refresh(client: watch::Receiver<Upstream>, recovery: Arc<Recovery>) {
    tokio::spawn(async move {
        let current = client.borrow().clone();
        match lookup_self(&current).await {
            Ok((v4, v6)) => {
                log::info!("upstream connection is warm; {RESOLVER_HOST} is at {v4:?} {v6:?}");
                recovery.success();
                if crate::endpoints::learn(&v4, &v6) {
                    recovery.rebuild();
                }
            }
            Err(e) => {
                log::warn!("warm-up query failed: {e:#}");
                recovery.search();
            }
        }
    });
}

/// Ask the resolver where it is.
///
/// The A query is the one that decides: without it there is nothing to learn and the caller treats
/// that as a failure. The AAAA query is best-effort — a machine with no IPv6 route may not get one
/// through at all, and an empty v6 answer must not be mistaken for "the resolver has no v6", which
/// is why [`crate::endpoints::learn`] keeps the previous v6 list when this comes back empty.
async fn lookup_self(client: &Upstream) -> Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>)> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    let query = crate::dnsmsg::build_query(RESOLVER_HOST, crate::dnsmsg::TYPE_A, 0)?;
    let answer = client.forward(&query).await?;
    sort_addresses(crate::dnsmsg::addresses(&answer), &mut v4, &mut v6);

    if let Ok(query) = crate::dnsmsg::build_query(RESOLVER_HOST, crate::dnsmsg::TYPE_AAAA, 0) {
        match client.forward(&query).await {
            Ok(answer) => sort_addresses(crate::dnsmsg::addresses(&answer), &mut v4, &mut v6),
            Err(e) => log::debug!("AAAA for {RESOLVER_HOST} did not come back: {e:#}"),
        }
    }

    Ok((v4, v6))
}

fn sort_addresses(addrs: Vec<IpAddr>, v4: &mut Vec<Ipv4Addr>, v6: &mut Vec<Ipv6Addr>) {
    for ip in addrs {
        match ip {
            IpAddr::V4(a) => {
                if !v4.contains(&a) {
                    v4.push(a);
                }
            }
            IpAddr::V6(a) => {
                if !v6.contains(&a) {
                    v6.push(a);
                }
            }
        }
    }
}

async fn bind_pair(addr: SocketAddr) -> Result<(UdpSocket, TcpListener)> {
    let udp = UdpSocket::bind(addr).await.context("UDP bind")?;
    let tcp = TcpListener::bind(addr).await.context("TCP bind")?;
    Ok((udp, tcp))
}

async fn serve_udp(
    sock: UdpSocket,
    client: watch::Receiver<Upstream>,
    stats: Arc<Stats>,
    recovery: Arc<Recovery>,
    mut shutdown: watch::Receiver<bool>,
) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; MAX_UDP];
    // Every query task holds a reference to the socket, so it closes only once the last of them
    // is gone. Tracked here so that `stop` can wait for exactly that.
    let mut in_flight = JoinSet::new();
    loop {
        let (len, from) = tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = in_flight.join_next(), if !in_flight.is_empty() => continue,
            r = sock.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(e) => { log::warn!("UDP recv failed: {e}"); continue }
            }
        };
        let query = buf[..len].to_vec();
        // The client is read per query rather than captured once: an address list learned or
        // rescued while this listener is running arrives as a new client on this channel, and a
        // task holding a copy of the old one would keep dialling an address that is gone.
        let client = client.borrow().clone();
        let (sock, stats, recovery) = (sock.clone(), stats.clone(), recovery.clone());
        in_flight.spawn(async move {
            stats.queries.fetch_add(1, Ordering::Relaxed);
            let reply = match client.forward(&query).await {
                Ok(mut answer) => {
                    recovery.success();
                    // A truncated answer over UDP is normal and correct: the client retries
                    // over TCP, which we also serve. Truncate at the advertised limit rather
                    // than dropping the datagram.
                    if answer.len() > MAX_UDP {
                        answer.truncate(MAX_UDP);
                    }
                    answer
                }
                Err(e) => {
                    stats.record_error(e);
                    recovery.failure();
                    match servfail(&query) {
                        Some(m) => m,
                        None => return,
                    }
                }
            };
            if let Err(e) = sock.send_to(&reply, from).await {
                log::warn!("UDP send to {from} failed: {e}");
            }
        });
    }
    drain(in_flight).await;
    log::info!("UDP listener stopped");
}

async fn serve_tcp(
    listener: TcpListener,
    client: watch::Receiver<Upstream>,
    stats: Arc<Stats>,
    recovery: Arc<Recovery>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    loop {
        let (stream, _peer) = tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => { log::warn!("TCP accept failed: {e}"); continue }
            }
        };
        let (client, stats, recovery) = (client.clone(), stats.clone(), recovery.clone());
        let stop = shutdown.clone();
        connections.spawn(async move {
            if let Err(e) = serve_tcp_conn(stream, client, stats, recovery, stop).await {
                log::debug!("TCP connection ended: {e:#}");
            }
        });
    }
    drop(listener);
    drain(connections).await;
    log::info!("TCP listener stopped");
}

async fn serve_tcp_conn(
    mut stream: TcpStream,
    client: watch::Receiver<Upstream>,
    stats: Arc<Stats>,
    recovery: Arc<Recovery>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        // A closed connection between queries is the normal end of a DNS/TCP session, not an
        // error worth logging as one. Between queries is also where `stop` ends it at once rather
        // than after the idle timeout; a query already being answered is left to `drain`.
        tokio::select! {
            _ = stop.changed() => return Ok(()),
            r = tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut len_buf)) => {
                match r {
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) | Err(_) => return Ok(()),
                }
            }
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_TCP {
            return Ok(());
        }
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await?;

        stats.queries.fetch_add(1, Ordering::Relaxed);
        let upstream = client.borrow().clone();
        let reply = match upstream.forward(&query).await {
            Ok(answer) => {
                recovery.success();
                answer
            }
            Err(e) => {
                stats.record_error(e);
                recovery.failure();
                match servfail(&query) {
                    Some(m) => m,
                    None => return Ok(()),
                }
            }
        };
        stream
            .write_all(&(reply.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(&reply).await?;
    }
}

/// Sends a single query over DoH without starting any listener or touching the machine.
///
/// This is the diagnostic path: it proves the resolver is reachable, that the certificate
/// validates, and that this source address is inside the RU/BY scope — all before the client is
/// allowed to rewrite the machine's DNS settings.
pub async fn query_once(query: &[u8]) -> Result<Vec<u8>> {
    Upstream::build(&config::bootstrap_addrs())?
        .forward(query)
        .await
}

/// One lookup, no listeners: where is `dns.dns-ai.ru` right now?
///
/// `None` means nothing answered — which is a different fact from "the list did not change", and
/// the caller acts on it: in native mode it is the only warning that the addresses about to be
/// written into an adapter may be dead.
///
/// **Native mode is why this is a separate entry point.** There the adapters carry the resolver's
/// own addresses and Windows does the DoH, so nothing of ours is in the query path and there is no
/// warm-up to learn from — but that mode is also the one where a stale address is worst, because
/// the program is not running when it fails. So the addresses are checked in the moment before
/// they are written into an adapter.
///
/// `budget` is short and deliberate. This runs on the path of a user pressing «Включить» and at
/// boot, where the network may not be up at all; the fallback is the list we already have, and a
/// user waiting is a worse failure than an address that is one enable out of date.
pub async fn refresh_endpoints(budget: Duration) -> Option<bool> {
    let client = match Upstream::build(&config::bootstrap_addrs()) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("could not check where the resolver is: {e:#}");
            return None;
        }
    };
    match tokio::time::timeout(budget, lookup_self(&client)).await {
        Ok(Ok((v4, v6))) => Some(crate::endpoints::learn(&v4, &v6)),
        Ok(Err(e)) => {
            log::warn!("could not check where the resolver is: {e:#}");
            None
        }
        Err(_) => {
            log::warn!("the resolver did not say where it is within {budget:?}");
            None
        }
    }
}

/// One query, one POST, one address. The body goes up and comes back untouched.
async fn post(client: &Client, query: &[u8]) -> Result<Vec<u8>> {
    let resp = client
        .post(DOH_URL)
        .header(CONTENT_TYPE, DNS_MESSAGE)
        .header(ACCEPT, DNS_MESSAGE)
        .body(query.to_vec())
        .send()
        .await
        .context("POST to the resolver failed")?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("resolver answered HTTP {status}");
    }
    let body = resp.bytes().await.context("could not read the answer")?;
    if body.len() < 12 {
        anyhow::bail!("resolver answered {} bytes, too short for DNS", body.len());
    }
    Ok(body.to_vec())
}

/// Builds a SERVFAIL for a query we could not forward.
///
/// Without this the client waits out its own timeout on every failure, which is how "the
/// internet is slow" gets reported instead of "the resolver is unreachable". Header and question
/// are echoed; everything else is cleared.
fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    let mut end = 12;
    if qdcount == 1 {
        // Walk the QNAME. A question section never uses compression, so a pointer here means
        // the query is malformed and we answer with the header alone.
        loop {
            let label = *query.get(end)? as usize;
            if label & 0xC0 != 0 {
                return None;
            }
            end += 1;
            if label == 0 {
                break;
            }
            end += label;
            if end >= query.len() {
                return None;
            }
        }
        end += 4; // QTYPE + QCLASS
        if end > query.len() {
            return None;
        }
    }

    let mut out = query[..end].to_vec();
    // byte 2: QR | Opcode(4) | AA | TC | RD  — keep the opcode and RD, set QR, clear AA/TC.
    out[2] = (query[2] & 0b0111_1001) | 0b1000_0000;
    // byte 3: RA | Z | AD | CD | RCODE(4)    — recursion available, RCODE 2 (SERVFAIL).
    out[3] = 0b1000_0000 | 2;
    out[4] = 0;
    out[5] = if qdcount == 1 { 1 } else { 0 };
    out[6..12].fill(0); // no answer, authority or additional records
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal A query for `example.com`, built by hand so the test does not depend on the
    /// code under test to produce its own input.
    fn sample_query() -> Vec<u8> {
        let mut q = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // RD
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        q.extend_from_slice(b"\x07example\x03com\x00");
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        q
    }

    #[test]
    fn servfail_echoes_id_and_question() {
        let q = sample_query();
        let r = servfail(&q).expect("a well-formed query gets a SERVFAIL");
        assert_eq!(
            &r[0..2],
            &q[0..2],
            "the ID must come back or the client ignores it"
        );
        assert_eq!(r[2] & 0x80, 0x80, "QR must be set");
        assert_eq!(r[2] & 0x01, 0x01, "RD must be preserved");
        assert_eq!(r[3] & 0x0F, 2, "RCODE must be SERVFAIL");
        assert_eq!(u16::from_be_bytes([r[4], r[5]]), 1);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "no answers");
        assert_eq!(r.len(), q.len(), "header plus question, nothing else");
    }

    /// Accepts TCP and never answers, so a DoH request to it hangs in the TLS handshake until the
    /// client's own timeout: a query in flight, on demand, with no network involved.
    async fn black_hole() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        addr
    }

    /// A loopback port free for UDP and TCP both, since the stub binds the pair.
    fn free_port() -> SocketAddr {
        loop {
            let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = udp.local_addr().unwrap();
            if std::net::TcpListener::bind(addr).is_ok() {
                return addr;
            }
        }
    }

    async fn listen_on(addr: SocketAddr, upstream: SocketAddr) -> Result<StubHandle> {
        let upstream = Upstream::build(&[upstream])?;
        let (handle, _, _) = listen(vec![addr], upstream, Arc::new(Stats::default())).await?;
        Ok(handle)
    }

    /// `App::set_settings` turns protection off and on again. A query still waiting on its
    /// upstream kept UDP/53 open past `stop`, so the second bind failed with "another program
    /// already owns port 53" and the machine was left unprotected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_query_in_flight_does_not_keep_the_port_after_stop() {
        let hole = black_hole().await;
        let addr = free_port();
        let stub = listen_on(addr, hole).await.unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&sample_query(), addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let started = std::time::Instant::now();
        stub.stop().await;
        let took = started.elapsed();
        assert!(took < Duration::from_secs(3), "stop took {took:?}");

        match listen_on(addr, hole).await {
            Ok(stub) => stub.stop().await,
            Err(e) => panic!("the port was still held after stop: {e:#}"),
        }
    }

    /// A DNS-over-TCP client that connected and went quiet held its connection task for the
    /// whole 20 s idle timeout after `stop`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_idle_tcp_client_is_closed_by_stop() {
        let hole = black_hole().await;
        let addr = free_port();
        let stub = listen_on(addr, hole).await.unwrap();

        let mut idle = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stub.stop().await;

        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), idle.read(&mut byte)).await;
        assert!(
            matches!(read, Ok(Ok(0)) | Ok(Err(_))),
            "the connection was still open after stop: {read:?}"
        );

        match listen_on(addr, hole).await {
            Ok(stub) => stub.stop().await,
            Err(e) => panic!("the port was still held after stop: {e:#}"),
        }
    }

    #[test]
    fn servfail_refuses_garbage() {
        assert!(servfail(&[0u8; 4]).is_none());
        // A compression pointer in the question section is malformed.
        let mut q = sample_query();
        q[12] = 0xC0;
        assert!(servfail(&q).is_none());
    }
}
