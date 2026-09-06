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

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

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

pub struct StubHandle {
    shutdown: watch::Sender<bool>,
    pub listening: Vec<SocketAddr>,
}

impl StubHandle {
    /// Signals every listener to stop. Sockets close when their tasks wind down.
    pub fn stop(&self) {
        let _ = self.shutdown.send(true);
    }
}

fn build_client() -> Result<Client> {
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
        // The pinned addresses, handed to the HTTP client directly. This is what keeps the
        // bootstrap from looping back into ourselves once the adapter points at 127.0.0.1;
        // `RESOLVER_HOST` is still what the certificate is checked against.
        .resolve_to_addrs(RESOLVER_HOST, &config::bootstrap_addrs())
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
    let client = build_client()?;
    let (tx, _) = watch::channel(false);

    let mut targets = vec![SocketAddr::new(IpAddr::V4(STUB_V4), DNS_PORT)];
    if ipv6 {
        targets.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), DNS_PORT));
    }

    let mut listening = Vec::new();
    for addr in targets {
        let required = addr.is_ipv4();
        match bind_pair(addr).await {
            Ok((udp, tcp)) => {
                listening.push(addr);
                tokio::spawn(serve_udp(
                    udp,
                    client.clone(),
                    stats.clone(),
                    tx.subscribe(),
                ));
                tokio::spawn(serve_tcp(
                    tcp,
                    client.clone(),
                    stats.clone(),
                    tx.subscribe(),
                ));
                log::info!("stub listening on {addr} (UDP and TCP)");
            }
            Err(e) if required => {
                return Err(e).with_context(|| {
                    format!("cannot listen on {addr} — another program already owns port 53")
                })
            }
            Err(e) => log::warn!("not listening on {addr}: {e:#}"),
        }
    }

    warm(client);

    Ok(StubHandle {
        shutdown: tx,
        listening,
    })
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
fn warm(client: Client) {
    tokio::spawn(async move {
        let Ok(query) = crate::dnsmsg::build_query(RESOLVER_HOST, crate::dnsmsg::TYPE_A, 0) else {
            return;
        };
        match forward(&client, &query).await {
            Ok(_) => log::info!("upstream connection is warm"),
            Err(e) => log::warn!("warm-up query failed: {e:#}"),
        }
    });
}

async fn bind_pair(addr: SocketAddr) -> Result<(UdpSocket, TcpListener)> {
    let udp = UdpSocket::bind(addr).await.context("UDP bind")?;
    let tcp = TcpListener::bind(addr).await.context("TCP bind")?;
    Ok((udp, tcp))
}

async fn serve_udp(
    sock: UdpSocket,
    client: Client,
    stats: Arc<Stats>,
    mut shutdown: watch::Receiver<bool>,
) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; MAX_UDP];
    loop {
        let (len, from) = tokio::select! {
            _ = shutdown.changed() => break,
            r = sock.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(e) => { log::warn!("UDP recv failed: {e}"); continue }
            }
        };
        let query = buf[..len].to_vec();
        let (sock, client, stats) = (sock.clone(), client.clone(), stats.clone());
        tokio::spawn(async move {
            stats.queries.fetch_add(1, Ordering::Relaxed);
            let reply = match forward(&client, &query).await {
                Ok(mut answer) => {
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
    log::info!("UDP listener stopped");
}

async fn serve_tcp(
    listener: TcpListener,
    client: Client,
    stats: Arc<Stats>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let (stream, _peer) = tokio::select! {
            _ = shutdown.changed() => break,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => { log::warn!("TCP accept failed: {e}"); continue }
            }
        };
        let (client, stats) = (client.clone(), stats.clone());
        tokio::spawn(async move {
            if let Err(e) = serve_tcp_conn(stream, client, stats).await {
                log::debug!("TCP connection ended: {e:#}");
            }
        });
    }
    log::info!("TCP listener stopped");
}

async fn serve_tcp_conn(mut stream: TcpStream, client: Client, stats: Arc<Stats>) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        // A closed connection between queries is the normal end of a DNS/TCP session, not an
        // error worth logging as one.
        match tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => return Ok(()),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_TCP {
            return Ok(());
        }
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await?;

        stats.queries.fetch_add(1, Ordering::Relaxed);
        let reply = match forward(&client, &query).await {
            Ok(answer) => answer,
            Err(e) => {
                stats.record_error(e);
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
    let client = build_client()?;
    forward(&client, query).await
}

/// One query, one POST. The body goes up and comes back untouched.
async fn forward(client: &Client, query: &[u8]) -> Result<Vec<u8>> {
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

    #[test]
    fn servfail_refuses_garbage() {
        assert!(servfail(&[0u8; 4]).is_none());
        // A compression pointer in the question section is malformed.
        let mut q = sample_query();
        q[12] = 0xC0;
        assert!(servfail(&q).is_none());
    }
}
