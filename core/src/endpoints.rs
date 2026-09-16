//! Where `dns.dns-ai.ru` actually is, and how that stays true after a node moves.
//!
//! The addresses in [`crate::config`] are compiled in, and they have to be: the whole point of
//! pinning them is that resolving the resolver's own name through the machine's DNS would come
//! straight back to us once the adapters point at the stub (the client's half of invariant I7).
//! But a compiled-in address is a statement about the day the build was made. Nodes are replaced —
//! msk2 and eu1 were deleted and their addresses **released back to the providers** (ROADMAP
//! S11/S18) — and an address that was ours in one month belongs to a stranger in the next.
//!
//! **A stale address is safe but useless**, and the difference matters. The certificate is checked
//! against `RESOLVER_HOST`, so whoever holds that address now cannot answer as us: they get a
//! failed handshake, and the user gets no DNS. Nothing leaks; everything stops.
//!
//! So the list is refreshed, in three tiers that cost what they are worth:
//!
//! 1. **From our own resolver, over a connection we were going to open anyway.** The stub's
//!    warm-up query already asked `dns.dns-ai.ru A` and threw the answer away; it now keeps it.
//!    The source of truth is the A record itself — the record the operator edits when a node
//!    changes — so there is no second copy of the addresses to keep in step, and nothing to forget
//!    to update. It costs nothing, tells nobody, and covers every planned migration: while one old
//!    address still answers, every client learns the new ones.
//! 2. **From an independent public resolver**, asked for `dns.dns-ai.ru` directly by IP over DoH.
//!    Reached only when tier 1 cannot happen because every address we know is dead.
//! 3. **From `endpoints.json`** on GitHub, mirrored on the site. The channel that survives losing
//!    the domain's DNS entirely, and the only one that can say *retired*.
//!
//! Tiers 2 and 3 are the rescue path and run **only after the resolver has actually stopped
//! answering**. That is a privacy decision as much as a traffic one: a DNS client that reports to
//! Google and GitHub every time it starts is telling two third parties who our users are, and it
//! would be doing it on machines where nothing is wrong.
//!
//! ## The invariant that makes any of this safe
//!
//! **Only addresses come from the network.** [`crate::config::RESOLVER_HOST`] — the name the
//! certificate is checked against — is compiled in and is never read from a manifest, a public
//! resolver or anything else off the wire. A forged `endpoints.json`, a hijacked GitHub account or
//! a poisoned public resolver can therefore point this client at a machine of their choosing, and
//! that machine still cannot complete a TLS handshake as `dns.dns-ai.ru`. The worst they achieve
//! is a client that cannot resolve — which is why the compiled-in addresses are **never removed**
//! from the candidate list. They stay at the end of it, so a hostile answer costs one failed
//! connection rather than a machine with no DNS (`stub::Upstream` is what moves on to the next).
//! The day the hostname becomes updatable is the day this file needs a signature; until then the
//! certificate is the signature.
//!
//! `retired` is the one piece of remote input with no effect on what we connect to: it only
//! demotes an address to the end of the list and, far more importantly, keeps it in
//! [`known_addresses`] so [`crate::config::is_resolver_address`] still recognises it as ours. An
//! address that drops out of that set is an address the backup logic will mistake for the user's
//! own previous DNS — and then «Выключить» hands them back a dead resolver instead of DHCP.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::{RESOLVER_IPS, RESOLVER_IPV6};

/// Every transport a node speaks runs on 443; the manifest does not get to choose a port, because
/// a port is one more thing arriving from the network for no benefit anyone has asked for.
pub const DOH_PORT: u16 = 443;

/// Caps on anything that arrives from outside. A list is a list, not an allocation primitive.
const MAX_ADDRS: usize = 8;
const MAX_RETIRED: usize = 32;

/// How long to leave the outside world alone after a rescue attempt, successful or not.
///
/// Persisted rather than kept in memory: the machine that most needs this is the one rebooting
/// into a broken configuration, and an in-memory cooldown resets at every boot.
const RESCUE_COOLDOWN_SECS: u64 = 1800;

/// The current shape of `endpoints.json`. A client that meets a larger number ignores the file.
const FORMAT: u32 = 1;

/// What we know about where the resolver is, as cached beside the executable.
///
/// The first seven fields are the published document; the last three are local bookkeeping and are
/// simply absent from the file on GitHub. Everything is `#[serde(default)]` so that a future field
/// does not make an older client refuse a newer manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Endpoints {
    /// Format version. See [`FORMAT`].
    pub v: u32,
    /// Bumped by hand on every publish. A manifest that goes backwards is refused, so a copy
    /// replayed from a cache or a mirror cannot undo a newer one.
    pub serial: u64,
    /// Free text for a human reading the file. Never parsed.
    pub updated: String,
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
    /// Addresses that were ours and are not any more. They are still recognised as ours by
    /// [`known_addresses`] — that is the entire point — and are tried last, never dropped.
    pub retired: Vec<IpAddr>,
    /// Shown to nobody yet; reserved so an operator can explain an emergency in the file itself.
    pub notice: String,

    /// Which tier produced this, for the log and for a support question. Local only.
    pub source: String,
    /// Unix seconds. Local only.
    pub checked_at: u64,
    /// Unix seconds of the last tier-2/3 attempt, successful or not. Local only.
    pub last_rescue_at: u64,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            v: FORMAT,
            serial: 0,
            updated: String::new(),
            v4: Vec::new(),
            v6: Vec::new(),
            retired: Vec::new(),
            notice: String::new(),
            source: String::new(),
            checked_at: 0,
            last_rescue_at: 0,
        }
    }
}

/// Read once per process, not once per call: [`crate::config::is_resolver_address`] runs per
/// adapter per refresh, and none of this is worth a stat call each time.
static CACHE: OnceLock<Mutex<Endpoints>> = OnceLock::new();

fn cache() -> &'static Mutex<Endpoints> {
    CACHE.get_or_init(|| Mutex::new(read_file().unwrap_or_default()))
}

/// The cached document, or an empty one. Never fails: with nothing on disk the compiled-in
/// addresses are the whole answer, which is exactly what this program shipped with.
pub fn current() -> Endpoints {
    match cache().lock() {
        Ok(g) => g.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

fn read_file() -> Option<Endpoints> {
    let path = crate::paths::endpoints_file();
    let text = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<Endpoints>(strip_bom(&text)) {
        Ok(e) if e.v <= FORMAT => Some(sanitised(e)),
        Ok(e) => {
            log::warn!(
                "{} is format v{}, which this build does not read",
                path.display(),
                e.v
            );
            None
        }
        Err(e) => {
            log::warn!(
                "{} is not readable ({e}); using the compiled-in addresses",
                path.display()
            );
            None
        }
    }
}

/// A UTF-8 byte-order mark, which `serde_json` refuses at "line 1 column 1".
///
/// Every Windows editor that offers "UTF-8" writes one — PowerShell's `Set-Content -Encoding utf8`
/// included — so a file edited by hand, here or before it was published, would be silently ignored
/// by every client that read it.
pub(crate) fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

/// Everything that arrives from outside goes through here, cache file included: a file beside a
/// portable executable is written by whoever can write that folder, which is not a privilege
/// boundary worth trusting.
fn sanitised(mut e: Endpoints) -> Endpoints {
    e.v4.retain(usable_v4);
    e.v6.retain(usable_v6);
    e.retired.retain(|ip| match ip {
        IpAddr::V4(v4) => usable_v4(v4),
        IpAddr::V6(v6) => usable_v6(v6),
    });
    e.v4.truncate(MAX_ADDRS);
    e.v6.truncate(MAX_ADDRS);
    e.retired.truncate(MAX_RETIRED);
    clip(&mut e.notice, 500);
    clip(&mut e.updated, 100);
    clip(&mut e.source, 40);
    e
}

/// Shorten a string to at most `max` **bytes**, without splitting a character.
///
/// `String::truncate` panics when the index is not a character boundary, and every string here
/// arrives as UTF-8 from the network — where a `notice` written in Russian is two bytes per letter
/// and a 500-byte cut lands mid-character roughly half the time. The one that would have panicked
/// is the service, on a machine whose DNS it is holding.
fn clip(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let end = (0..=max)
        .rev()
        .find(|i| s.is_char_boundary(*i))
        .unwrap_or(0);
    s.truncate(end);
}

fn store(e: &Endpoints) {
    if let Err(err) = crate::paths::ensure_data_dir() {
        log::warn!("cannot keep the endpoint list: {err:#}");
        return;
    }
    let path = crate::paths::endpoints_file();
    let tmp = path.with_extension("json.tmp");
    let text = match serde_json::to_string_pretty(e) {
        Ok(t) => t,
        Err(err) => {
            log::warn!("cannot serialise the endpoint list: {err}");
            return;
        }
    };
    // Written aside and renamed over: a half-written file here is read at the next start, and the
    // next start is exactly the moment this machine has no DNS to spare.
    if std::fs::write(&tmp, text).is_ok() && std::fs::rename(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        log::warn!("cannot replace {}", path.display());
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether `ip` is an address a resolver of ours could plausibly be at.
///
/// A manifest naming `127.0.0.1` is the interesting case: the stub would then be told to reach
/// its own upstream through loopback, and the one thing a resolver must never do is forward to
/// itself. Everything non-global is refused for the same reason — none of it can be a node.
fn usable_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || o[0] == 0
        || o[0] >= 240
        // 100.64/10, carrier-grade NAT: a client's own ISP, never a public resolver.
        || (o[0] == 100 && (64..128).contains(&o[1])))
}

fn usable_v6(ip: &Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xffc0) == 0xfe80 // link-local
        || (first & 0xfe00) == 0xfc00 // unique local
        || ip.to_ipv4_mapped().is_some())
}

fn push_unique<T: PartialEq>(list: &mut Vec<T>, item: T) {
    if !list.contains(&item) {
        list.push(item);
    }
}

/// The same addresses, in any order.
///
/// **Order is not a change, and reading it as one was measured rather than reasoned about.** An
/// authoritative server is free to rotate a multi-address record between answers, and ours does:
/// two lookups a quarter of a second apart came back with the same pair in different orders. A
/// comparison by position calls that a new address list every single time — which means rebuilding
/// the HTTPS client on every refresh, and a log line announcing a migration that never happened.
fn same_set<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    a.len() == b.len() && a.iter().all(|x| b.contains(x))
}

/// Add to `retired`; never take anything out of it.
///
/// **This is the only direction that is safe, and it is why every replacement of the address list
/// goes through here.** `known_addresses` is what tells an adapter's DNS setting apart from the
/// user's own, and the compiled-in pair is the only part of it that is remembered for nothing. An
/// address this machine *learned* — a node added after the build and later removed — exists in no
/// constant anywhere; drop it from the list and the next backup records it as the user's previous
/// configuration, which «Выключить» then restores.
///
/// Bounded, because it grows for the life of an installation, and the oldest goes first: an address
/// that 32 others have outlived is not one still sitting on somebody's adapter.
fn remember_retired(retired: &mut Vec<IpAddr>, gone: impl IntoIterator<Item = IpAddr>) {
    for ip in gone {
        if !retired.contains(&ip) {
            retired.push(ip);
        }
    }
    if retired.len() > MAX_RETIRED {
        retired.drain(0..retired.len() - MAX_RETIRED);
    }
}

/// The addresses to hand the HTTPS client, in the order it should try them.
///
/// Three rules, and each one is load-bearing:
///
/// * **What we learned comes first.** That is the whole feature.
/// * **The compiled-in addresses are always present**, at the end. Nothing arriving from the
///   network can remove them, so the worst a hostile or merely wrong list achieves is a failed
///   connection before the machine resolves anyway.
/// * **IPv4 before IPv6**, unchanged from [`crate::config`]: half-working IPv6 is far more common
///   than none, and a machine that has it costs nothing by having it tried last.
pub fn candidates() -> Vec<SocketAddr> {
    let e = current();

    let mut v4: Vec<Ipv4Addr> = Vec::new();
    for ip in &e.v4 {
        push_unique(&mut v4, *ip);
    }
    let retired_v4 = |ip: &Ipv4Addr| e.retired.contains(&IpAddr::V4(*ip));
    for ip in RESOLVER_IPS.iter().filter(|ip| !retired_v4(ip)) {
        push_unique(&mut v4, *ip);
    }
    for ip in RESOLVER_IPS.iter().filter(|ip| retired_v4(ip)) {
        push_unique(&mut v4, *ip);
    }

    let mut v6: Vec<Ipv6Addr> = Vec::new();
    for ip in &e.v6 {
        push_unique(&mut v6, *ip);
    }
    let retired_v6 = |ip: &Ipv6Addr| e.retired.contains(&IpAddr::V6(*ip));
    for ip in RESOLVER_IPV6.iter().filter(|ip| !retired_v6(ip)) {
        push_unique(&mut v6, *ip);
    }
    for ip in RESOLVER_IPV6.iter().filter(|ip| retired_v6(ip)) {
        push_unique(&mut v6, *ip);
    }

    v4.into_iter()
        .map(|ip| SocketAddr::new(IpAddr::V4(ip), DOH_PORT))
        .chain(
            v6.into_iter()
                .map(|ip| SocketAddr::new(IpAddr::V6(ip), DOH_PORT)),
        )
        .collect()
}

/// The v4 addresses to write into an adapter in native mode, and to show in the window.
///
/// Unlike [`candidates`] this does **not** append the compiled-in list behind a learned one:
/// Windows tries the servers on an adapter in order and waits on each, so a dead address here is
/// seconds of every lookup rather than one connect. What we learned replaces what we shipped with,
/// or — when we have learned nothing — is exactly what we shipped with.
pub fn effective_v4() -> Vec<Ipv4Addr> {
    let e = current();
    if e.v4.is_empty() {
        RESOLVER_IPS.to_vec()
    } else {
        e.v4
    }
}

/// The v6 addresses, for the same callers and the same reason.
pub fn effective_v6() -> Vec<Ipv6Addr> {
    let e = current();
    if e.v6.is_empty() {
        RESOLVER_IPV6.to_vec()
    } else {
        e.v6
    }
}

/// Every address that has ever been ours, as far as this machine knows.
///
/// This is the set [`crate::config::is_resolver_address`] answers from, and it is a union rather
/// than the current list on purpose. It decides whether an address found on an adapter is ours or
/// the user's, and getting that wrong in the *forgetting* direction is the one failure in this
/// whole file that a user cannot undo: a retired address of ours, no longer recognised, is written
/// into `dns-backup.json` as their previous configuration, and «Выключить» then restores a dead
/// resolver instead of DHCP.
pub fn known_addresses() -> Vec<IpAddr> {
    let e = current();
    let mut all: Vec<IpAddr> = Vec::new();
    for ip in RESOLVER_IPS {
        push_unique(&mut all, IpAddr::V4(ip));
    }
    for ip in RESOLVER_IPV6 {
        push_unique(&mut all, IpAddr::V6(ip));
    }
    for ip in e.v4 {
        push_unique(&mut all, IpAddr::V4(ip));
    }
    for ip in e.v6 {
        push_unique(&mut all, IpAddr::V6(ip));
    }
    for ip in e.retired {
        push_unique(&mut all, ip);
    }
    all
}

/// Tier 1: what `dns.dns-ai.ru` itself just answered.
///
/// Returns true when this changed what the next connection will try. The answer arrived over a
/// TLS connection to a certificate for `RESOLVER_HOST`, so it is as trustworthy as the resolver
/// we were already talking to — there is nothing further to verify, and a signature here would be
/// verifying our own server to ourselves.
///
/// An empty or entirely unusable answer is ignored rather than stored: a node that briefly
/// answers NOERROR with no records must not be able to empty every client's address list.
pub fn learn(v4: &[Ipv4Addr], v6: &[Ipv6Addr]) -> bool {
    adopt_addresses(v4, v6, "resolver")
}

/// The one place a fresh pair of address lists reaches the cache, whoever produced them.
fn adopt_addresses(v4: &[Ipv4Addr], v6: &[Ipv6Addr], source: &str) -> bool {
    let fresh_v4: Vec<Ipv4Addr> = v4
        .iter()
        .copied()
        .filter(usable_v4)
        .take(MAX_ADDRS)
        .collect();
    let fresh_v6: Vec<Ipv6Addr> = v6
        .iter()
        .copied()
        .filter(usable_v6)
        .take(MAX_ADDRS)
        .collect();
    if fresh_v4.is_empty() {
        return false;
    }

    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    // Compared against what this machine was *using*, which on a first run is the compiled-in
    // pair: a fresh client that learns exactly the addresses it already had has learned nothing,
    // and saying otherwise would announce a migration at every first start.
    //
    // A v6-less answer (the machine has no v6 route, or the resolver was asked over v4 only) must
    // not erase a v6 list we already had — that would quietly turn v6 off for that machine.
    let previous_v4 = if guard.v4.is_empty() {
        RESOLVER_IPS.to_vec()
    } else {
        guard.v4.clone()
    };
    let previous_v6 = if guard.v6.is_empty() {
        RESOLVER_IPV6.to_vec()
    } else {
        guard.v6.clone()
    };
    let changed = !same_set(&fresh_v4, &previous_v4)
        || (!fresh_v6.is_empty() && !same_set(&fresh_v6, &previous_v6));

    // Whatever leaves the list is retired, not forgotten. Only the compiled-in addresses are
    // remembered for free; an address this machine learned and is now dropping exists nowhere else,
    // and one that stops being recognised is one the backup takes for the user's own DNS.
    let mut gone: Vec<IpAddr> = guard
        .v4
        .iter()
        .filter(|ip| !fresh_v4.contains(ip))
        .map(|ip| IpAddr::V4(*ip))
        .collect();
    if !fresh_v6.is_empty() {
        gone.extend(
            guard
                .v6
                .iter()
                .filter(|ip| !fresh_v6.contains(ip))
                .map(|ip| IpAddr::V6(*ip)),
        );
    }

    guard.v4 = fresh_v4;
    if !fresh_v6.is_empty() {
        guard.v6 = fresh_v6;
    }
    remember_retired(&mut guard.retired, gone);
    guard.source = source.into();
    guard.checked_at = now();
    if changed {
        log::info!(
            "endpoint list updated from {source}: v4 {:?}, v6 {:?}",
            guard.v4,
            guard.v6
        );
    }
    store(&guard);
    changed
}

/// Tier 3: take a published `endpoints.json`, or refuse it.
///
/// **The rollback check is the only thing standing between a cached copy and an old one.** Serving
/// yesterday's file is something a mirror does by accident and an attacker does on purpose, and
/// either way it would re-introduce an address that was retired for a reason. A manifest whose
/// serial is below what this machine has already seen is dropped without comment.
fn adopt_manifest(manifest: Endpoints) -> bool {
    let manifest = sanitised(manifest);
    if manifest.v4.is_empty() {
        log::warn!("the published list names no usable address; ignoring it");
        return false;
    }

    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if manifest.serial < guard.serial {
        log::warn!(
            "the published list is serial {} and this machine has already seen {}; ignoring it",
            manifest.serial,
            guard.serial
        );
        return false;
    }

    let previous_v4 = if guard.v4.is_empty() {
        RESOLVER_IPS.to_vec()
    } else {
        guard.v4.clone()
    };
    let previous_v6 = if guard.v6.is_empty() {
        RESOLVER_IPV6.to_vec()
    } else {
        guard.v6.clone()
    };
    let changed = !same_set(&manifest.v4, &previous_v4) || !same_set(&manifest.v6, &previous_v6);

    // Same rule as tier 1, and here it also means a manifest can only ever ADD to `retired`. A
    // published file that dropped an address from that list — by mistake, or by an attacker who
    // wants a machine to mistake our old address for its user's — would be asking this client to
    // forget, and forgetting is the one operation that is never safe (`known_addresses`).
    let mut gone: Vec<IpAddr> = guard
        .v4
        .iter()
        .filter(|ip| !manifest.v4.contains(ip))
        .map(|ip| IpAddr::V4(*ip))
        .collect();
    gone.extend(
        guard
            .v6
            .iter()
            .filter(|ip| !manifest.v6.contains(ip))
            .map(|ip| IpAddr::V6(*ip)),
    );
    gone.extend(manifest.retired);

    guard.v4 = manifest.v4;
    guard.v6 = manifest.v6;
    remember_retired(&mut guard.retired, gone);
    guard.serial = manifest.serial;
    guard.updated = manifest.updated;
    guard.notice = manifest.notice;
    guard.source = "manifest".into();
    guard.checked_at = now();
    if changed {
        log::info!(
            "endpoint list updated from the published file (serial {}): v4 {:?}, v6 {:?}",
            guard.serial,
            guard.v4,
            guard.v6
        );
    }
    store(&guard);
    changed
}

/// Whether a rescue attempt is allowed now, and the bookkeeping that goes with making one.
///
/// Both halves live here so the cooldown cannot be forgotten at a call site: the caller asks, and
/// asking is what starts the clock.
fn claim_rescue() -> bool {
    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let now = now();
    // A clock that went backwards (a VM resumed from a snapshot, a machine that just got its time
    // from the network — which it cannot do without DNS) must not lock rescue out until it catches
    // up, so a stamp in the future is treated as no stamp at all.
    if guard.last_rescue_at <= now && now - guard.last_rescue_at < RESCUE_COOLDOWN_SECS {
        return false;
    }
    guard.last_rescue_at = now;
    store(&guard);
    true
}

/// Give most of the cooldown back after an attempt that never reached anything at all.
///
/// A machine that is simply offline — booted before the network came up, a laptop in a tunnel —
/// fails every query and would otherwise spend its one rescue attempt on a network that was not
/// there, then sit out the full quiet period with broken DNS once it comes back. An attempt that
/// got no bytes from anywhere is not evidence about the resolver, so it does not earn the silence;
/// a minute is enough to keep this from spinning.
fn relax_cooldown() {
    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.last_rescue_at = now().saturating_sub(RESCUE_COOLDOWN_SECS.saturating_sub(60));
    store(&guard);
}

#[cfg(feature = "stub")]
mod rescue;
#[cfg(feature = "stub")]
pub use rescue::{rescue, rescue_forced};

#[cfg(test)]
mod tests {
    use super::*;

    fn ip4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn non_global_addresses_are_refused() {
        // The one that matters: a manifest that points the stub back at itself.
        assert!(!usable_v4(&ip4("127.0.0.1")));
        assert!(!usable_v4(&ip4("0.0.0.0")));
        assert!(!usable_v4(&ip4("192.168.1.1")));
        assert!(!usable_v4(&ip4("10.0.0.1")));
        assert!(!usable_v4(&ip4("169.254.1.1")));
        assert!(!usable_v4(&ip4("100.64.0.1")));
        assert!(!usable_v4(&ip4("224.0.0.1")));
        assert!(!usable_v4(&ip4("255.255.255.255")));
        assert!(usable_v4(&ip4("192.144.59.14")));

        assert!(!usable_v6(&"::1".parse::<Ipv6Addr>().unwrap()));
        assert!(!usable_v6(&"fe80::1".parse::<Ipv6Addr>().unwrap()));
        assert!(!usable_v6(&"fd00::1".parse::<Ipv6Addr>().unwrap()));
        assert!(usable_v6(
            &"2a0d:8480:0:67c::14".parse::<Ipv6Addr>().unwrap()
        ));
    }

    /// A file saved as "UTF-8" by any Windows editor starts with a BOM, and `serde_json` refuses
    /// it at the first column — which reads as a manifest nobody published.
    #[test]
    fn a_byte_order_mark_does_not_hide_the_file() {
        let text = "\u{feff}{\"v\":1,\"serial\":3}";
        let parsed: Endpoints = serde_json::from_str(strip_bom(text)).expect("parses");
        assert_eq!(parsed.serial, 3);
        assert!(
            serde_json::from_str::<Endpoints>(text).is_err(),
            "and it would not have"
        );
    }

    /// The failure this design exists to prevent: an address the client learned, and later stopped
    /// being told about, must still be recognised as ours. Only the compiled-in pair is remembered
    /// for free — a node added after the build and then removed lives in no constant anywhere.
    #[test]
    fn an_address_that_leaves_the_list_is_retired_not_forgotten() {
        let old = IpAddr::V4(ip4("217.60.10.20"));
        let mut retired = vec![old];

        remember_retired(&mut retired, [IpAddr::V4(ip4("203.0.113.9"))]);
        assert!(retired.contains(&old), "nothing is ever taken out");
        assert!(retired.contains(&IpAddr::V4(ip4("203.0.113.9"))));

        remember_retired(&mut retired, [IpAddr::V4(ip4("203.0.113.9"))]);
        assert_eq!(retired.len(), 2, "and nothing is added twice");

        // Bounded for the life of an installation, and the oldest is what falls off.
        let many: Vec<IpAddr> = (0..MAX_RETIRED as u8 + 5)
            .map(|i| IpAddr::V4(Ipv4Addr::new(203, 0, 113, i + 20)))
            .collect();
        remember_retired(&mut retired, many);
        assert_eq!(retired.len(), MAX_RETIRED);
        assert!(!retired.contains(&old));
    }

    /// Measured against the live resolver: two lookups 250 ms apart returned the same pair in
    /// different orders, and the first version of this called that a migration both times.
    #[test]
    fn a_rotated_record_is_not_a_new_address_list() {
        let a = [ip4("192.144.59.14"), ip4("186.246.49.127")];
        let b = [ip4("186.246.49.127"), ip4("192.144.59.14")];
        assert!(same_set(&a, &b));
        assert!(!same_set(&a, &[ip4("192.144.59.14")]));
        assert!(!same_set(&a, &[ip4("192.144.59.14"), ip4("203.0.113.9")]));
    }

    #[test]
    fn sanitise_drops_junk_and_caps_lists() {
        let e = sanitised(Endpoints {
            v4: vec![ip4("127.0.0.1"), ip4("192.144.59.14")],
            retired: vec![IpAddr::V4(ip4("10.1.2.3")), IpAddr::V4(ip4("217.60.10.20"))],
            notice: "x".repeat(900),
            ..Default::default()
        });
        assert_eq!(e.v4, vec![ip4("192.144.59.14")]);
        assert_eq!(e.retired, vec![IpAddr::V4(ip4("217.60.10.20"))]);
        assert_eq!(e.notice.len(), 500);
    }

    /// `String::truncate` panics on a cut that is not a character boundary, and a `notice` written
    /// in Russian is two bytes a letter — so the cap would have panicked the service on roughly
    /// every other over-long message.
    #[test]
    fn a_long_russian_notice_is_clipped_not_split() {
        let e = sanitised(Endpoints {
            v4: vec![ip4("192.144.59.14")],
            notice: "я".repeat(400), // 800 bytes, every boundary odd-numbered
            ..Default::default()
        });
        assert!(e.notice.len() <= 500);
        assert_eq!(e.notice.len() % 2, 0, "clipped between characters");
        assert!(e.notice.chars().all(|c| c == 'я'));
    }

    /// The property the whole design rests on: whatever arrives from the network, the addresses
    /// this build shipped with are still in the list.
    #[test]
    fn built_ins_survive_any_manifest() {
        let hostile = Endpoints {
            v4: vec![ip4("203.0.113.9")],
            retired: RESOLVER_IPS.iter().map(|ip| IpAddr::V4(*ip)).collect(),
            ..Default::default()
        };
        // `candidates` reads the process cache, so exercise the same ordering directly.
        let mut v4: Vec<Ipv4Addr> = Vec::new();
        for ip in &hostile.v4 {
            push_unique(&mut v4, *ip);
        }
        let retired = |ip: &Ipv4Addr| hostile.retired.contains(&IpAddr::V4(*ip));
        for ip in RESOLVER_IPS.iter().filter(|ip| !retired(ip)) {
            push_unique(&mut v4, *ip);
        }
        for ip in RESOLVER_IPS.iter().filter(|ip| retired(ip)) {
            push_unique(&mut v4, *ip);
        }
        for built_in in RESOLVER_IPS {
            assert!(v4.contains(&built_in), "{built_in} must remain reachable");
        }
        assert_eq!(v4[0], ip4("203.0.113.9"), "what we learned is tried first");
    }
}
