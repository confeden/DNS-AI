//! Resolver endpoints and user-visible settings.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

/// The name in the certificate. Used for SNI and hostname verification only — it is NEVER
/// resolved through the system resolver.
///
/// The bootstrap loop is the reason: once the adapter points at our own stub on 127.0.0.1,
/// resolving `dns.dns-ai.ru` would come back to us and hang. So the addresses below are pinned
/// into the binary and handed to the HTTP client directly. This mirrors invariant I7 on the
/// egress side, for the same reason.
pub const RESOLVER_HOST: &str = "dns.dns-ai.ru";

/// The A record of `dns.dns-ai.ru` (ROADMAP S19), pinned. msk3 first, spb1 second; the HTTP
/// client is given both and picks, so a dead node costs one connect timeout, not resolution.
///
/// msk2 used to be first here and is gone: its host starves it (ROADMAP S18) and it was removed
/// from the published record, so a client still pinning it would spend its first connect on a node
/// nothing else points at.
pub const RESOLVER_IPS: [Ipv4Addr; 2] = [
    Ipv4Addr::new(192, 144, 59, 14),  // msk3
    Ipv4Addr::new(186, 246, 49, 127), // spb1
];

/// The AAAA records of `dns.dns-ai.ru`, pinned for the same reason as the A records above.
///
/// **Two nodes now, not one.** This used to be a single spb1 address, which is why native mode
/// cleared IPv6 instead of configuring it: handing Windows one v6 server it prefers over v4 would
/// have aimed every query at a single resolver. msk3 has a global v6 address too, so the pair is
/// as redundant as the v4 pair and both modes can use it.
pub const RESOLVER_IPV6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0x2a0d, 0x8480, 0, 0x067c, 0, 0, 0, 0x14), // msk3
    Ipv6Addr::new(0x2a0a, 0x2b41, 0, 0x500d, 0, 0, 0, 0x53), // spb1
];

/// RFC 8484 endpoint. Also what native mode registers as Windows' DoH template.
pub const DOH_URL: &str = "https://dns.dns-ai.ru/dns-query";

/// The name to hand a DoT/DoQ client — Android's "Private DNS", a router, another machine.
///
/// Nothing in this program speaks either transport (the stub is DoH over HTTP/2), so this is here
/// only to be shown: the window is the one place a user who wants to configure a second device
/// looks, and the answer is one hostname rather than a page on the site.
pub const DOT_DOQ_HOST: &str = RESOLVER_HOST;

/// Where the stub listens. Loopback only — this is a stub resolver, not a network service.
pub const STUB_V4: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// What we write into the adapters when enabled.
pub const ADAPTER_DNS_V4: &str = "127.0.0.1";
pub const ADAPTER_DNS_V6: &str = "::1";

/// Upstream request timeout. Windows' own resolver gives up around 2 s per server and retries,
/// so anything above ~4 s here is only ever seen as a hang.
pub const UPSTREAM_TIMEOUT_SECS: u64 = 4;

/// The same addresses as text, for the `netsh` calls that configure native mode.
pub fn resolver_ips_text() -> Vec<String> {
    RESOLVER_IPS.iter().map(|ip| ip.to_string()).collect()
}

/// The v6 addresses as text, for the same callers.
pub fn resolver_ipv6_text() -> Vec<String> {
    RESOLVER_IPV6.iter().map(|ip| ip.to_string()).collect()
}

/// Where the stub's own DoH client is allowed to connect. IPv4 first, IPv6 **last**.
///
/// The order is the whole design here. A machine with working IPv6 loses nothing by having it
/// third; a machine with *broken* IPv6 — a tunnel that is up but does not route, a link-local-only
/// interface, a hotel network that advertises v6 and drops it — loses a real connect timeout every
/// time it is tried first, and that machine cannot tell the difference between that and "DNS-AI is
/// down". Half-working IPv6 is far more common than none, so it goes last and is only reached when
/// both v4 addresses have failed.
///
/// A host with no IPv6 route at all pays nothing: the connect fails immediately with
/// "network unreachable" rather than timing out.
pub fn bootstrap_addrs() -> Vec<SocketAddr> {
    RESOLVER_IPS
        .iter()
        .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 443))
        .chain(
            RESOLVER_IPV6
                .iter()
                .map(|ip| SocketAddr::new(IpAddr::V6(*ip), 443)),
        )
        .collect()
}

/// How the machine is pointed at DNS-AI.
///
/// Two genuinely different mechanisms, not two spellings of one. In [`Mode::Stub`] the adapters
/// point at our own loopback resolver and this process speaks DoH upstream; in [`Mode::Native`]
/// the adapters carry the resolver's real addresses and **Windows itself** does the DoH, using a
/// template we register with `netsh dns add encryption`.
///
/// Native is only reachable on Windows 11 (build 22000+). On Windows 10 the DoH client does not
/// exist in retail at all *and* our nodes do not answer plain `:53`, so pointing an adapter
/// straight at them yields no DNS whatsoever rather than unencrypted DNS (ROADMAP N14). That is
/// why [`crate::netif::native_doh_supported`] gates the choice instead of the UI merely
/// discouraging it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Adapters -> `127.0.0.1`; this process resolves. Works on every Windows we support, and is
    /// the only mode that can ever offer DoQ/DoH3.
    #[default]
    Stub,
    /// Adapters -> the resolver's own addresses; Windows' built-in DoH client resolves.
    Native,
}

/// The mode this Windows should be using, which is not the same question as which ones it *can*.
///
/// Windows 11 has a DoH client and should use it; everything older has none, and on our resolvers
/// the plain-`:53` path it would fall back to does not exist (ROADMAP N14), so there the client has
/// to be the resolver. One function so the window's recommendation and the first-run default can
/// never disagree.
pub fn recommended_mode() -> Mode {
    if crate::netif::native_doh_supported() {
        Mode::Native
    } else {
        Mode::Stub
    }
}

/// Persisted in `%ProgramData%\DNS-AI\settings.json`. Owned by the service; the tray edits it
/// through the IPC channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Whether the adapters should be pointed at the stub. This is the state the service
    /// restores on boot.
    pub enabled: bool,
    /// Which of the two mechanisms above is in use.
    pub mode: Mode,
    /// Configure the adapters' IPv6 DNS as well as their IPv4. On by default: touching only IPv4
    /// leaves the ISP's RA/DHCPv6 resolver in place and Windows will happily use it — the single
    /// most common way a "DoH is on!" screenshot is still leaking (README §4.4).
    ///
    /// What it *writes* differs by mode: [`Mode::Stub`] adds a `::1` listener and points the
    /// adapters at it, [`Mode::Native`] writes [`RESOLVER_IPV6`]. Off means the v6 side is
    /// emptied rather than left alone, which is the only setting that cannot leak.
    pub ipv6: bool,
    /// Configure VPN / tunnel adapters too. Off by default: VPN clients re-assert their own DNS
    /// and fighting them produces a machine whose resolution depends on start-up order.
    pub include_vpn_adapters: bool,
    /// Start the tray UI at logon.
    pub autostart_tray: bool,
    /// Start the service with Windows rather than on demand.
    ///
    /// This is the setting that decides whether protection survives a reboot with nobody logged
    /// in: the service is what owns the stub and the adapter configuration, and a manual-start
    /// service leaves a machine that was enabled pointing at a resolver nothing is running.
    /// Applied to the SCM registration itself, not merely remembered here.
    pub service_autostart: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: Mode::Stub,
            ipv6: true,
            include_vpn_adapters: false,
            autostart_tray: true,
            service_autostart: true,
        }
    }
}

impl Settings {
    /// What a machine with no settings file yet should start with.
    ///
    /// [`Mode::Stub`] is the *safe* default — it is the only one that works everywhere, which is
    /// why it is what `Default` returns — but on Windows 11 it is not the *right* one. There the
    /// operating system has a DoH client of its own, and letting it do the work means nothing of
    /// ours sits in the query path: our process dying costs that machine nothing. So the first run
    /// picks per Windows version, and the window says which one it recommends, rather than leaving
    /// a user to work out from two switches which of them their Windows wants.
    pub fn recommended() -> Self {
        Self {
            mode: recommended_mode(),
            ..Self::default()
        }
    }

    pub fn load() -> Self {
        let path = crate::paths::settings_file();
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                log::warn!("settings.json is not readable ({e}); falling back to defaults");
                Settings::recommended()
            }),
            // No file: this is a first run, not a lost one.
            Err(_) => Settings::recommended(),
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        crate::paths::ensure_data_dir()?;
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(crate::paths::settings_file(), text)?;
        Ok(())
    }
}
