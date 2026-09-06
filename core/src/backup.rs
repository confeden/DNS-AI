//! The record of what the machine's DNS looked like before we touched it.
//!
//! "Recorded" is the operative word: what the revert can undo is exactly what reached the disk,
//! so the file is written *before* the first adapter is changed and rewritten after each one.
//!
//! The file is treated as **data, not instructions** on the way back in. It is read by a process
//! running as SYSTEM and its contents become arguments to commands that reconfigure the machine,
//! so every value is checked against what this code can actually have written before it is used.
//! The honest limit of that check is stated on [`AdapterBackup::sanitised`].

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::netif::{DnsState, Family};
use crate::paths;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterBackup {
    pub index: u32,
    pub ipv6_index: u32,
    pub guid: String,
    pub alias: String,
    pub v4: DnsState,
    pub v6: DnsState,
}

impl AdapterBackup {
    /// Returns a copy with every address that cannot be an address dropped, plus the list of
    /// what was dropped.
    ///
    /// **The honest limit.** This stops a value in the file from reaching a command line as
    /// something other than an IP address. It cannot decide whether a plausible previous
    /// configuration is the one that was really there — restoring "the static DNS this machine
    /// had before" means writing whatever addresses the file names, which is arbitrary by
    /// definition. That is why the caller prints the list before applying it.
    pub fn sanitised(&self) -> (AdapterBackup, Vec<String>) {
        let mut dropped = Vec::new();
        let clean = |state: &DnsState, family: &str, dropped: &mut Vec<String>| -> DnsState {
            match state {
                DnsState::Dhcp => DnsState::Dhcp,
                DnsState::Static(list) => DnsState::Static(
                    list.iter()
                        .filter_map(|s| match s.parse::<IpAddr>() {
                            // Re-emitted in canonical form: what gets applied is the parsed
                            // address, not the original text.
                            Ok(ip) => Some(ip.to_string()),
                            Err(_) => {
                                dropped.push(format!("{family}: {s}"));
                                None
                            }
                        })
                        .collect(),
                ),
            }
        };
        let v4 = clean(&self.v4, "IPv4", &mut dropped);
        let v6 = clean(&self.v6, "IPv6", &mut dropped);
        (
            AdapterBackup {
                index: self.index,
                ipv6_index: self.ipv6_index,
                guid: self.guid.clone(),
                alias: self.alias.clone(),
                v4,
                v6,
            },
            dropped,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBackup {
    /// Unix seconds. Deliberately not a formatted date: this file is read by code, and a
    /// timestamp is the one field that must not depend on a locale.
    pub created_unix: u64,
    pub adapters: Vec<AdapterBackup>,
    /// Resolver addresses whose Windows DoH template **we** registered, and which the revert must
    /// therefore delete again.
    ///
    /// Only ones we added. A template that predates us — the PowerShell installer left exactly
    /// these two behind on the first machine this ran on — is somebody else's setting, and
    /// deleting it on our way out would be a client removing configuration it never made.
    /// `serde(default)` so a backup written by an older build still loads.
    #[serde(default)]
    pub doh_added: Vec<String>,
}

/// Whether an address is one this program writes into adapters — either mode.
///
/// Loopback is what [`crate::config::Mode::Stub`] writes; the resolver's own addresses are what
/// [`crate::config::Mode::Native`] writes. Both had to be listed, and the second was missing:
/// native mode's addresses look exactly like a configuration somebody chose, so a machine that was
/// enabled in that mode and lost its backup recorded them as "the previous DNS" and would have
/// "restored" itself to a state that only works while the client is installed.
fn is_ours(server: &str) -> bool {
    server == crate::config::ADAPTER_DNS_V4
        || server == crate::config::ADAPTER_DNS_V6
        || server.parse::<IpAddr>().is_ok_and(|ip| match ip {
            IpAddr::V4(v4) => crate::config::RESOLVER_IPS.contains(&v4),
            IpAddr::V6(v6) => crate::config::RESOLVER_IPV6.contains(&v6),
        })
}

/// Refuses to record our own addresses as somebody's previous configuration.
///
/// The second half of the guarantee [`DnsBackup::capture_preserving`] describes, and it covers the
/// case that one cannot: an adapter that appeared while the service was down, is already pointing
/// at us, and has no earlier row to preserve. A recorded `127.0.0.1` is never worth restoring —
/// putting it back means aiming the machine at a loopback port with nothing listening on it — so it
/// is read as "we do not know", which spells DHCP. That is a guess, but it is the guess that leaves
/// the machine resolving.
fn not_ours(state: DnsState) -> DnsState {
    match &state {
        DnsState::Static(list) if !list.is_empty() && list.iter().all(|s| is_ours(s)) => {
            log::warn!(
                "an adapter was already pointing at DNS-AI ({}); recording DHCP instead of \
                 treating it as a previous configuration",
                list.join(", ")
            );
            DnsState::Dhcp
        }
        _ => state,
    }
}

impl DnsBackup {
    pub fn capture(adapters: &[crate::netif::Adapter]) -> Self {
        let adapters = adapters
            .iter()
            .map(|a| AdapterBackup {
                index: a.index,
                ipv6_index: a.ipv6_index,
                guid: a.guid.clone(),
                alias: a.alias.clone(),
                v4: not_ours(crate::netif::read_dns_state(&a.guid, Family::V4)),
                v6: not_ours(crate::netif::read_dns_state(&a.guid, Family::V6)),
            })
            .collect();
        Self {
            created_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            adapters,
            doh_added: Vec::new(),
        }
    }

    /// Captures `adapters`, but never overwrites what an earlier run already recorded.
    ///
    /// **This is the difference between a machine that can be put back and one whose real DNS
    /// settings are gone for good.** A backup still on disk means the previous run never reverted:
    /// after a crash, a hard power-off, or an SCM restart-on-failure, the service comes back up
    /// with `enabled` still set and the adapters still pointing at `127.0.0.1`. Capturing there
    /// reads the machine's "previous" DNS as our own loopback address and writes that over the only
    /// record of what was really configured. Nothing looks wrong — resolution works — until the day
    /// the user turns protection off or uninstalls, and the revert faithfully restores a static
    /// `127.0.0.1` with nothing listening on it.
    ///
    /// So an existing row wins over a fresh reading, always. A row for an adapter that is not in
    /// this selection is kept too: a NIC that has gone away can come back, and dropping its row
    /// would leave nothing to put it back to.
    pub fn capture_preserving(adapters: &[crate::netif::Adapter]) -> Self {
        let mut fresh = Self::capture(adapters);
        let Some(previous) = Self::load() else {
            return fresh;
        };

        let same = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
        for a in &mut fresh.adapters {
            if let Some(old) = previous.adapters.iter().find(|p| same(&p.guid, &a.guid)) {
                // The index can legitimately have changed — a driver update recreates an adapter —
                // so today's index is kept and only the recorded STATE comes from the old row.
                a.v4 = old.v4.clone();
                a.v6 = old.v6.clone();
            }
        }
        for old in previous.adapters {
            if !fresh.adapters.iter().any(|a| same(&a.guid, &old.guid)) {
                fresh.adapters.push(old);
            }
        }
        // Both belong to the original capture: the timestamp says when the machine was really
        // read, and the templates are the ones the first enable registered and the revert owes.
        fresh.created_unix = previous.created_unix;
        fresh.doh_added = previous.doh_added;
        fresh
    }

    pub fn save(&self) -> Result<()> {
        paths::ensure_data_dir()?;
        let path = paths::backup_file();
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, text).with_context(|| format!("cannot write {}", path.display()))?;
        Ok(())
    }

    pub fn load() -> Option<Self> {
        let path = paths::backup_file();
        let text = std::fs::read_to_string(&path).ok()?;
        match serde_json::from_str::<DnsBackup>(&text) {
            Ok(b) => Some(b),
            Err(e) => {
                log::error!("{} is not valid backup JSON: {e}", path.display());
                None
            }
        }
    }

    pub fn delete() {
        let _ = std::fs::remove_file(paths::backup_file());
    }

    pub fn exists() -> bool {
        paths::backup_file().exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule that keeps a machine restorable: what we wrote is never mistaken for what we
    /// found. Both modes are covered, because the second one was the gap — loopback was refused
    /// from the start, the resolver's own addresses were not, and those are what native mode
    /// writes into every adapter.
    #[test]
    fn our_own_addresses_are_not_a_previous_configuration() {
        let stub = DnsState::Static(vec![
            crate::config::ADAPTER_DNS_V4.to_string(),
            crate::config::ADAPTER_DNS_V6.to_string(),
        ]);
        assert!(matches!(not_ours(stub), DnsState::Dhcp));

        let native = DnsState::Static(crate::config::resolver_ips_text());
        assert!(matches!(not_ours(native), DnsState::Dhcp));

        let native_v6 = DnsState::Static(crate::config::resolver_ipv6_text());
        assert!(matches!(not_ours(native_v6), DnsState::Dhcp));
    }

    /// The other half, and the more important one: a real setting must survive being read. A list
    /// that merely CONTAINS one of ours is still the user's own — we never write a mixed list, so
    /// somebody put it together by hand and restoring it means restoring all of it.
    #[test]
    fn somebody_elses_configuration_survives() {
        let theirs = DnsState::Static(vec!["1.1.1.1".into(), "8.8.8.8".into()]);
        assert!(matches!(not_ours(theirs), DnsState::Static(_)));

        let mixed = DnsState::Static(vec![
            "1.1.1.1".into(),
            crate::config::ADAPTER_DNS_V4.to_string(),
        ]);
        assert!(matches!(not_ours(mixed), DnsState::Static(_)));

        assert!(matches!(not_ours(DnsState::Dhcp), DnsState::Dhcp));
    }

    /// A written v6 address does not have to be spelled the way the file spells it: `2a0d:8480:0:67c::14`
    /// and `2A0D:8480:0000:067C::0014` are one address, and a comparison on the text would say they
    /// are two.
    #[test]
    fn addresses_are_compared_as_addresses_not_as_text() {
        assert!(is_ours("2A0D:8480:0000:067C:0000:0000:0000:0014"));
        assert!(!is_ours("2a0d:8480:0:67c::15"));
    }
}
