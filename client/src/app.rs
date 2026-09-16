//! The service's state machine: the only code in the product that changes system DNS.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use dns_ai_core::backup::DnsBackup;
use dns_ai_core::config::{self, Mode, Settings, ADAPTER_DNS_V4, ADAPTER_DNS_V6};
use dns_ai_core::ipc::{AdapterView, Status};
use dns_ai_core::netif::{self, DnsState, DohEntry, Family};
use dns_ai_core::stub::{self, Stats, StubHandle};

/// How long enabling native mode may wait to find out where the resolver is.
///
/// Short on purpose: this is on the path of a button press and of a boot where the network may not
/// be up yet. Running out of it is not a failure — the list already on disk, and behind it the one
/// compiled into this build, is what gets written.
const REFRESH_BUDGET: Duration = Duration::from_millis(2500);

/// And how long it may then spend asking the outside world where the resolver went, when none of
/// the addresses it knows about answered at all.
const RESCUE_BUDGET: Duration = Duration::from_secs(8);

pub struct App {
    settings: Settings,
    stub: Option<StubHandle>,
    stats: Arc<Stats>,
    /// Whether the adapters are, as far as this process knows, pointed at us.
    enabled: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            settings: Settings::load(),
            stub: None,
            stats: Arc::new(Stats::default()),
            enabled: false,
        }
    }

    /// Called once at start-up. Puts the machine back into the state the settings describe.
    ///
    /// `can_write_adapters` is `false` for exactly one caller: an unelevated window running the
    /// local backend, where changing an adapter's DNS is not permitted. That case is not a failure
    /// and must not be treated as one — the adapters are persistent, so a machine that was enabled
    /// before a reboot comes back still pointing at `127.0.0.1`, and the one thing needed to keep
    /// it resolving is the listener, which needs no rights at all. Starting it and saying nothing
    /// is the difference between a portable copy that survives a reboot and one that leaves the
    /// user with no DNS until they find the UAC prompt.
    pub async fn resume(&mut self, can_write_adapters: bool) {
        if self.settings.enabled && !can_write_adapters {
            // Only the local-resolver mode has anything to bring back. In native mode the adapters
            // carry the resolver's own addresses and Windows does the work, so there is nothing of
            // ours to start: binding a loopback port nobody points at would be a listener for no
            // one, and it would take `:53` from whatever else wants it.
            if self.settings.mode == Mode::Native {
                log::info!("enabled in native mode; nothing for this process to start");
                self.enabled = true;
                return;
            }
            log::info!(
                "enabled, but this process cannot change adapters — starting the resolver only"
            );
            match self.ensure_stub().await {
                Ok(()) => self.enabled = true,
                Err(e) => log::error!("could not start the local resolver: {e:#}"),
            }
            return;
        }
        if !can_write_adapters {
            // Not enabled and nothing we may do about a leftover backup. Saying so beats a silent
            // no-op: the file staying put is what lets an elevated run finish the job later.
            if DnsBackup::exists() {
                log::warn!("a backup is on disk but this process cannot restore it (no administrator rights)");
            }
            return;
        }
        self.restore_on_start().await;
    }

    /// The elevated half of [`Self::resume`]. The service, which is always LocalSystem, has no
    /// other case and calls this directly.
    pub async fn restore_on_start(&mut self) {
        if !self.settings.enabled {
            // A backup left behind by a crash means the adapters may still point at a stub that
            // is not running. Put them back before anything else tries to resolve.
            if DnsBackup::exists() {
                log::warn!("found a backup while disabled — a previous run did not shut down cleanly; restoring");
                match restore_from_backup() {
                    // The same rule as every other revert path, and it was missing here: the file
                    // goes only after a COMPLETE restore. A partial one — netsh refused one
                    // adapter, so it is still on 127.0.0.1 with no stub behind it — used to delete
                    // the only record of what that adapter really had, in exactly the situation
                    // the record exists for.
                    Ok(warnings) if warnings.is_empty() => DnsBackup::delete(),
                    Ok(warnings) => log::error!(
                        "restore after an unclean shutdown finished with warnings, keeping {}: {}",
                        dns_ai_core::paths::backup_file().display(),
                        warnings.join("; ")
                    ),
                    Err(e) => log::error!("could not restore after an unclean shutdown: {e:#}"),
                }
            }
            return;
        }
        log::info!("settings say enabled; applying at start-up");
        if let Err(e) = self.enable().await {
            log::error!("could not enable at start-up: {e:#}");
        }
    }

    pub async fn enable(&mut self) -> Result<()> {
        match self.settings.mode {
            Mode::Stub => self.enable_stub().await,
            Mode::Native => {
                // The addresses are about to be written into an adapter, where nothing of ours can
                // notice they have gone stale: in native mode Windows resolves and this program is
                // not in the path. So this is the moment to ask where the resolver actually is —
                // the stub's warm-up does the same thing for the other mode, free, because it was
                // already asking (`dns_ai_core::endpoints`).
                if stub::refresh_endpoints(REFRESH_BUDGET).await.is_none() {
                    // Nothing we know about answered. In stub mode the resolver's own failures
                    // would start this search within seconds; here there is no stub to fail, so a
                    // machine enabled at boot against addresses that have moved would sit with no
                    // DNS until somebody opened the window. Bounded, because the alternative is a
                    // button that hangs on a machine that is merely offline.
                    log::warn!("no known address answered; looking for the resolver before enabling");
                    let _ = tokio::time::timeout(
                        RESCUE_BUDGET,
                        dns_ai_core::endpoints::rescue(),
                    )
                    .await;
                }
                self.enable_native()
            }
        }
    }

    /// Adapters -> `127.0.0.1`, this process resolves.
    async fn enable_stub(&mut self) -> Result<()> {
        // 1. The stub comes up FIRST. Pointing an adapter at a loopback address that nothing is
        //    listening on, even for a moment, is a machine with no DNS.
        self.ensure_stub().await?;

        let v4 = vec![ADAPTER_DNS_V4.to_string()];
        // Empty when the user turned IPv6 off, and empty means "static, none" rather than "leave
        // it alone": an untouched v6 side keeps the ISP's RA-supplied resolver, which Windows
        // prefers over v4 and which would see every query.
        let v6 = if self.settings.ipv6 {
            vec![ADAPTER_DNS_V6.to_string()]
        } else {
            Vec::new()
        };
        let (selection, _) = self.back_up()?;
        self.write_adapters(&selection.chosen, &v4, &v6, false)
    }

    /// Adapters -> the resolver's real addresses, and Windows does the encryption.
    ///
    /// The stub is not started here, and that is the point of the mode: nothing of ours sits in
    /// the query path, so our process dying costs the machine nothing.
    fn enable_native(&mut self) -> Result<()> {
        if !netif::native_doh_supported() {
            bail!(
                "этой Windows (сборка {}) нужен встроенный DoH-клиент, а он появился только в Windows 11. \
                 Выберите режим локального резолвера.",
                netif::windows_build()
            );
        }

        // IPv6 is CONFIGURED now, not cleared. It was cleared while only spb1 had a global v6
        // address: handing Windows a single v6 server it prefers over v4 would have aimed every
        // query at one node and depended on it alone. msk3 has one too, so the v6 pair is as
        // redundant as the v4 pair and both go in.
        //
        // With the switch off the v6 side is still emptied rather than left alone — an untouched
        // one keeps the ISP's RA-supplied resolver, which is the single most common way a machine
        // that looks protected still leaks every query (README §4.4).
        let v4 = config::resolver_ips_text();
        let v6 = if self.settings.ipv6 {
            config::resolver_ipv6_text()
        } else {
            Vec::new()
        };

        // Three steps, in an order each of which is load-bearing: the backup reaches the disk,
        // then the templates, then the addresses.
        //
        // The templates go in BEFORE the addresses. The reverse order leaves a window in which
        // the adapter points at a resolver Windows has no template for and no permission to reach
        // over UDP — which is not "briefly unencrypted", it is briefly nothing.
        //
        // And the backup goes in before the templates, with the templates we are about to add
        // already CLAIMED in it. They used to be recorded only after the adapters had taken the
        // change, and a process that died in between — several `netsh` runs wide — left
        // templates in Windows that no file named. The next start then found them present, took
        // them for somebody else's, and nothing ever removed them. A claim for a template that
        // never got added costs nothing: removing an absent one is a silent success (measured).
        let had_backup = DnsBackup::exists();
        let (selection, mut backup) = self.back_up()?;

        // One per ADDRESS, v6 included: Windows matches a template to the server it is about to
        // query, so a v6 address with no template is one Windows would only talk to in the clear —
        // and our nodes do not answer that at all (ROADMAP G35). A template that is already there
        // is left alone and unclaimed: the PowerShell installer left exactly these behind, and a
        // revert that deleted them would be removing configuration this program never made.
        let mut missing = Vec::new();
        for ip in v4.iter().chain(v6.iter()) {
            match netif::doh_template_lookup(ip) {
                Some(true) => log::info!("DoH template for {ip} already exists — leaving it alone"),
                Some(false) => missing.push(ip.clone()),
                // `netsh` could not be asked. Reading that as "absent" would claim a template that
                // may be somebody else's — and `add` does not refuse an existing entry, so nothing
                // after this would notice until a revert deleted it. A failed enable is the
                // smaller harm. Nothing is claimed yet, so only a backup this call made goes.
                None => {
                    if !had_backup {
                        DnsBackup::delete();
                    }
                    bail!("не удалось проверить DoH-шаблон для {ip} (netsh dns show encryption)");
                }
            }
        }
        let claimed = claim_templates(&mut backup, &missing);
        if !claimed.is_empty() {
            backup
                .save()
                .context("не удалось сохранить резервную копию настроек DNS")?;
        }

        for ip in &missing {
            if let Err(e) = netif::doh_template_add(ip, config::DOH_URL) {
                withdraw_templates(&mut backup, &missing, &claimed, had_backup);
                return Err(e)
                    .with_context(|| format!("не удалось зарегистрировать DoH-шаблон для {ip}"));
            }
            log::info!("registered DoH template {} -> {}", ip, config::DOH_URL);
        }

        // A failure from here on rolls back through `restore_from_backup`, which removes every
        // claimed template along with the adapters' previous state.
        self.write_adapters(&selection.chosen, &v4, &v6, true)
    }

    /// The first half both modes share: choose the adapters and get their current state onto the
    /// disk. Nothing on the machine changes here.
    fn back_up(&self) -> Result<(netif::AdapterSelection, DnsBackup)> {
        let selection = netif::select_adapters(self.settings.include_vpn_adapters)?;
        if selection.chosen.is_empty() {
            bail!("не найдено ни одного подходящего адаптера (все виртуальные, туннельные или без шлюза)");
        }

        // Record the previous state and get it onto the disk BEFORE changing anything. What the
        // revert can undo is exactly what reached the disk.
        //
        // `capture_preserving`, not `capture`: a backup that is still on disk means the last run
        // never reverted, so the adapters may already be pointing at our own stub. Reading them
        // there and calling the answer "the previous configuration" would overwrite the only
        // record of what the machine really had — and the machine would keep working until the
        // day somebody turned protection off.
        let backup = DnsBackup::capture_preserving(&selection.chosen);
        backup
            .save()
            .context("не удалось сохранить резервную копию настроек DNS")?;
        log::info!(
            "backed up {} adapter(s): {}",
            backup.adapters.len(),
            backup
                .adapters
                .iter()
                .map(|a| a.alias.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        Ok((selection, backup))
    }

    /// The second half: write, rolling everything back on first failure. Only ever called after
    /// [`Self::back_up`] has put the previous state on the disk.
    ///
    /// `v6` empty means "static, none" — the v6 side is emptied, never left as it was.
    ///
    /// `encrypted` is native mode: the servers go in together with the adapter's own DoH switch
    /// ([`netif::set_dns_encrypted`]). Writing only the addresses, as `netsh` does, left Windows
    /// showing «Незашифровано» against both of them although both templates were registered.
    fn write_adapters(
        &mut self,
        chosen: &[netif::Adapter],
        v4: &[String],
        v6: &[String],
        encrypted: bool,
    ) -> Result<()> {
        let write = |a: &netif::Adapter, family: Family, servers: &[String]| {
            if encrypted && !servers.is_empty() {
                netif::set_dns_encrypted(&a.guid, family, servers)
            } else {
                netif::set_dns_static(a.index, family, servers)
            }
        };

        for a in chosen {
            if let Err(e) = write(a, Family::V4, v4) {
                log::error!("could not configure {}: {e:#}; rolling back", a.alias);
                if let Err(re) = restore_from_backup() {
                    log::error!("rollback itself failed: {re:#}");
                }
                netif::flush_dns_cache();
                return Err(e).with_context(|| format!("адаптер «{}»", a.alias));
            }
            // IPv6 is a hardening step, not the resolution path, and it fails on machines that
            // have the protocol switched off on the adapter — where `netsh` refuses a v6 command
            // outright. Rolling the whole enable back for that would mean the users most likely to
            // turn the switch off are the ones who cannot turn protection on.
            if let Err(e) = write(a, Family::V6, v6) {
                log::warn!("{}: IPv6 DNS left as it was ({e:#})", a.alias);
            }
            log::info!(
                "{} -> {}{}",
                a.alias,
                v4.join(", "),
                if encrypted { " (DoH)" } else { "" }
            );
        }

        netif::flush_dns_cache();
        self.enabled = true;
        self.settings.enabled = true;
        let _ = self.settings.save();
        Ok(())
    }

    /// The user asked to turn it off: restore, then forget.
    pub async fn disable(&mut self) -> Result<()> {
        let result = restore_from_backup();
        netif::flush_dns_cache();

        // The stub stops only after the adapters no longer point at it.
        self.stop_stub().await;
        self.enabled = false;
        self.settings.enabled = false;
        let _ = self.settings.save();

        match result {
            Ok(warnings) => {
                // Backups are deleted only after a fully successful revert; if anything was
                // skipped the file stays so a second attempt is possible.
                if warnings.is_empty() {
                    DnsBackup::delete();
                } else {
                    log::warn!(
                        "revert finished with warnings, keeping {}: {}",
                        dns_ai_core::paths::backup_file().display(),
                        warnings.join("; ")
                    );
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// The window is going away — «Выход», the X button on a copy that is handing over to an
    /// elevated one, or the process simply ending.
    ///
    /// **It changes no DNS setting at all**, and that is the rule rather than an omission. Two
    /// things follow from it. Protection that the user switched on stays on: closing the window
    /// used to hand the adapters back to DHCP, so on the portable path the machine was protected
    /// only while a window happened to be open — and the elevated copy that a click on «Включить»
    /// starts is a window that is *expected* to be closed. And the backup stays on disk, which is
    /// what lets the next run — or `dns-ai uninstall` — put the machine back the way it was.
    ///
    /// The stub is stopped because it is a listener inside this process and it is going anyway;
    /// nothing on the machine is rewritten to say so.
    pub async fn release(&mut self) {
        self.stop_stub().await;
    }

    /// Service stop or machine shutdown. Restores the adapters but keeps the backup and the
    /// `enabled` setting, so the next start puts things back the way the user asked.
    ///
    /// Unlike [`Self::release`] this one does revert, and the asymmetry is deliberate: a service
    /// that stops is the *resolver* leaving a machine that may not get it back — nobody has to log
    /// in for a service to be stopped — while a window closing is a user putting a window away.
    pub async fn on_stop(&mut self) {
        if self.enabled {
            if let Err(e) = restore_from_backup() {
                log::error!("could not restore DNS while stopping: {e:#}");
            }
            netif::flush_dns_cache();
        }
        self.stop_stub().await;
    }

    async fn ensure_stub(&mut self) -> Result<()> {
        if self.stub.is_some() {
            return Ok(());
        }
        let handle = stub::start(self.settings.ipv6, self.stats.clone()).await?;
        self.stub = Some(handle);
        Ok(())
    }

    async fn stop_stub(&mut self) {
        if let Some(h) = self.stub.take() {
            h.stop().await;
        }
    }

    pub async fn set_settings(&mut self, new: Settings) -> Result<()> {
        // The start type is a property of the SCM registration, not of this process, and changing
        // it needs neither the stub nor the adapters touched — so it is applied first and on its
        // own. It is done HERE rather than in the window because the window is unelevated and this
        // is not: LocalSystem's token carries the Administrators group, which is what a service's
        // default security descriptor grants SERVICE_CHANGE_CONFIG to. A failure is reported and
        // not fatal; the rest of the settings are still the user's.
        if new.service_autostart != crate::service::start_type_is_auto() {
            if let Err(e) = crate::service::set_start_type(new.service_autostart) {
                log::warn!("could not change the service start type: {e:#}");
            }
        }

        // A mode change is the most invasive of these: it swaps which mechanism resolves at all,
        // so it always goes through the full off/on rather than being patched in place.
        let remode = new.mode != self.settings.mode;
        let restart_stub = new.ipv6 != self.settings.ipv6;
        let readapt = new.include_vpn_adapters != self.settings.include_vpn_adapters;
        let was_enabled = self.enabled;
        let (restart_stub, readapt) = (restart_stub || remode, readapt || remode);

        if was_enabled && (restart_stub || readapt) {
            // Go through a full off/on rather than patching live state: a half-applied change is
            // exactly the shape that produces a machine nobody can explain.
            self.disable().await?;
        }
        self.settings = Settings {
            enabled: self.settings.enabled,
            ..new
        };
        self.settings.save()?;

        if was_enabled && (restart_stub || readapt) {
            self.enable().await?;
        }
        Ok(())
    }

    pub fn status(&self) -> Status {
        let adapters = netif::select_adapters(self.settings.include_vpn_adapters)
            .map(|s| {
                s.chosen
                    .iter()
                    .map(|a| AdapterView {
                        alias: a.alias.clone(),
                        index: a.index,
                        current_v4: describe(&netif::read_dns_state(&a.guid, Family::V4)),
                        current_v6: describe(&netif::read_dns_state(&a.guid, Family::V6)),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Status {
            enabled: self.enabled,
            stub_running: self.stub.is_some(),
            adapters,
            settings: self.settings.clone(),
            native_supported: netif::native_doh_supported(),
            service_autostart: crate::service::start_type_is_auto(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Applies whatever the backup recorded. Returns the list of things it could not do — an empty
/// list means a complete revert.
///
/// A free function rather than a method on [`App`], because `dns-ai-svc uninstall` has to be
/// able to put DNS back when there is no running service left to ask, and that path must go
/// through exactly this code and not a second implementation of it.
pub fn restore_from_backup() -> Result<Vec<String>> {
    let Some(backup) = DnsBackup::load() else {
        bail!(
            "резервная копия не найдена ({}). Аварийный сброс: netsh interface ipv4 set dnsservers name=<индекс> source=dhcp",
            dns_ai_core::paths::backup_file().display()
        );
    };

    let mut warnings = Vec::new();
    // Match by GUID, not by the recorded index: a NIC driver update can recreate the adapter
    // with a new interface index, and the old index would then point at somebody else's adapter.
    let live = netif::list_adapters().unwrap_or_default();

    for record in &backup.adapters {
        let (clean, dropped) = record.sanitised();
        for d in dropped {
            warnings.push(format!("{}: пропущено значение {d}", record.alias));
        }

        let live_adapter = match live.iter().find(|a| a.guid == record.guid) {
            Some(a) => {
                if a.index != record.index {
                    log::warn!(
                        "{} changed interface index {} -> {}; using the live one",
                        record.alias,
                        record.index,
                        a.index
                    );
                }
                a
            }
            None => {
                warnings.push(format!(
                    "адаптер «{}» больше не существует — пропущен",
                    record.alias
                ));
                continue;
            }
        };

        // Logged before it is applied: an unexpected value has to be visible at the moment it is
        // used, not only afterwards in a post-mortem.
        log::info!(
            "restoring {}: IPv4 {}, IPv6 {}",
            record.alias,
            describe(&clean.v4),
            describe(&clean.v6)
        );

        // The DoH entries go back BEFORE the addresses: the address change is what makes Windows
        // re-read the adapter, and a restored server should come back already encrypted.
        //
        // The live adapter's GUID, not the file's: equal by the match above, but only one of them
        // came from a file, and this one becomes part of a registry path.
        let (index, guid) = (live_adapter.index, live_adapter.guid.as_str());
        for (family, saved) in [(Family::V4, &clean.doh_v4), (Family::V6, &clean.doh_v6)] {
            restore_doh_entries(guid, &record.alias, family, saved.as_deref(), &mut warnings);
        }

        if let Err(e) = netif::apply_state(index, Family::V4, &clean.v4) {
            warnings.push(format!("{}: IPv4 не восстановлен ({e})", record.alias));
        }
        if let Err(e) = netif::apply_state(index, Family::V6, &clean.v6) {
            warnings.push(format!("{}: IPv6 не восстановлен ({e})", record.alias));
        }
    }

    // Native mode's second half. This lives here rather than in `disable()` so that every path
    // that reverts — the user's toggle, a service stop, a shutdown, `uninstall` with no service
    // left to ask, and the recovery from an unclean shutdown — undoes the same things. A DoH
    // template we registered but never removed would keep pointing Windows at our resolver long
    // after the client was gone.
    for server in &backup.doh_added {
        match netif::doh_template_remove(server) {
            Ok(()) => log::info!("removed the DoH template we registered for {server}"),
            Err(e) => warnings.push(format!("DoH-шаблон для {server} не удалён ({e})")),
        }
    }

    Ok(warnings)
}

/// Puts one family's per-adapter DoH entries back the way the backup found them.
///
/// Our entries go — every one naming a resolver address that the backup does not also name, since
/// the adapter is about to stop using those servers. The backup names one only when the user's own
/// list contained that address (`doh_entry_is_ours` in `backup.rs`), and then it stays. The saved
/// ones come back only where they differ from what is there, so a revert of stub mode, which never
/// touched them, writes nothing. Entries that are neither ours nor saved are left alone: they are
/// somebody's, and not ours to judge.
fn restore_doh_entries(
    guid: &str,
    alias: &str,
    family: Family,
    saved: Option<&[DohEntry]>,
    warnings: &mut Vec<String>,
) {
    let saved = saved.unwrap_or_default();
    let current = netif::read_doh_entries(guid, family);
    let ours = current.iter().filter(|e| {
        config::is_resolver_address(&e.server)
            && !saved.iter().any(|s| netif::same_address(&s.server, &e.server))
    });
    for entry in ours {
        match netif::delete_doh_entry(guid, family, &entry.server) {
            Ok(()) => log::info!("{alias}: removed our DoH switch for {}", entry.server),
            Err(e) => warnings.push(format!("{alias}: DoH для {} не снят ({e})", entry.server)),
        }
    }
    for entry in saved {
        if current.contains(entry) {
            continue;
        }
        match netif::write_doh_entry(guid, family, entry) {
            Ok(()) => log::info!("{alias}: restored the DoH switch for {}", entry.server),
            Err(e) => warnings.push(format!("{alias}: DoH для {} не восстановлен ({e})", entry.server)),
        }
    }
}

/// Undoes the template step of a native enable that failed before any adapter was touched.
///
/// Every template this call may have added is removed, and a claim is withdrawn only once its
/// template is confirmed gone. Withdrawing the claim for one whose removal failed would recreate
/// the very orphan claiming exists to prevent: Windows keeps the template, no file names it, and
/// the next enable takes it for somebody else's. So a backup this call created is deleted only
/// when nothing is left owing; otherwise it stays, and the next start — which reads a backup
/// with protection off as an unclean shutdown — finishes the removal.
fn withdraw_templates(
    backup: &mut DnsBackup,
    missing: &[String],
    claimed: &[String],
    had_backup: bool,
) {
    let unremoved: Vec<&String> = missing
        .iter()
        .filter(|ip| match netif::doh_template_remove(ip) {
            Ok(()) => false,
            Err(e) => {
                log::error!("could not remove the DoH template for {ip}: {e:#}");
                true
            }
        })
        .collect();
    let withdrawn: Vec<&String> = claimed.iter().filter(|s| !unremoved.contains(s)).collect();
    backup.doh_added.retain(|s| !withdrawn.contains(&s));

    if !had_backup && backup.doh_added.is_empty() {
        DnsBackup::delete();
    } else if !withdrawn.is_empty() {
        if let Err(e) = backup.save() {
            log::error!("could not save the backup after withdrawing template claims: {e:#}");
        }
    }
}

/// Adds to the backup's `doh_added` every address in `missing` it does not already name, and
/// returns the ones this call added — the claims a failed enable has to take back.
///
/// Added to, never assigned over: a claim from an earlier run is still owed a removal even when
/// its template is present today, and a list replaced wholesale would orphan it.
fn claim_templates(backup: &mut DnsBackup, missing: &[String]) -> Vec<String> {
    let mut claimed = Vec::new();
    for ip in missing {
        if !backup.doh_added.contains(ip) {
            backup.doh_added.push(ip.clone());
            claimed.push(ip.clone());
        }
    }
    claimed
}

fn describe(state: &DnsState) -> String {
    match state {
        DnsState::Dhcp => "автоматически (DHCP)".to_string(),
        DnsState::Static(list) if list.is_empty() => "вручную, пусто".to_string(),
        DnsState::Static(list) => list.join(", "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim that survives a crash is the one that is already on the list. Only new claims
    /// are handed back for a failed enable to withdraw — withdrawing an old one would orphan a
    /// template an earlier run registered.
    #[test]
    fn claims_are_added_and_only_new_ones_are_returned() {
        let mut backup = DnsBackup {
            created_unix: 1,
            adapters: Vec::new(),
            doh_added: vec!["2a0d:8480:0:67c::14".into()],
        };
        let missing = vec!["2a0d:8480:0:67c::14".to_string(), "2a0a:2b41:0:500d::53".into()];

        let claimed = claim_templates(&mut backup, &missing);
        assert_eq!(claimed, vec!["2a0a:2b41:0:500d::53".to_string()]);
        assert_eq!(backup.doh_added, missing);

        assert!(claim_templates(&mut backup, &missing).is_empty());
        assert_eq!(backup.doh_added.len(), 2, "claiming twice must not duplicate");
    }
}
