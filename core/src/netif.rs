//! Network adapters: enumeration, current DNS state, and applying a new one.
//!
//! Two rules shape this module.
//!
//! **Adapters are addressed by interface index, never by name.** `netsh interface ipv4 set
//! dnsservers` takes "the name or index of the interface" and the index sidesteps localised
//! aliases ("Подключение по локальной сети"), aliases containing quotes, and console code-page
//! mangling on the way in.
//!
//! **Static and DHCP are told apart in the registry, not from the effective list.** The API that
//! reports DNS servers reports what is *in use*; it cannot say whether an administrator set them
//! or DHCP handed them out. Restoring "as it was" needs that distinction, so the backup reads
//! `NameServer` (static) against `DhcpNameServer` (leased) directly.

use std::os::windows::process::CommandExt;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::Globalization::{GetOEMCP, MultiByteToWideChar};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    DnsServerDohProperty, GetAdaptersAddresses, DNS_DOH_SERVER_SETTINGS,
    DNS_DOH_SERVER_SETTINGS_ENABLE_AUTO, DNS_INTERFACE_SETTINGS3, DNS_INTERFACE_SETTINGS_VERSION3,
    DNS_SERVER_PROPERTY, DNS_SERVER_PROPERTY_TYPES, DNS_SERVER_PROPERTY_VERSION1, DNS_SETTING_DOH,
    DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

/// `CREATE_NO_WINDOW`. Every helper process we start must carry it: a service has no desktop,
/// and from the tray a bare `Command` flashes a console window on screen.
pub const fn no_window() -> u32 {
    0x0800_0000
}

// IANA ifType values, spelled out rather than imported: the constants live in different modules
// across `windows-sys` releases and these four never change.
const IF_TYPE_PPP: u32 = 23;
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IF_TYPE_TUNNEL: u32 = 131;
const IF_OPER_STATUS_UP: i32 = 1;

/// Substrings that mark an adapter as virtual — something with no path to the internet of its
/// own. Matched case-insensitively against both the friendly name and the description.
const VIRTUAL_MARKERS: &[&str] = &[
    "vethernet",
    "hyper-v",
    "vmware",
    "virtualbox",
    "vbox",
    "wsl",
    "docker",
    "loopback",
    "wi-fi direct",
    "wifi direct",
    "microsoft wi-fi direct",
    "teredo",
    "isatap",
    "bluetooth",
    "npcap",
    "packet scheduler",
];

/// Substrings that mark a tunnel. These are skipped by default and only with a warning: a VPN
/// client installs and re-asserts its own DNS, so configuring the tunnel adapter produces a
/// machine whose resolution depends on which service won the last race.
const VPN_MARKERS: &[&str] = &[
    "wireguard",
    "wintun",
    "openvpn",
    "tap-windows",
    "tap adapter",
    "tailscale",
    "zerotier",
    "anyconnect",
    "nordlynx",
    "globalprotect",
    "pangp",
    "forticlient",
    "amnezia",
    "mullvad",
    "proton",
    "outline",
    "wan miniport",
    "softether",
    "hamachi",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn netsh_context(self) -> &'static str {
        match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }
    }

    fn tcpip_service(self) -> &'static str {
        match self {
            Family::V4 => "Tcpip",
            Family::V6 => "Tcpip6",
        }
    }
}

/// What an adapter's DNS configuration was, in the only two shapes Windows can restore it to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "servers")]
pub enum DnsState {
    /// Obtain automatically. Whatever DHCP/RA hands out is what gets used.
    Dhcp,
    /// An explicit list. May be empty, which is a real state: "static, none configured".
    Static(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterKind {
    /// A real path to the internet.
    Physical,
    /// Virtual or host-only — skipped, and named in the report.
    Virtual(String),
    /// A tunnel — skipped unless the operator opts in.
    Vpn(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Adapter {
    pub index: u32,
    pub ipv6_index: u32,
    /// The interface GUID, e.g. `{2C1B...}` — this is what the registry is keyed by.
    pub guid: String,
    pub alias: String,
    pub description: String,
    pub if_type: u32,
    pub up: bool,
    pub gateway_v4: bool,
    pub gateway_v6: bool,
}

impl Adapter {
    pub fn kind(&self) -> AdapterKind {
        let hay = format!("{} {}", self.alias, self.description).to_lowercase();
        if self.if_type == IF_TYPE_SOFTWARE_LOOPBACK {
            return AdapterKind::Virtual("loopback".into());
        }
        if let Some(m) = VIRTUAL_MARKERS.iter().find(|m| hay.contains(**m)) {
            return AdapterKind::Virtual((*m).to_string());
        }
        if let Some(m) = VPN_MARKERS.iter().find(|m| hay.contains(**m)) {
            return AdapterKind::Vpn((*m).to_string());
        }
        if self.if_type == IF_TYPE_TUNNEL || self.if_type == IF_TYPE_PPP {
            return AdapterKind::Vpn(format!("ifType {}", self.if_type));
        }
        AdapterKind::Physical
    }

    /// Windows resolves against every interface that has DNS servers, so "the adapter with the
    /// lowest metric" is the wrong unit — anything with a default route can answer.
    pub fn has_default_route(&self) -> bool {
        self.gateway_v4 || self.gateway_v6
    }
}

/// Why an adapter was left alone. Shown in the UI: "my Wi-Fi was not configured" needs an answer
/// that is not a shrug.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedAdapter {
    pub alias: String,
    pub reason: String,
}

pub struct AdapterSelection {
    pub chosen: Vec<Adapter>,
    pub skipped: Vec<SkippedAdapter>,
}

/// Every adapter the machine has, in the order Windows reports them.
pub fn list_adapters() -> Result<Vec<Adapter>> {
    const FLAGS: u32 = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;

    let mut size: u32 = 32 * 1024;
    // A `Vec<u64>` rather than `Vec<u8>`: the buffer is cast to a struct with 8-byte fields and
    // `Vec<u8>` carries no alignment guarantee.
    let mut buf: Vec<u64> = Vec::new();

    for _ in 0..5 {
        buf.clear();
        buf.resize((size as usize).div_ceil(8), 0);
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                FLAGS,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        match rc {
            ERROR_SUCCESS => {
                return Ok(unsafe {
                    parse_adapters(buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH)
                })
            }
            // `size` now holds what is actually needed; go round again.
            ERROR_BUFFER_OVERFLOW => continue,
            other => bail!("GetAdaptersAddresses failed with code {other}"),
        }
    }
    bail!("GetAdaptersAddresses kept asking for a bigger buffer")
}

unsafe fn parse_adapters(head: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<Adapter> {
    let mut out = Vec::new();
    let mut p = head;
    while !p.is_null() {
        let a = &*p;
        let (mut gw4, mut gw6) = (false, false);
        let mut g = a.FirstGatewayAddress;
        while !g.is_null() {
            let sa = (*g).Address.lpSockaddr;
            if !sa.is_null() {
                match (*sa).sa_family {
                    f if f == AF_INET => gw4 = true,
                    f if f == AF_INET6 => gw6 = true,
                    _ => {}
                }
            }
            g = (*g).Next;
        }
        out.push(Adapter {
            index: a.Anonymous1.Anonymous.IfIndex,
            ipv6_index: a.Ipv6IfIndex,
            guid: cstr(a.AdapterName),
            alias: wstr(a.FriendlyName),
            description: wstr(a.Description),
            if_type: a.IfType,
            up: a.OperStatus == IF_OPER_STATUS_UP,
            gateway_v4: gw4,
            gateway_v6: gw6,
        });
        p = a.Next;
    }
    out
}

unsafe fn wstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0usize;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

unsafe fn cstr(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0usize;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(p, n)).into_owned()
}

/// The adapters we will configure, and every one we will not, with the reason.
pub fn select_adapters(include_vpn: bool) -> Result<AdapterSelection> {
    let all = list_adapters()?;
    let mut chosen = Vec::new();
    let mut skipped = Vec::new();

    for a in all {
        if !a.up {
            continue; // Down adapters are noise, not a decision worth reporting.
        }
        if !a.has_default_route() {
            skipped.push(SkippedAdapter {
                alias: a.alias.clone(),
                reason: "нет шлюза по умолчанию".into(),
            });
            continue;
        }
        match a.kind() {
            AdapterKind::Physical => chosen.push(a),
            AdapterKind::Virtual(m) => skipped.push(SkippedAdapter {
                alias: a.alias.clone(),
                reason: format!("виртуальный адаптер ({m})"),
            }),
            AdapterKind::Vpn(m) => {
                if include_vpn {
                    chosen.push(a);
                } else {
                    skipped.push(SkippedAdapter {
                        alias: a.alias.clone(),
                        reason: format!("VPN/туннель ({m}) — включается в настройках"),
                    });
                }
            }
        }
    }
    Ok(AdapterSelection { chosen, skipped })
}

/// Reads the *configured* DNS state straight out of the registry.
///
/// A missing interface key is reported as `Dhcp`, which is what "obtain automatically" restores
/// to — the safe answer when the machine has nothing recorded.
pub fn read_dns_state(guid: &str, family: Family) -> DnsState {
    let path = format!(
        r"SYSTEM\CurrentControlSet\Services\{}\Parameters\Interfaces\{}",
        family.tcpip_service(),
        guid
    );
    let key = match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(&path) {
        Ok(k) => k,
        Err(e) => {
            log::debug!("no registry key {path} ({e}); treating as DHCP");
            return DnsState::Dhcp;
        }
    };
    let ns: String = key.get_value("NameServer").unwrap_or_default();
    let servers: Vec<String> = ns
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    if servers.is_empty() {
        // `NameServer` empty means the interface is on DHCP for this family — whatever
        // `DhcpNameServer` holds is a lease, not a configuration, and must not be restored as
        // static or it would freeze a value the network is entitled to change.
        DnsState::Dhcp
    } else {
        DnsState::Static(servers)
    }
}

/// Points one family of one adapter at an explicit list. An empty list is "static, none".
///
/// Named `netsh` parameters throughout, and on purpose: the positional form would force us to
/// supply `register` in order to reach `validate`, and passing a value there would silently
/// change whether the adapter registers itself in DNS — a setting we have no business touching.
/// Naming the parameters leaves every one we do not mention alone.
pub fn set_dns_static(index: u32, family: Family, servers: &[String]) -> Result<()> {
    let ctx = family.netsh_context();
    let name = format!("name={index}");

    let first = servers.first().map(String::as_str).unwrap_or("none");
    netsh(&[
        "interface",
        ctx,
        "set",
        "dnsservers",
        &name,
        "source=static",
        &format!("address={first}"),
        "validate=no",
    ])?;

    for (i, s) in servers.iter().enumerate().skip(1) {
        netsh(&[
            "interface",
            ctx,
            "add",
            "dnsservers",
            &name,
            &format!("address={s}"),
            &format!("index={}", i + 1),
            "validate=no",
        ])?;
    }
    Ok(())
}

/// Returns one family of one adapter to "obtain DNS automatically".
pub fn set_dns_dhcp(index: u32, family: Family) -> Result<()> {
    netsh(&[
        "interface",
        family.netsh_context(),
        "set",
        "dnsservers",
        &format!("name={index}"),
        "source=dhcp",
    ])
}

pub fn apply_state(index: u32, family: Family, state: &DnsState) -> Result<()> {
    match state {
        DnsState::Dhcp => set_dns_dhcp(index, family),
        DnsState::Static(servers) => set_dns_static(index, family, servers),
    }
}

pub fn flush_dns_cache() {
    if let Err(e) = run(Command::new("ipconfig").arg("/flushdns")) {
        log::warn!("could not flush the DNS cache: {e}");
    }
}

// =============================================================================================
// Windows' own DoH client (native mode)
// =============================================================================================

/// The build number from the registry rather than `GetVersionEx`, which lies to processes without
/// a matching compatibility manifest and would report 6.2 here.
pub fn windows_build() -> u32 {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .ok()
        .and_then(|k| k.get_value::<String, _>("CurrentBuildNumber").ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Windows 11 (22000) is where the DoH client actually shipped.
///
/// This gates the *offer*, not just the advice. On Windows 10 the mode is not merely worse, it is
/// broken by construction: the DoH client is absent from retail and our nodes refuse plain `:53`,
/// so an adapter pointed at them resolves nothing at all (ROADMAP N14).
pub fn native_doh_supported() -> bool {
    windows_build() >= 22000
}

/// Registers a DoH template so Windows encrypts queries to `server` instead of sending them in
/// the clear.
///
/// `udpfallback=no` is not a preference. Our resolvers do not answer plain `:53` from the
/// internet, so a fallback would not degrade to unencrypted DNS — it would degrade to silence,
/// and take the timeout with it. Refusing the fallback turns that into an immediate, visible
/// failure instead.
pub fn doh_template_add(server: &str, template: &str) -> Result<()> {
    netsh(&[
        "dns",
        "add",
        "encryption",
        &format!("server={server}"),
        &format!("dohtemplate={template}"),
        "autoupgrade=yes",
        "udpfallback=no",
    ])
}

/// Removes the template for `server`. Removing one that is not there is a success.
///
/// On 26100 `netsh` itself says so — exit 0, no output, for an absent entry, v4 and v6 alike
/// (measured). The fallback below is for the builds that have not been measured: a failure that
/// leaves no template behind is still the outcome the caller asked for. It matters because the
/// backup claims a template BEFORE adding it, so a revert after a crash can name one that never
/// got in, and a warning there would keep the backup — and the machine's revert — pending for ever.
pub fn doh_template_remove(server: &str) -> Result<()> {
    match netsh(&["dns", "delete", "encryption", &format!("server={server}")]) {
        Err(e) if doh_template_lookup(server) == Some(false) => {
            log::debug!("no DoH template for {server} to remove ({e:#})");
            Ok(())
        }
        other => other,
    }
}

/// Whether Windows already knows a template for this address.
///
/// Checked before we add one, and the answer is recorded in the backup: a template that was here
/// before us must survive our uninstall. The machine this was first run on already carried
/// exactly these two entries, added by the PowerShell installer weeks earlier.
pub fn doh_template_exists(server: &str) -> bool {
    doh_template_lookup(server) == Some(true)
}

/// `None` when `netsh` could not be asked at all — which must not read as "there is none".
pub fn doh_template_lookup(server: &str) -> Option<bool> {
    let mut cmd = Command::new("netsh");
    cmd.args(["dns", "show", "encryption", &format!("server={server}")]);
    let out = cmd.creation_flags(no_window()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    // `show encryption` exits 0 whether or not the entry exists, with empty output for an absent
    // one (measured on 26100); the presence of the template line is the only reliable signal.
    Some(
        oem_to_string(&out.stdout)
            .to_lowercase()
            .contains("https://"),
    )
}

// =============================================================================================
// The adapter's own DoH switch (native mode, the half the template table is not)
// =============================================================================================

/// One per-adapter DoH entry, as Windows keeps it: the server address it applies to, `DohFlags`,
/// and the template when the entry carries its own.
///
/// Stored in the backup, because turning our switch on replaces every entry of that family on the
/// adapter — including ones the user set in Settings for their previous DNS servers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DohEntry {
    /// The address exactly as the registry names the entry.
    pub server: String,
    pub flags: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

/// Turns on encryption for `servers` on one family of one adapter — what Settings calls «Шифрование
/// DNS: вкл. (автоматический шаблон)» — and makes them that family's DNS servers in the same call.
///
/// **The template table is not this switch, and treating it as enough was the defect.** A Windows
/// 11 with both templates registered, `autoupgrade=yes`, still showed «Незашифровано» against both
/// addresses. The table says which template an address has; this says whether the adapter uses it.
/// `netsh interface … set dnsservers` neither sets nor clears it (all measured on 26100).
///
/// Three measured facts decide the shape:
/// - `DNS_SETTING_DOH` without `DNS_SETTING_NAMESERVER` returns success and stores nothing, so the
///   server list has to travel in the same call — which is also the ordering we want: there is no
///   moment in which the adapter points at our addresses with the switch off.
/// - The call REPLACES every entry of that family on the adapter, not just the ones it names. That
///   is why [`read_doh_entries`] is snapshotted into the backup before it runs.
/// - "Automatic template" (`DNS_DOH_SERVER_SETTINGS_ENABLE_AUTO`) is honoured only while the address
///   has a template in the table, so [`doh_template_add`] still has to run first.
///
/// Resolved at run time rather than imported: `SetInterfaceDnsSettings` is Windows 10 2004, and a
/// static import would stop the one Windows 7 binary loading at all (README §3). Native mode is
/// gated to Windows 11 long before anything calls this.
pub fn set_dns_encrypted(guid: &str, family: Family, servers: &[String]) -> Result<()> {
    if servers.is_empty() {
        bail!("encrypted DNS needs at least one server");
    }
    let interface = parse_guid(guid)?;
    let set = set_interface_dns_settings()?;

    let mut name_server: Vec<u16> = servers.join(",").encode_utf16().chain([0]).collect();
    let mut doh: Vec<DNS_DOH_SERVER_SETTINGS> = servers
        .iter()
        .map(|_| DNS_DOH_SERVER_SETTINGS {
            Template: std::ptr::null_mut(),
            Flags: DNS_DOH_SERVER_SETTINGS_ENABLE_AUTO as u64,
        })
        .collect();
    // Raw pointers into `doh`, which is neither moved nor resized until the call has returned.
    let mut properties: Vec<DNS_SERVER_PROPERTY> = doh
        .iter_mut()
        .enumerate()
        .map(|(i, d)| DNS_SERVER_PROPERTY {
            Version: DNS_SERVER_PROPERTY_VERSION1,
            ServerIndex: i as u32,
            Type: DnsServerDohProperty,
            Property: DNS_SERVER_PROPERTY_TYPES { DohSettings: d },
        })
        .collect();

    let mut flags = DNS_SETTING_NAMESERVER | DNS_SETTING_DOH;
    if family == Family::V6 {
        flags |= DNS_SETTING_IPV6;
    }
    // Every field this call does not name in `Flags` is ignored, so zero is "leave it alone".
    let mut settings: DNS_INTERFACE_SETTINGS3 = unsafe { std::mem::zeroed() };
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION3;
    settings.Flags = flags as u64;
    settings.NameServer = name_server.as_mut_ptr();
    settings.cServerProperties = properties.len() as u32;
    settings.ServerProperties = properties.as_mut_ptr();

    let rc = unsafe { set(interface, &settings) };
    if rc != ERROR_SUCCESS {
        bail!(
            "SetInterfaceDnsSettings ({}, {}) failed with code {rc}",
            family.netsh_context(),
            servers.join(", ")
        );
    }
    Ok(())
}

type SetInterfaceDnsSettingsFn =
    unsafe extern "system" fn(GUID, *const DNS_INTERFACE_SETTINGS3) -> u32;

fn set_interface_dns_settings() -> Result<SetInterfaceDnsSettingsFn> {
    let library: Vec<u16> = "iphlpapi.dll".encode_utf16().chain([0]).collect();
    unsafe {
        // System32 only: a DLL of that name beside a portable copy must never be the one loaded
        // into a LocalSystem process.
        let module = LoadLibraryExW(
            library.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        );
        if module.is_null() {
            bail!("could not load iphlpapi.dll");
        }
        // The module is never freed: it is already mapped for `GetAdaptersAddresses`, and the
        // pointer below must stay valid for the life of the process.
        match GetProcAddress(module, c"SetInterfaceDnsSettings".as_ptr().cast()) {
            Some(f) => Ok(std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                SetInterfaceDnsSettingsFn,
            >(f)),
            None => bail!("this Windows has no SetInterfaceDnsSettings"),
        }
    }
}

/// `{E6AF56C0-9A53-4678-9CB8-A69ADE6489F1}` -> `GUID`. Braces optional, hex digits only.
fn parse_guid(text: &str) -> Result<GUID> {
    let inner = text.trim().trim_start_matches('{').trim_end_matches('}');
    let groups: Vec<&str> = inner.split('-').collect();
    let shape_ok = groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups
            .iter()
            .all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()));
    if !shape_ok {
        bail!("not an interface GUID: {text}");
    }
    let value = u128::from_str_radix(&groups.concat(), 16)
        .with_context(|| format!("not an interface GUID: {text}"))?;
    Ok(GUID::from_u128(value))
}

fn doh_key_path(guid: &str, family: Family) -> String {
    format!(
        r"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\{}\DohInterfaceSettings\{}",
        guid,
        match family {
            Family::V4 => "Doh",
            Family::V6 => "Doh6",
        }
    )
}

/// Every per-adapter DoH entry of one family, read from where Windows keeps them.
///
/// The registry rather than `GetInterfaceDnsSettings`, because the API only reports entries for
/// addresses in the adapter's current server list, and an adapter on DHCP has none — while its
/// entries still exist and come back the moment one of those addresses is configured again.
pub fn read_doh_entries(guid: &str, family: Family) -> Vec<DohEntry> {
    let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(doh_key_path(guid, family)) else {
        return Vec::new();
    };
    key.enum_keys()
        .filter_map(Result::ok)
        .filter_map(|server| {
            let flags = key
                .open_subkey(&server)
                .and_then(|sub| sub.get_raw_value("DohFlags").map(|v| (sub, v)));
            // QWORD is what 26100 writes; a DWORD is accepted rather than lost, because an entry
            // this cannot read is one the switch will replace and the revert will not bring back.
            let parsed = flags.as_ref().ok().and_then(|(_, v)| match (&v.vtype, v.bytes.len()) {
                (winreg::enums::RegType::REG_QWORD, 8) => {
                    Some(u64::from_le_bytes(v.bytes[..8].try_into().ok()?))
                }
                (winreg::enums::RegType::REG_DWORD, 4) => {
                    Some(u32::from_le_bytes(v.bytes[..4].try_into().ok()?) as u64)
                }
                _ => None,
            });
            match (flags, parsed) {
                (Ok((sub, _)), Some(flags)) => Some(DohEntry {
                    template: sub.get_value::<String, _>("DohTemplate").ok(),
                    server,
                    flags,
                }),
                _ => {
                    log::warn!(
                        "unreadable DoH entry {} under {guid} ({family:?}); it will not be in the backup",
                        server
                    );
                    None
                }
            }
        })
        .collect()
}

/// Two spellings of one address are one address: `2A0D:8480:0000:067C::0014` is `2a0d:8480:0:67c::14`.
pub fn same_address(a: &str, b: &str) -> bool {
    match (
        a.trim().parse::<std::net::IpAddr>(),
        b.trim().parse::<std::net::IpAddr>(),
    ) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Writes one entry back as Windows stores it: `DohFlags` REG_QWORD, `DohTemplate` REG_SZ.
pub fn write_doh_entry(guid: &str, family: Family, entry: &DohEntry) -> Result<()> {
    let path = format!(r"{}\{}", doh_key_path(guid, family), entry.server);
    let (key, _) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .create_subkey(&path)
        .with_context(|| format!("cannot open HKLM\\{path}"))?;
    key.set_value("DohFlags", &entry.flags)?;
    match &entry.template {
        Some(t) => key.set_value("DohTemplate", t)?,
        None => {
            let _ = key.delete_value("DohTemplate");
        }
    }
    Ok(())
}

pub fn delete_doh_entry(guid: &str, family: Family, server: &str) -> Result<()> {
    let path = format!(r"{}\{}", doh_key_path(guid, family), server);
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .delete_subkey_all(&path)
        .with_context(|| format!("cannot delete HKLM\\{path}"))
}

fn netsh(args: &[&str]) -> Result<()> {
    let mut cmd = Command::new("netsh");
    cmd.args(args);
    run(&mut cmd).with_context(|| format!("netsh {}", args.join(" ")))
}

fn run(cmd: &mut Command) -> Result<()> {
    let out = cmd
        .creation_flags(no_window())
        .output()
        .context("could not start the process")?;
    if out.status.success() {
        return Ok(());
    }
    // netsh reports most failures on stdout, not stderr, and in the console OEM code page —
    // decoding it as UTF-8 would turn a Russian error message into mojibake at exactly the
    // moment it is needed.
    let mut text = oem_to_string(&out.stdout);
    let err = oem_to_string(&out.stderr);
    if !err.trim().is_empty() {
        text.push_str(err.trim());
    }
    Err(anyhow!(
        "exit {:?}: {}",
        out.status.code(),
        text.trim().replace(['\r', '\n'], " ")
    ))
}

/// Decodes console output using the OEM code page (866 on a Russian machine, 437 on English).
fn oem_to_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    unsafe {
        let cp = GetOEMCP();
        let needed = MultiByteToWideChar(
            cp,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            std::ptr::null_mut(),
            0,
        );
        if needed <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut wide = vec![0u16; needed as usize];
        let written = MultiByteToWideChar(
            cp,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            wide.as_mut_ptr(),
            needed,
        );
        if written <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        String::from_utf16_lossy(&wide[..written as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The byte order is the part that fails silently: a GUID with `data4` reversed is a valid
    /// GUID for no adapter, and `SetInterfaceDnsSettings` reports that as "not found", not "wrong".
    #[test]
    fn interface_guid_is_parsed_field_by_field() {
        let g = parse_guid("{E6AF56C0-9A53-4678-9CB8-A69ADE6489F1}").unwrap();
        assert_eq!(g.data1, 0xE6AF56C0);
        assert_eq!(g.data2, 0x9A53);
        assert_eq!(g.data3, 0x4678);
        assert_eq!(g.data4, [0x9C, 0xB8, 0xA6, 0x9A, 0xDE, 0x64, 0x89, 0xF1]);

        let bare = parse_guid("e6af56c0-9a53-4678-9cb8-a69ade6489f1").unwrap();
        assert_eq!((bare.data1, bare.data4), (g.data1, g.data4));
    }

    #[test]
    fn anything_but_a_guid_is_refused() {
        for bad in [
            "",
            "{E6AF56C0-9A53-4678-9CB8-A69ADE6489F}",
            "{E6AF56C09A5346789CB8A69ADE6489F1}",
            "{+6AF56C0-9A53-4678-9CB8-A69ADE6489F1}",
            r"{E6AF56C0-9A53-4678-9CB8-A69ADE6489F1}\Doh",
        ] {
            assert!(parse_guid(bad).is_err(), "{bad:?} was accepted");
        }
    }
}
