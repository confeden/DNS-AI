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
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::Globalization::{GetOEMCP, MultiByteToWideChar};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};
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

pub fn doh_template_remove(server: &str) -> Result<()> {
    netsh(&["dns", "delete", "encryption", &format!("server={server}")])
}

/// Whether Windows already knows a template for this address.
///
/// Checked before we add one, and the answer is recorded in the backup: a template that was here
/// before us must survive our uninstall. The machine this was first run on already carried
/// exactly these two entries, added by the PowerShell installer weeks earlier.
pub fn doh_template_exists(server: &str) -> bool {
    let mut cmd = Command::new("netsh");
    cmd.args(["dns", "show", "encryption", &format!("server={server}")]);
    match cmd.creation_flags(no_window()).output() {
        Ok(out) => {
            let text = oem_to_string(&out.stdout);
            // `show encryption` exits 0 whether or not the entry exists; the presence of the
            // template line is the only reliable signal.
            out.status.success() && text.to_lowercase().contains("https://")
        }
        Err(_) => false,
    }
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
