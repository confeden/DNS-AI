//! The named-pipe protocol between the tray UI and the service.
//!
//! The split exists because the two halves need different privileges and different lifetimes.
//! Changing adapter DNS needs administrator rights, and the stub has to keep resolving while no
//! user is logged in — so that work belongs to a SYSTEM service. The tray, by contrast, runs as
//! the logged-in user with no elevation, which is what lets it start from the Run key without a
//! UAC prompt at every logon.
//!
//! One request, one response, one connection. Messages are single-line JSON: a DNS client is not
//! the place for a framing protocol nobody can debug by hand.

use serde::{Deserialize, Serialize};

use crate::config::Settings;

pub const PIPE_NAME: &str = r"\\.\pipe\dns-ai-svc";

/// Security descriptor for the pipe, in SDDL.
///
/// `SY` (SYSTEM) and `BA` (Administrators) get everything; `IU` — the interactive user, i.e.
/// whoever is actually sitting at the machine — gets read and write so the unelevated tray can
/// talk to us. Note what that grants: a standard interactive user can switch DNS on and off.
/// That is the intended product behaviour (it is the same trust model every VPN client on
/// Windows uses), but it is a decision, not an accident, and it is the reason the protocol below
/// carries no free-form paths or addresses — everything the service acts on comes from its own
/// configuration, never from the wire.
pub const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Current state. Cheap enough to poll from the UI.
    Status,
    /// Back up the current DNS configuration and point the adapters at the stub.
    Enable,
    /// Restore exactly what the backup recorded.
    Disable,
    /// Replace the persisted settings. If the client is enabled, the service re-applies.
    SetSettings { settings: Settings },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterView {
    pub alias: String,
    pub index: u32,
    /// What the adapter's IPv4 DNS is right now, as text, for display only.
    pub current_v4: String,
    pub current_v6: String,
}

/// What the window draws. Nothing here is a statistic: query and error counters used to ride along
/// and be shown, and a number that only ever goes up tells a user nothing they can act on. The stub
/// still counts them for the log.
///
/// `serde(default)` because the two halves are upgraded separately: `setup` replaces the file and
/// restarts the service, but a tray started before that is still on screen and still asking. A
/// missing field there is one build talking to another, not a fault, and refusing the whole reply
/// over it draws «Служба не отвечает» on a machine where everything works.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Status {
    /// The service believes the adapters are pointed at us.
    pub enabled: bool,
    /// The loopback listeners are up.
    pub stub_running: bool,
    pub adapters: Vec<AdapterView>,
    pub settings: Settings,
    /// Whether this Windows has a DoH client at all. Answered by the service, because the tray
    /// must not decide it independently — one process reading the build number keeps the UI and
    /// the code that would actually apply the mode from disagreeing.
    pub native_supported: bool,
    /// How the SCM is actually configured to start us, read from the registration rather than from
    /// [`Settings::service_autostart`]. The two can differ — somebody changes it in `services.msc`,
    /// or a change failed — and a switch that shows the wish instead of the machine is the kind of
    /// setting that quietly stops being true.
    pub service_autostart: bool,
    pub service_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub error: Option<String>,
    pub status: Option<Status>,
}

impl Response {
    pub fn ok(status: Status) -> Self {
        Self {
            ok: true,
            error: None,
            status: Some(status),
        }
    }

    pub fn err(e: impl std::fmt::Display) -> Self {
        Self {
            ok: false,
            error: Some(e.to_string()),
            status: None,
        }
    }
}
