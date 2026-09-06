//! Start the tray at logon, via the per-user Run key.
//!
//! `HKEY_CURRENT_USER` on purpose: it needs no elevation, so the checkbox works for the user who
//! ticked it without a UAC prompt. The service starts itself — it is registered as AutoStart and
//! does not depend on anyone logging in.
//!
//! **The value names the *installed* copy, not the running one.** Almost every first run is a
//! double-click on a file in Downloads, and a Run key pointing there survives exactly until the
//! user tidies up — after which Windows tries to start a program that is not there, at every
//! logon, silently.

use std::path::PathBuf;

use anyhow::{Context, Result};
use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "DNS-AI";

/// The file the Run key should name: the installed copy if there is one, otherwise whatever is
/// running — which is the best that can be done before the program has been installed.
fn target_exe() -> Result<PathBuf> {
    let installed = crate::setup::install_exe();
    if installed.is_file() {
        return Ok(installed);
    }
    std::env::current_exe().context("cannot determine our own path")
}

/// What the Run key should contain.
///
/// Quoted: a path containing a space is otherwise parsed as a command plus arguments.
///
/// `--tray` is what keeps the logon quiet. Bare invocation opens the window, because a
/// double-click that appears to do nothing is the worst first impression this program can make —
/// but the same behaviour at every logon would be the second worst.
fn value() -> Result<String> {
    Ok(format!("\"{}\" --tray", target_exe()?.display()))
}

pub fn get() -> Option<String> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(RUN_KEY)
        .ok()?
        .get_value::<String, _>(VALUE_NAME)
        .ok()
}

pub fn set(enabled: bool) -> Result<()> {
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(RUN_KEY)
        .context("cannot open the Run key")?;

    if enabled {
        key.set_value(VALUE_NAME, &value()?)
            .context("cannot write the Run value")?;
    } else if let Err(e) = key.delete_value(VALUE_NAME) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e).context("cannot remove the Run value");
        }
    }
    Ok(())
}

/// Makes the registry agree with the setting, and does nothing when it already does.
///
/// This exists because the switch used to be the only writer: `autostart_tray` defaults to **on**,
/// so a freshly installed machine showed the switch on while no Run value existed anywhere, and
/// the tray did not come back after a reboot. The setting was not describing the machine — it was
/// describing the last time somebody had flipped it, which on most machines is never.
///
/// It also repairs the path, which is the other half of the same problem: a value written while
/// the program was still in Downloads has to be re-pointed at `%ProgramFiles%` once it is
/// installed.
pub fn reconcile(enabled: bool) -> Result<()> {
    let current = get();
    if enabled {
        let want = value()?;
        if current.as_deref() == Some(want.as_str()) {
            return Ok(());
        }
    } else if current.is_none() {
        return Ok(());
    }
    set(enabled)
}
