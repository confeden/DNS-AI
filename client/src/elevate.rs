//! One UAC prompt, one verb, one child process.
//!
//! The window stays unelevated, and that is not an oversight to be tidied up later: it is what
//! lets it start from the per-user `Run` key with no prompt at every logon, and it is the reason
//! the service exists at all (`core/src/ipc.rs`). Registering and removing a Windows service is
//! the one job the window has that a standard user cannot do — so rather than running the whole
//! UI as administrator, the program re-launches **itself** with the one verb it needs, under
//! `runas`, and waits for that process to finish.
//!
//! Nothing but a fixed verb crosses the boundary. The elevated child is handed no path, no
//! address and no setting; where it must report back, it writes to a path it decides for itself
//! (`paths::last_action_file`). An administrator process acting on arguments an unelevated one
//! chose is the classic local privilege-escalation shape, and the whole point of this module is
//! to open that door as narrowly as it will go.

use std::os::windows::ffi::OsStrExt;

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};

/// `WaitForSingleObject` returning "the handle you asked about is signalled".
const WAIT_OBJECT_0: u32 = 0;

/// How long to wait for the elevated child before giving up on it.
///
/// `uninstall` is the slow verb: it stops the service, which is allowed thirty seconds to come to
/// rest, and only then restores every adapter. Three minutes is far past anything observed and
/// still finite — an `INFINITE` wait would park the worker thread for the life of the process if
/// the child ever deadlocked, and from the window there would be nothing to see but a button that
/// never comes back.
const WAIT_MS: u32 = 180_000;

/// What became of the elevated run.
pub enum Outcome {
    /// The child ran to completion. Zero means it did the job.
    Exited(u32),
    /// The user answered "No" to the UAC prompt.
    ///
    /// A decision, not a failure, and it has to stay distinguishable from one: told "не удалось",
    /// the next thing somebody does is go looking for a bug that is not there.
    Declined,
}

/// Runs this same executable, elevated, with `args`, and waits for it.
///
/// COM is initialised per thread, and this runs on the worker thread — not the one eframe already
/// set up. `ShellExecuteEx` delegates to shell extensions, and for `runas` to the Application
/// Information service, both over COM; the documented requirement is that the calling thread has
/// initialised it (`com.rs`).
pub fn run_self(args: &[&str]) -> Result<Outcome> {
    crate::com::ensure();

    // Every caller passes fixed verbs and a hex nonce. Nothing here quotes anything, so a value
    // with a space in it would silently arrive as two arguments — cheap to assert, expensive to
    // debug.
    debug_assert!(
        args.iter().all(|a| !a.contains(' ')),
        "elevate::run_self does no quoting; arguments must not contain spaces"
    );

    let exe = std::env::current_exe().context("не удалось определить путь к собственному файлу")?;
    let file = wide(exe.as_os_str());
    let verb = wide("runas".as_ref());
    let params = wide(args.join(" ").as_ref());

    // Zeroed rather than field-by-field: the struct carries a union, and a partial initialisation
    // would leave the rest as whatever was on the stack.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    // NOCLOSEPROCESS is what makes `hProcess` usable afterwards — without it there is nothing to
    // wait on and no exit code to read. NOASYNC keeps ShellExecuteEx from returning before the
    // launch has actually been carried out.
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    // The child is a GUI-subsystem binary running a command-line verb: it draws nothing and has no
    // console to show. A visible window here would be an empty flash on screen.
    info.nShow = SW_HIDE;

    let launched = unsafe { ShellExecuteExW(&mut info) };
    if launched == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_CANCELLED {
            return Ok(Outcome::Declined);
        }
        bail!("не удалось запустить с правами администратора (код {code})");
    }
    if info.hProcess.is_null() {
        // Documented as possible when the request is satisfied without a new process. None of our
        // verbs can be, so treat it as "ran, told us nothing" rather than inventing a success.
        bail!("Windows не вернула дескриптор запущенного процесса");
    }

    let handle = info.hProcess;
    let waited = unsafe { WaitForSingleObject(handle, WAIT_MS) };
    let outcome = if waited == WAIT_OBJECT_0 {
        let mut code: u32 = 0;
        if unsafe { GetExitCodeProcess(handle, &mut code) } == 0 {
            Err(anyhow::anyhow!("не удалось прочитать код завершения"))
        } else {
            Ok(Outcome::Exited(code))
        }
    } else {
        Err(anyhow::anyhow!(
            "операция не завершилась за {} с",
            WAIT_MS / 1000
        ))
    };
    unsafe { CloseHandle(handle) };
    outcome
}

/// Starts this executable elevated and does **not** wait for it.
///
/// One caller: the portable path, where the program has to become an administrator of itself
/// because there is no service to do the work. A process cannot gain rights, so the only way up is
/// a new one — this launches it and the caller exits, handing over the tray icon and the window.
///
/// Visible, unlike [`run_self`]: the child here is the user interface, not a verb.
pub fn run_self_detached(args: &[&str]) -> Result<Outcome> {
    crate::com::ensure();
    debug_assert!(
        args.iter().all(|a| !a.contains(' ')),
        "elevate::run_self_detached does no quoting; arguments must not contain spaces"
    );

    let exe = std::env::current_exe().context("не удалось определить путь к собственному файлу")?;
    let file = wide(exe.as_os_str());
    let verb = wide("runas".as_ref());
    let params = wide(args.join(" ").as_ref());

    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_SHOWNORMAL;

    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_CANCELLED {
            return Ok(Outcome::Declined);
        }
        bail!("не удалось запустить с правами администратора (код {code})");
    }
    Ok(Outcome::Exited(0))
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}
