//! DNS-AI for Windows — one executable, three roles.
//!
//! ```text
//!   dns-ai                    the window (this is what a double-click does)
//!   dns-ai --tray             the same, starting hidden — what the Run key passes at logon
//!   dns-ai --enable           the window, elevated, turning protection on — what the program
//!   dns-ai --disable          starts of ITSELF when the portable path needs rights. Which of the
//!                             two it passes is the click the user just made
//!   dns-ai service            the Service Control Manager's entry point — not for humans
//!   dns-ai install            register and start the service at THIS path (administrator)
//!   dns-ai uninstall          stop it, restore DNS, remove it              (administrator)
//!   dns-ai start | stop | restart
//!                             control it without the Services applet
//!   dns-ai setup / remove     copy the program into %ProgramFiles% and undo that. Not part of
//!                             the product any more — the program is portable — and kept only
//!                             because a machine somewhere has already had it run.
//!   dns-ai run-console        run the resolver in the foreground, log to stderr
//!   dns-ai probe              READ-ONLY: adapters, and what their DNS is right now
//!   dns-ai test-doh [имя] [тип]
//!                             READ-ONLY: one DoH query to the resolver, changing nothing
//! ```
//!
//! **The program is portable.** It is one file; it keeps its settings in `config\<этот компьютер>`
//! beside itself, and it works with no service at all — the window holds the resolver open and
//! drives the adapters (`backend.rs`). Installing the service is an option, not a step: what it
//! buys is protection before anybody logs in and no UAC prompt per change.
//!
//! **Nothing above is required to use it.** The diagnostics and the service verbs are here because
//! a runbook and a support request can quote them, not because a user is expected to type one.
//!
//! **Why one binary.** Two files was an implementation detail leaking into the product: users
//! copy one of them, sign one of them, and ask which one to run. The privilege split that
//! actually matters is still there — it is a split between *processes at runtime*, not between
//! files on disk. The service is registered as `<exe> service` and runs as LocalSystem; the tray
//! is the same image started with no arguments as the logged-in user, and it still owns no system
//! state.
//!
//! **Why the `windows` subsystem plus `AttachConsole`.** A single executable has a single
//! subsystem, and the two roles want opposite ones. Choosing `console` would flash a black window
//! at every logon, because the tray autostarts — the most visible possible defect. So the binary
//! is a GUI program that borrows its parent's console when it is run as a command. The wart that
//! buys: `cmd` does not wait for a GUI process, so the shell prompt returns before the output
//! appears.

#![windows_subsystem = "windows"]

mod app;
mod autostart;
/// Who changes system DNS in this run: a registered service, or this process itself.
mod backend;
/// Fonts, the wordmark and the switch — everything the window is drawn out of that is not a screen.
mod brand;
mod com;
mod elevate;
mod icon;
mod ipc_client;
/// The mark's geometry. `build.rs` `include!`s the same file to produce the icon resource, so the
/// half of it that only the resource needs is dead code here.
#[allow(dead_code)]
mod mark;
mod pipe;
mod report;
mod service;
mod setup;
mod shell_link;
mod ui;

use anyhow::Result;

use crate::report::ActionReport;

fn main() -> Result<()> {
    let arg = std::env::args().nth(1).unwrap_or_default();

    // The UI paths must not touch the console at all: attaching one to a process started from
    // Explorer is harmless but pointless, and the window has nowhere to print to anyway.
    //
    // No arguments means somebody double-clicked the file, and they should SEE something — a
    // program that puts an icon in the notification area and nothing else is indistinguishable
    // from one that failed to start. `--tray` is the quiet form, and it is what the Run key
    // passes, so the logon path stays silent (`autostart.rs`).
    // `--enable` and `--disable` are the window again, started by ITSELF with administrator rights
    // because the portable path has no service to do the work (`backend.rs`). They carry no path, no
    // address and no setting — only "do the thing the user just clicked" — and they are exempt from
    // the single-instance guard below, because the copy that asked for it is exiting at this moment
    // and losing that race would leave the user with a UAC prompt and nothing to show for it.
    if arg == "--enable" || arg == "--disable" {
        return ui::run(true, Some(arg == "--enable")).map_err(|e| anyhow::anyhow!("{e}"));
    }
    if arg.is_empty() || arg == "--tray" {
        // One window per session. There are now three ways to start it — a double-click, the
        // Start-menu shortcut and the Run key — and before the shortcut existed nothing ever
        // arrived twice. A second instance would put a second icon in the notification area,
        // polling the same service and disagreeing with the first about what it says.
        // ...but a copy from somewhere else is exempt, and that exemption is the point. On an
        // installed machine the tray starts at logon from `%ProgramFiles%` and holds the claim all
        // day. Without this, downloading a newer build and double-clicking it would raise the OLD
        // window and exit — so the one screen that offers «Обновить установленную до этой» could
        // never be reached, and nothing would say why the new file appeared to do nothing.
        let is_other_copy = matches!(setup::placement(), setup::Placement::Elsewhere { .. });
        if !is_other_copy && !setup::claim_instance() {
            // Only for an explicit launch. `--tray` is the logon path, where the right answer to
            // "somebody is already running" is silence, not a window appearing by itself.
            if arg.is_empty() {
                setup::signal_show();
            }
            return Ok(());
        }
        return ui::run(arg.is_empty(), None).map_err(|e| anyhow::anyhow!("{e}"));
    }
    if arg == "service" {
        return service::dispatch();
    }

    let has_console = console::attach();
    match arg.as_str() {
        "setup" => verb("setup", setup::install_program),
        "remove" => cmd_remove(has_console),
        "install" => verb("install", service::install),
        "uninstall" => verb("uninstall", service::uninstall),
        "start" => verb("start", || service::control(service::Control::Start)),
        "stop" => verb("stop", || service::control(service::Control::Stop)),
        "restart" => verb("restart", || service::control(service::Control::Restart)),
        "run-console" => service::run_console(),
        "probe" => {
            for line in service::probe_report()? {
                println!("{line}");
            }
            Ok(())
        }
        "test-doh" => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            let name = args
                .first()
                .map(String::as_str)
                .unwrap_or("proto.dns-ai.ru");
            let qtype = args.get(1).map(String::as_str).unwrap_or("TXT");
            let (lines, ok) = service::doh_report(name, qtype)?;
            for line in lines {
                println!("{line}");
            }
            if !ok {
                std::process::exit(1);
            }
            Ok(())
        }
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        other => {
            eprintln!("неизвестная команда: {other}");
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}

/// Runs one of the service verbs, prints what it did, and — when the window is the one that asked
/// — leaves the outcome where the window can read it.
///
/// The nonce comes from the command line and is echoed back untouched. It is not a path, not a
/// setting and not a permission: an elevated process must not act on anything an unelevated one
/// chose, and a value that is only ever compared against itself is the narrowest thing that can
/// still answer "is this report about the click I just made?" (`report.rs`).
fn verb(name: &str, run: impl FnOnce() -> Result<Vec<String>>) -> Result<()> {
    let nonce = report_nonce();
    let outcome = run();

    match &outcome {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
        }
        Err(e) => eprintln!("{e:#}"),
    }
    if let Some(nonce) = nonce {
        ActionReport::from_outcome(name, &nonce, &outcome).save();
    }
    outcome.map(|_| ())
}

/// `remove`, which is different from every other verb in two ways.
///
/// It is the `UninstallString` in Windows' own list of programs, and "Apps & features" runs that
/// with the caller's ordinary token — this binary has no elevation manifest, deliberately, because
/// the window must be able to start from the Run key without a prompt at every logon. So the verb
/// asks for administrator rights itself when it does not have them, rather than failing on its
/// first call into the service manager with an error nobody can act on.
///
/// And it is the only verb that removes the folder the report is written to, so the last step
/// happens *after* the report exists: the window is still waiting to read it.
fn cmd_remove(has_console: bool) -> Result<()> {
    let quiet = std::env::args().any(|a| a == "--quiet");

    if !setup::is_elevated() {
        // Pass nothing on. The child decides everything for itself, including where to leave its
        // report; that is the rule the whole elevation boundary rests on (`elevate.rs`).
        let args: &[&str] = if quiet {
            &["remove", "--quiet"]
        } else {
            &["remove"]
        };
        return match elevate::run_self(args)? {
            elevate::Outcome::Declined => {
                eprintln!("Отменено: без прав администратора удалить программу нельзя.");
                std::process::exit(1);
            }
            elevate::Outcome::Exited(0) => {
                // This unelevated half is the only part of the uninstall that lives in the right
                // user's registry hive. The elevated child cannot do it — the administrator who
                // approved the prompt may be somebody else entirely — and Windows' own Uninstall
                // button never goes through the window, which is the other place it is done. Left
                // undone, the Run value names a file that is about to be deleted and Windows tries
                // to start it at every logon.
                if let Err(e) = autostart::set(false) {
                    eprintln!("предупреждение: запись автозапуска не удалена: {e:#}");
                }
                Ok(())
            }
            elevate::Outcome::Exited(code) => std::process::exit(code as i32),
        };
    }

    let nonce = report_nonce();
    let outcome = setup::remove_program();
    match &outcome {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
        }
        Err(e) => eprintln!("{e:#}"),
    }
    if let Some(nonce) = &nonce {
        ActionReport::from_outcome("remove", nonce, &outcome).save();
    }

    // Nobody is watching otherwise. "Apps & features" runs this with no console and no window, so
    // without a box the whole uninstall is a UAC prompt followed by silence — which reads as
    // nothing having happened. Skipped when our own window asked (it draws the report), when there
    // is a console to print to, and when Windows used `QuietUninstallString`.
    if nonce.is_none() && !has_console && !quiet {
        let text = match &outcome {
            Ok(lines) => lines.join("\n"),
            Err(e) => format!("Не удалось удалить DNS-AI.\n\n{e:#}"),
        };
        message_box("DNS-AI", &text, outcome.is_ok());
    }
    // Last, and only now: everything above may still have wanted to write to this folder, and the
    // window has not read the report out of it yet.
    //
    // Only on success. A removal that failed halfway leaves a program that is still installed, and
    // taking its settings and its log away at the next boot would turn one problem into two.
    if outcome.is_ok() {
        setup::schedule_data_dir_removal();
    }
    outcome.map(|_| ())
}

/// The only dialog this program draws outside the egui window, and it exists for one caller: the
/// uninstall Windows itself starts, which has neither a console nor a window of ours to report to.
fn message_box(title: &str, text: &str, ok: bool) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MB_SETFOREGROUND,
    };
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let icon = if ok { MB_ICONINFORMATION } else { MB_ICONERROR };
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(text).as_ptr(),
            wide(title).as_ptr(),
            MB_OK | icon | MB_SETFOREGROUND,
        )
    };
}

fn report_nonce() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    let at = args.iter().position(|a| a == "--report")?;
    args.get(at + 1).cloned()
}

const USAGE: &str = "\
DNS-AI — защищённый DNS для Windows

Программа портативная: просто запустите её, настройки лягут в папку config рядом.
Всё нужное есть в окне; команды ниже — для служебных задач.

  dns-ai                     окно и значок в трее
  dns-ai --tray              то же, но свёрнуто (используется при входе в систему)
  dns-ai install             зарегистрировать службу по текущему пути файла
  dns-ai uninstall           остановить, вернуть DNS, удалить службу
  dns-ai start|stop|restart  управление службой
  dns-ai run-console         резолвер в консоли, журнал в stderr
  dns-ai probe               ТОЛЬКО ЧТЕНИЕ: адаптеры и их текущий DNS
  dns-ai test-doh [имя] [тип]  ТОЛЬКО ЧТЕНИЕ: один DoH-запрос к резолверу
  dns-ai setup|remove        установка в Program Files — больше не нужна, оставлена
                             для машин, где она уже выполнялась";

/// Borrowing the parent shell's console, so a GUI-subsystem binary can still be a command-line
/// tool.
mod console {
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Console::{
        AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE,
        STD_OUTPUT_HANDLE,
    };

    /// Attaches to the console of whoever started us, and — the part that is easy to miss —
    /// re-points the standard handles at it.
    ///
    /// `AttachConsole` alone is not enough: a process started from a shell as a GUI program has
    /// no inherited stdout, so `GetStdHandle` keeps returning null and every `println!` is
    /// silently discarded. Opening `CONOUT$` and installing it explicitly is what makes the
    /// output appear. Failure is not an error — it only means nobody is watching (started from
    /// Explorer, or by Windows' own uninstall entry), and the command must still run. The return
    /// value says which of the two it was, because a verb with nobody watching may want to say
    /// what it did some other way.
    pub fn attach() -> bool {
        unsafe {
            if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
                return false;
            }
            // Only where there is nothing already. A shell redirect (`dns-ai probe > out.txt`)
            // hands us a perfectly good handle, and overwriting it with the console would send
            // the output to the screen instead of the file the user asked for.
            for std_handle in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
                let existing = GetStdHandle(std_handle);
                if !existing.is_null() && existing != INVALID_HANDLE_VALUE {
                    continue;
                }
                let name: Vec<u16> = "CONOUT$\0".encode_utf16().collect();
                let handle = CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                );
                if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
                    SetStdHandle(std_handle, handle);
                }
            }
            true
        }
    }
}
