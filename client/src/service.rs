//! The privileged role: the Windows service, and the command-line verbs that manage it.
//!
//! Same executable as the tray — `main.rs` picks the role from argv. The service is registered
//! with an explicit `service` argument rather than none, because "no arguments" now means the
//! user double-clicked the program and wants the UI.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dns_ai_core::netif::Family;
use tokio::sync::{watch, Mutex};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::app::{self, App};
use crate::pipe;

const SERVICE_NAME: &str = "DnsAiClient";
const DISPLAY_NAME: &str = "DNS-AI — защищённый DNS";
const DESCRIPTION: &str = "Локальный шифрующий DNS-резолвер DNS-AI: принимает запросы на 127.0.0.1 и передаёт их на dns.dns-ai.ru по DoH. Управляет настройками DNS сетевых адаптеров и восстанавливает их при остановке.";

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Hands this process to the Service Control Manager. Reached only through the `service`
/// argument, which is what [`cmd_install`] writes into the service's binary path.
pub fn dispatch() -> Result<()> {
    // Anything printed from here goes nowhere: a service has no console. Every diagnostic from
    // this point on is in the log file.
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main).context(
        "этот режим запускает диспетчер служб; для интерактивного запуска есть `dns-ai run-console`",
    )?;
    Ok(())
}

pub enum Control {
    Start,
    Stop,
    /// Stop and start again. Exists because the window offers it as a button: a service that is
    /// registered and running but not answering its pipe is the one state where "turn it off and
    /// on again" is the correct advice, and making the user assemble it from two clicks would
    /// leave a window in which the machine has neither.
    Restart,
}

/// Whether the service exists on this machine, as the *unelevated* window is able to see it.
///
/// Opening the manager with `CONNECT` and the service with `QUERY_STATUS` is what a standard user
/// is granted by the default security descriptor, so this answer costs no UAC prompt — which is
/// the whole point: the window has to know which button to draw before it asks for anything.
pub enum Installed {
    No,
    Stopped,
    Running,
    /// Registered, and in one of the transitional states. Carries the word to show.
    Other(&'static str),
    /// The question itself could not be asked.
    Unknown(String),
}

/// `ERROR_SERVICE_DOES_NOT_EXIST`. Distinguished from every other failure on purpose: "not
/// installed yet" is the ordinary first-run state and must offer an install button, while anything
/// else is a fault and has to say so rather than inviting a second install.
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

pub fn query_installed() -> Installed {
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    {
        Ok(m) => m,
        Err(e) => return Installed::Unknown(format!("{e}")),
    };
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(s) => s,
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) =>
        {
            return Installed::No
        }
        Err(e) => return Installed::Unknown(format!("{e}")),
    };
    match service.query_status() {
        Ok(s) => match s.current_state {
            ServiceState::Stopped => Installed::Stopped,
            ServiceState::Running => Installed::Running,
            ServiceState::StartPending => Installed::Other("запускается"),
            ServiceState::StopPending => Installed::Other("останавливается"),
            _ => Installed::Other("переходное состояние"),
        },
        Err(e) => Installed::Unknown(format!("{e}")),
    }
}

/// How the SCM is configured to start us: `true` for "with Windows", `false` for on demand.
///
/// Read from the registration, never from the settings file. The two are allowed to disagree —
/// `services.msc` can change one without the other — and the switch in the window has to show the
/// machine rather than the wish. `QueryServiceConfig` is readable by an ordinary interactive user,
/// so this costs no elevation; a machine where it cannot be read at all is reported as "on demand",
/// which is the answer that offers to fix something rather than the one that hides the question.
pub fn start_type_is_auto() -> bool {
    let read = || -> Option<bool> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG)
            .ok()?;
        let config = service.query_config().ok()?;
        // The two driver-only types are here for completeness rather than because we could ever be
        // one: anything that is not "on demand" or "disabled" starts without being asked.
        Some(matches!(
            config.start_type,
            ServiceStartType::AutoStart
                | ServiceStartType::SystemStart
                | ServiceStartType::BootStart
        ))
    };
    read().unwrap_or(false)
}

/// Changes only the start type of the registration, leaving everything else exactly as it is.
///
/// `ChangeServiceConfigW` with `SERVICE_NO_CHANGE` everywhere else, rather than
/// `windows-service`'s `change_config`, which takes a whole `ServiceInfo` and would have us
/// reconstruct the binary path and its arguments from what `QueryServiceConfig` hands back — a
/// single command-line string. Rebuilding a registration in order to flip one DWORD is how a
/// service ends up pointing somewhere subtly wrong.
///
/// Called by the **service**, from the pipe handler, so flipping the switch costs no UAC prompt:
/// LocalSystem's token carries `BUILTIN\Administrators`, which is the entry in a service's default
/// security descriptor that grants `SERVICE_CHANGE_CONFIG`.
pub fn set_start_type(auto: bool) -> Result<()> {
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfigW, CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
        SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG, SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
    };

    let name: Vec<u16> = SERVICE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("не удалось открыть менеджер служб");
        }
        let service = OpenServiceW(manager, name.as_ptr(), SERVICE_CHANGE_CONFIG);
        if service.is_null() {
            let e = std::io::Error::last_os_error();
            CloseServiceHandle(manager);
            return Err(e).context("не удалось открыть службу для изменения настроек запуска");
        }
        let start_type = if auto {
            SERVICE_AUTO_START
        } else {
            SERVICE_DEMAND_START
        };
        let ok = ChangeServiceConfigW(
            service,
            SERVICE_NO_CHANGE,
            start_type,
            SERVICE_NO_CHANGE,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        let err = std::io::Error::last_os_error();
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        if ok == 0 {
            return Err(err).context("не удалось изменить тип запуска службы");
        }
    }
    log::info!(
        "service start type set to {}",
        if auto { "auto" } else { "demand" }
    );
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    dns_ai_core::logging::init(&dns_ai_core::paths::service_log(), false);
    if let Err(e) = run_as_service() {
        log::error!("service exited with an error: {e:#}");
    }
}

fn run_as_service() -> Result<()> {
    let (stop_tx, stop_rx) = watch::channel(false);
    let handler_tx = stop_tx.clone();

    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            // Shutdown matters as much as Stop: without it a reboot leaves the adapters
            // pointing at a stub that is no longer running.
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = handler_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("could not register the service control handler")?;

    let running = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(running)?;
    log::info!(
        "service {SERVICE_NAME} v{} running",
        env!("CARGO_PKG_VERSION")
    );

    let result = tokio_main(stop_rx);

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(if result.is_ok() { 0 } else { 1 }),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    result
}

pub fn run_console() -> Result<()> {
    dns_ai_core::logging::init(&dns_ai_core::paths::service_log(), true);
    println!(
        "DNS-AI service v{} — режим консоли",
        env!("CARGO_PKG_VERSION")
    );
    println!("Ctrl+C — остановить и вернуть настройки DNS.");

    let (stop_tx, stop_rx) = watch::channel(false);
    std::thread::spawn(move || {
        // A blocking Ctrl-C wait on its own thread keeps the async side free of a signal
        // handler that would also have to exist under the SCM, where it is meaningless.
        let _ = ctrl_c_blocking();
        let _ = stop_tx.send(true);
    });
    tokio_main(stop_rx)
}

fn ctrl_c_blocking() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async { tokio::signal::ctrl_c().await })?;
    Ok(())
}

fn tokio_main(stop_rx: watch::Receiver<bool>) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start the async runtime")?;
    rt.block_on(async_main(stop_rx))
}

async fn async_main(mut stop_rx: watch::Receiver<bool>) -> Result<()> {
    let app = Arc::new(Mutex::new(App::new()));
    app.lock().await.restore_on_start().await;

    let (pipe_stop_tx, pipe_stop_rx) = watch::channel(false);
    let pipe_task = tokio::spawn(pipe::serve(app.clone(), pipe_stop_rx));

    let _ = stop_rx.changed().await;
    log::info!("stop requested");

    let _ = pipe_stop_tx.send(true);
    // Restore before the process goes away. This is the whole reason stop is handled at all:
    // a machine whose adapters point at a stub that is not running has no DNS.
    app.lock().await.on_stop();
    pipe_task.abort();

    log::info!("service stopped cleanly");
    Ok(())
}

/// Registers the service at this executable's own location and starts it.
///
/// Kept as the plain `install` verb for a runbook or a support request. The product path goes
/// through [`crate::setup::install_program`], which puts the file somewhere permanent first — this
/// one registers whatever path it is run from, which is exactly the trap that made the installer
/// necessary.
pub fn install() -> Result<Vec<String>> {
    let exe = std::env::current_exe().context("cannot determine our own path")?;
    install_at(&exe)
}

/// Registers the service against `exe`, or re-points an existing registration at it, and starts it.
///
/// Idempotent on purpose, and that is a behaviour change: this used to be `create_service` alone
/// and failed with «возможно, она уже установлена» on a second run. A registration that names a
/// file which is no longer there is a real state — it is what a moved or re-downloaded executable
/// leaves behind — and the only way out of it is to rewrite the path, so an install that repairs
/// is worth more than one that refuses.
///
/// Returns what it did, line by line, rather than printing: the same function has to serve the
/// command line and the window, and the window has no console to read.
pub fn install_at(exe: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("не удалось открыть менеджер служб — нужны права администратора")?;

    // The user's own answer to «Автозапуск службы в фоне», so a re-install does not silently put
    // back the start type they turned off. Defaults to automatic on a machine with no settings
    // file yet, which is the first install.
    let start_type = if dns_ai_core::config::Settings::load().service_autostart {
        ServiceStartType::AutoStart
    } else {
        ServiceStartType::OnDemand
    };

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        // "service", not nothing: bare invocation is now the tray UI.
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        // LocalSystem: the account has to be able to rewrite adapter configuration.
        account_name: None,
        account_password: None,
    };

    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(existing) => {
            existing
                .change_config(&info)
                .context("не удалось обновить регистрацию службы")?;
            out.push("Регистрация службы обновлена.".into());
            existing
        }
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) =>
        {
            let created = manager
                .create_service(&info, access)
                .context("не удалось создать службу")?;
            out.push(format!("Служба «{DISPLAY_NAME}» установлена."));
            created
        }
        Err(e) => return Err(e).context("не удалось открыть службу"),
    };

    service.set_description(DESCRIPTION)?;

    // If it dies, bring it back: a stopped service with adapters pointed at 127.0.0.1 is a
    // machine with no DNS, and the user cannot be expected to diagnose that.
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(600)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(5),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(15),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(60),
                },
            ]),
        })
        .unwrap_or_else(|e| out.push(format!("предупреждение: не заданы действия при сбое: {e}")));

    // Starting an already-running service is an error from the SCM, and on the repair path it is
    // the ordinary case: a re-registration that only changed the path leaves it running.
    match service.query_status()?.current_state {
        ServiceState::Running => out.push("Служба уже работает.".into()),
        ServiceState::StartPending => out.push("Служба запускается.".into()),
        _ => {
            service.start::<&OsStr>(&[])?;
            out.push("Служба запущена.".into());
        }
    }
    out.push(format!("Файл: {}", exe.display()));
    out.push(format!(
        "Журнал: {}",
        dns_ai_core::paths::service_log().display()
    ));
    Ok(out)
}

/// Stops the service so its executable can be replaced, and says so if it had to.
///
/// Best effort throughout: none of these failures is a reason to refuse to install. A service that
/// will not stop is very often exactly the reason somebody is re-installing, and the copy that
/// follows has its own error to report if the file really is locked.
///
/// This also restores the machine's DNS on the way down (`App::on_stop`), which is why the upgrade
/// path is safe to run while protection is on: there is no moment where the adapters point at a
/// stub whose process is being overwritten.
pub fn stop_for_upgrade() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return out;
    };
    let Ok(service) = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
    ) else {
        return out;
    };
    match service.query_status() {
        Ok(s) if s.current_state == ServiceState::Stopped => return out,
        Ok(_) => {}
        Err(_) => return out,
    }

    out.push("Останавливаю прежнюю службу (настройки DNS возвращаются)...".into());
    if let Err(e) = service.stop() {
        out.push(format!("предупреждение: не удалось остановить службу: {e}"));
        return out;
    }
    if let Err(e) = wait_for_stop(&service) {
        out.push(format!("предупреждение: {e}"));
    }
    out
}

/// The executable the service is registered against, if any — regardless of whether it still
/// exists, which is the whole point of asking.
///
/// `QueryServiceConfig` is readable by an ordinary interactive user under the default service
/// security descriptor, so the window can call this without elevation. "Should be" is not "is" on
/// a machine with a hardened SD, hence the registry fallback: `ImagePath` under the service's own
/// key is readable by Users on every default install.
pub fn registered_exe() -> Option<PathBuf> {
    let from_scm = || -> Option<OsString> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG)
            .ok()?;
        Some(
            service
                .query_config()
                .ok()?
                .executable_path
                .into_os_string(),
        )
    };
    let from_registry = || -> Option<OsString> {
        winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
            .open_subkey(format!(r"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"))
            .ok()?
            .get_value::<String, _>("ImagePath")
            .ok()
            .map(OsString::from)
    };
    from_scm()
        .or_else(from_registry)
        .map(|cmd| exe_from_launch_command(&cmd))
}

/// The executable out of a service's launch command.
///
/// What the SCM stores and hands back is the whole command line — `"C:\...\dns-ai.exe" service` —
/// not a path, so treating it as one produces a file name that never exists and a "the program is
/// missing" verdict on a perfectly healthy machine.
fn exe_from_launch_command(cmd: &OsStr) -> PathBuf {
    let text = cmd.to_string_lossy();
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('"') {
        return PathBuf::from(rest.split('"').next().unwrap_or(rest));
    }
    // Unquoted, which the SCM allows when the path has no spaces. Anything after the first space
    // is an argument.
    PathBuf::from(text.split(' ').next().unwrap_or(text))
}

/// Stops the service, removes it, and makes sure the machine's DNS is back where it was.
pub fn uninstall() -> Result<Vec<String>> {
    let mut out = Vec::new();
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("не удалось открыть менеджер служб — нужны права администратора")?;

    match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(service) => {
            // Every failure here is reported and stepped over rather than returned. The backup
            // restore below is the part that matters to the machine, and it used to be skipped by
            // a `?` on a service that would not come to rest — precisely the case where the
            // adapters are still pointing at a stub that is about to be deleted.
            let running = match service.query_status() {
                Ok(s) => s.current_state != ServiceState::Stopped,
                Err(e) => {
                    out.push(format!("Не удалось узнать состояние службы: {e}"));
                    true
                }
            };
            if running {
                out.push("Останавливаю службу (настройки DNS возвращаются)...".into());
                match service.stop() {
                    Ok(_) => {
                        if let Err(e) = wait_for_stop(&service) {
                            out.push(format!("Предупреждение: {e}"));
                        }
                    }
                    Err(e) => {
                        out.push(format!("Предупреждение: не удалось остановить службу: {e}"))
                    }
                }
            }
            match service.delete() {
                Ok(()) => out.push("Служба удалена.".into()),
                Err(e) => out.push(format!("Предупреждение: не удалось удалить службу: {e}")),
            }
        }
        Err(e) => out.push(format!("Служба не зарегистрирована ({e}); продолжаю.")),
    }

    // Belt and braces. If the service never got to restore — it was killed, or it was already
    // broken when the uninstall started — the backup is still on disk and the adapters are
    // still pointing at a stub that is now gone.
    if dns_ai_core::backup::DnsBackup::exists() {
        out.push("Найдена резервная копия настроек DNS — восстанавливаю.".into());
        match app::restore_from_backup() {
            Ok(warnings) if warnings.is_empty() => {
                dns_ai_core::netif::flush_dns_cache();
                dns_ai_core::backup::DnsBackup::delete();
                out.push("Настройки DNS восстановлены.".into());
            }
            Ok(warnings) => {
                dns_ai_core::netif::flush_dns_cache();
                out.push("ВОССТАНОВЛЕНО НЕ ВСЁ. Резервная копия сохранена:".into());
                for w in warnings {
                    out.push(format!("  - {w}"));
                }
                out.push(format!(
                    "  файл: {}",
                    dns_ai_core::paths::backup_file().display()
                ));
            }
            Err(e) => {
                out.push(format!("Не удалось восстановить настройки: {e:#}"));
                out.push("Аварийный сброс всех адаптеров на автоматический DNS:".into());
                out.push("  Get-NetAdapter | Where-Object Status -eq Up | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }".into());
            }
        }
    }
    Ok(out)
}

pub fn control(what: Control) -> Result<Vec<String>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("не удалось открыть менеджер служб — нужны права администратора")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::START | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        )
        .context("служба не зарегистрирована")?;

    let mut out = Vec::new();
    let stop = |out: &mut Vec<String>| -> Result<()> {
        // Stopping an already-stopped service is an error from the SCM, and on the restart path it
        // is the ordinary case rather than a fault: the reason to restart is usually that the
        // thing is not running properly in the first place.
        if service.query_status()?.current_state == ServiceState::Stopped {
            out.push("Служба уже остановлена.".into());
            return Ok(());
        }
        service.stop()?;
        wait_for_stop(&service)?;
        out.push("Служба остановлена.".into());
        Ok(())
    };

    match what {
        Control::Start => {
            service.start::<&std::ffi::OsStr>(&[])?;
            out.push("Служба запущена.".into());
        }
        Control::Stop => stop(&mut out)?,
        Control::Restart => {
            stop(&mut out)?;
            service.start::<&std::ffi::OsStr>(&[])?;
            out.push("Служба запущена заново.".into());
        }
    }
    Ok(out)
}

fn wait_for_stop(service: &windows_service::service::Service) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    anyhow::bail!("служба не остановилась за 30 секунд")
}

/// Read-only. What the client *would* do, and what the machine looks like now.
///
/// The point is to be usable on a machine nobody has installed anything on: it opens no socket,
/// writes no file and changes no setting. That is what makes it safe as the first thing a user
/// touches, and it is why the window offers it as a button before the service exists.
pub fn probe_report() -> Result<Vec<String>> {
    let settings = dns_ai_core::config::Settings::load();
    let mut out = vec![
        format!(
            "Настройки: IPv6={}, VPN-адаптеры={}",
            settings.ipv6, settings.include_vpn_adapters
        ),
        format!(
            "Резолвер: {} -> {:?}",
            dns_ai_core::config::DOH_URL,
            dns_ai_core::config::RESOLVER_IPS
        ),
        String::new(),
    ];

    let selection = dns_ai_core::netif::select_adapters(settings.include_vpn_adapters)?;

    out.push(format!("Будут настроены ({}):", selection.chosen.len()));
    for a in &selection.chosen {
        out.push(format!("  [{}] {}", a.index, a.alias));
        out.push(format!("      {}", a.description));
        out.push(format!(
            "      IPv4: {}",
            describe_state(&dns_ai_core::netif::read_dns_state(&a.guid, Family::V4))
        ));
        out.push(format!(
            "      IPv6: {}",
            describe_state(&dns_ai_core::netif::read_dns_state(&a.guid, Family::V6))
        ));
    }
    if selection.chosen.is_empty() {
        out.push("  (ни одного — включать защиту сейчас нельзя)".into());
    }

    out.push(String::new());
    out.push(format!("Пропущены ({}):", selection.skipped.len()));
    for s in &selection.skipped {
        out.push(format!("  {} — {}", s.alias, s.reason));
    }

    out.push(String::new());
    out.push(format!(
        "Резервная копия: {}",
        if dns_ai_core::backup::DnsBackup::exists() {
            "есть"
        } else {
            "нет"
        }
    ));
    Ok(out)
}

fn describe_state(state: &dns_ai_core::netif::DnsState) -> String {
    match state {
        dns_ai_core::netif::DnsState::Dhcp => "автоматически (DHCP)".into(),
        dns_ai_core::netif::DnsState::Static(l) if l.is_empty() => "вручную, пусто".into(),
        dns_ai_core::netif::DnsState::Static(l) => format!("вручную: {}", l.join(", ")),
    }
}

/// Read-only. One DoH query to the resolver, over the same code path the stub uses.
///
/// Run this BEFORE enabling anything. It separates the three failures that otherwise look
/// identical from inside the client: the node is unreachable, the certificate does not validate,
/// or this source address is outside the RU/BY scope (which comes back as REFUSED, not silence).
/// Returns the report and whether the check passed. A node that answers REFUSED, or does not
/// answer at all, is a **successful diagnostic** — the check ran and produced its verdict — so the
/// failure is in the boolean and never in the `Err`, which is reserved for not being able to ask
/// the question at all. The old shape called `process::exit(1)` here, which was defensible in a
/// command and would take the whole window down with it now that a button runs this.
pub fn doh_report(name: &str, qtype_text: &str) -> Result<(Vec<String>, bool)> {
    let qtype = dns_ai_core::dnsmsg::qtype_from_str(qtype_text)
        .with_context(|| format!("неизвестный тип записи «{qtype_text}» (A, AAAA, CNAME, TXT)"))?;

    // Not cryptographic — this is a diagnostic, and the ID only has to differ between runs.
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
        & 0xFFFF) as u16;

    let query = dns_ai_core::dnsmsg::build_query(name, qtype, id)?;
    let mut out = vec![
        format!(
            "Запрос: {name} {qtype_text} -> {}",
            dns_ai_core::config::DOH_URL
        ),
        format!("Адреса узлов: {:?}", dns_ai_core::config::RESOLVER_IPS),
        String::new(),
    ];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let started = Instant::now();
    let answer = match rt.block_on(dns_ai_core::stub::query_once(&query)) {
        Ok(a) => a,
        Err(e) => {
            out.push(format!("НЕ УДАЛОСЬ: {e:#}"));
            out.push(String::new());
            // The out-of-region case is FIRST because it is the only one that
            // looks like a broken node and is not one. A source outside RU/BY is
            // dropped in the kernel before anything answers, so it costs no
            // handshake and produces silence — a REFUSED would at least name
            // itself. On 2026-09-01 this exact timeout was read as an outage,
            // and it was an outage; but the reverse mistake is just as easy and
            // this text is the only place a user can learn the difference.
            out.push("Что это обычно значит:".into());
            out.push(
                "  - запрос ушёл НЕ из России/Беларуси -> узел молча отбрасывает пакет. Выключите"
                    .into(),
            );
            out.push(
                "    VPN на этой машине (или на хосте, если это виртуалка) и повторите".into(),
            );
            out.push(
                "  - таймаут или отказ соединения -> узел недоступен, или 443/tcp закрыт в этой сети"
                    .into(),
            );
            out.push(
                "  - ошибка проверки сертификата  -> перехват TLS (корпоративный прокси, антивирус)"
                    .into(),
            );
            return Ok((out, false));
        }
    };
    let elapsed = started.elapsed();

    let summary = dns_ai_core::dnsmsg::summarize(&answer)?;
    out.push(format!(
        "Ответ за {} мс: {} ({}), записей: {}",
        elapsed.as_millis(),
        dns_ai_core::dnsmsg::rcode_name(summary.rcode),
        summary.rcode,
        summary.answer_count
    ));
    for a in &summary.answers {
        out.push(format!("  {a}"));
    }

    if summary.rcode == 5 {
        out.push(String::new());
        out.push("REFUSED — узел ответил, но отказал этому источнику.".into());
        out.push("Почти всегда это значит, что запрос вышел не из России или Беларуси:".into());
        out.push("выключите VPN на этой машине (или на хосте, если это виртуалка).".into());
    }
    let ok = summary.rcode == 0;
    Ok((out, ok))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_command_yields_the_executable_not_the_command_line() {
        // What the SCM actually stores for us, spaces and all.
        assert_eq!(
            exe_from_launch_command(OsStr::new(
                r#""C:\Program Files\DNS-AI\dns-ai.exe" service"#
            )),
            PathBuf::from(r"C:\Program Files\DNS-AI\dns-ai.exe")
        );
        // The unquoted form the SCM allows when nothing needs quoting.
        assert_eq!(
            exe_from_launch_command(OsStr::new(r"C:\tools\dns-ai.exe service")),
            PathBuf::from(r"C:\tools\dns-ai.exe")
        );
        // A bare path, which is what a hand-written registration can look like.
        assert_eq!(
            exe_from_launch_command(OsStr::new(r"C:\tools\dns-ai.exe")),
            PathBuf::from(r"C:\tools\dns-ai.exe")
        );
    }
}
