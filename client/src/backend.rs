//! Who actually changes this machine's DNS — and it is no longer always a service.
//!
//! The program is one portable executable. A user downloads it, runs it, and it works; installing
//! the LocalSystem service is an option for a machine that should be protected before anybody logs
//! in, not a step on the way to using the program at all. So there are two backends and exactly one
//! of them is live at a time:
//!
//! | | Who owns the stub and the adapters | Needs |
//! |---|---|---|
//! | [`Backend::Service`] | the service, over the named pipe | the service to be registered |
//! | [`Backend::Local`] | **this process** | administrator rights to move adapters |
//!
//! **Which one is chosen is decided by the machine, not by a setting**: if a service is registered
//! it owns everything, because two writers of the same system state is how a machine ends up in a
//! shape nobody can explain. The local backend exists only where there is no service.
//!
//! **The privilege split is the interesting part.** Binding `127.0.0.1:53` needs no rights at all,
//! and rewriting an adapter's DNS needs administrator. So a local backend that is not elevated is
//! not useless: it can start the resolver and keep a machine that was already pointed at loopback
//! resolving — which is exactly what happens after a reboot, since adapter settings are persistent.
//! What it cannot do is turn protection on or off, and for that the window restarts itself elevated
//! (`ui.rs`).

use std::sync::Arc;

use anyhow::{Context, Result};
use dns_ai_core::ipc::{Request, Response};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

use crate::app::App;
use crate::ipc_client;
use crate::pipe;
use crate::service;

pub enum Backend {
    /// A registered service answers for the machine. This process only asks.
    Service,
    /// There is no service; this process is the whole program.
    Local(Local),
}

pub struct Local {
    /// `Option` for one reason: shutting the runtime down and DROPPING it are not the same thing.
    /// `Runtime::drop` waits for the blocking pool **with no timeout at all**
    /// (`BlockingPool::drop -> shutdown(None)`), so one wedged blocking task on the way out is a
    /// process that never exits. Taking it out lets [`Backend::shutdown`] end it on its own terms.
    rt: Option<Runtime>,
    app: Arc<Mutex<App>>,
}

impl Backend {
    /// Looks at the machine and picks. Called at start-up and again after anything that could have
    /// registered or removed the service.
    pub fn choose() -> Self {
        match service::query_installed() {
            service::Installed::No => match Local::start() {
                Ok(local) => {
                    log::info!("no service registered — running the resolver in this process");
                    Backend::Local(local)
                }
                Err(e) => {
                    // Nothing else can be done here, and the window will show the service screen,
                    // which is the honest thing to offer when the local path is unavailable.
                    log::error!("could not start the local backend: {e:#}");
                    Backend::Service
                }
            },
            _ => Backend::Service,
        }
    }

    pub fn is_local(&self) -> bool {
        matches!(self, Backend::Local(_))
    }

    /// One request, one answer, whichever half is live.
    ///
    /// The local path goes through the same [`pipe::dispatch`] the service uses, so there is one
    /// implementation of what a request means rather than two that can drift.
    pub fn ask(&self, req: &Request) -> Result<Response> {
        match self {
            Backend::Service => ipc_client::request(req),
            // `None` only between [`Self::shutdown`] and the process ending, or between it and a
            // `Backend::choose()` that replaces this value — the window is going away in both
            // cases. An error beats a panic on a path nobody is watching.
            Backend::Local(local) => match local.rt.as_ref() {
                Some(rt) => Ok(rt.block_on(pipe::dispatch(req.clone(), &local.app))),
                None => Err(anyhow::anyhow!("локальный резолвер уже остановлен")),
            },
        }
    }

    /// Lets go of the resolver before this process goes away — and of nothing else.
    ///
    /// Only the local backend has anything to do here: it is the one holding the stub open. A
    /// service keeps running after the window closes, which is the whole reason somebody installs
    /// one.
    ///
    /// **The machine's DNS is left exactly as it is.** Protection is switched off by «Выключить»
    /// and by nothing else — not by closing the window, not by «Выход», not by the handover to an
    /// elevated copy (`app.rs`, [`crate::app::App::release`]).
    /// **Never waits on the runtime's own teardown.** `shutdown_background` returns at once and
    /// leaves the worker threads to finish on their own; the sockets they hold are closed by the
    /// kernel when the process ends, which is moments later. Dropping the runtime here instead
    /// would block the exit for as long as the slowest blocking task takes — unbounded, and on the
    /// one path where a user is watching a window that will not go away.
    pub fn shutdown(&mut self) {
        if let Backend::Local(local) = self {
            if let Some(rt) = local.rt.take() {
                rt.block_on(async {
                    local.app.lock().await.release();
                });
                rt.shutdown_background();
            }
        }
    }
}

impl Local {
    fn start() -> Result<Self> {
        // Two worker threads rather than the service's full multi-thread runtime: this one shares a
        // process with a GUI and serves one machine's own DNS queries.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .context("could not start the async runtime")?;
        let app = Arc::new(Mutex::new(App::new()));
        let elevated = crate::setup::is_elevated();
        rt.block_on(async {
            app.lock().await.resume(elevated).await;
        });
        Ok(Self { rt: Some(rt), app })
    }
}
