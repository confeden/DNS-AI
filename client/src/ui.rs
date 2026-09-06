//! The window — and, when there is no service, the program itself.
//!
//! It used to own no system state at all: every question and every change went to a LocalSystem
//! service over a named pipe. That is still true whenever a service is registered. But the product
//! is a **portable executable** — one file a user runs from wherever they put it — and there the
//! window IS the program: it holds the resolver open and drives the adapters itself (`backend.rs`).
//!
//! What that costs is administrator rights, and only for half the job: binding `127.0.0.1:53` needs
//! none, rewriting an adapter's DNS needs them. So an unelevated portable copy still resolves for a
//! machine that was already enabled — adapter settings survive a reboot — and to *change* anything
//! it restarts itself elevated, once, with `--enable` when that is what the click meant.
//!
//! **The screen is settings and nothing else.** Diagnostics, counters, the install path and the
//! program's own uninstall are not on it; they are `dns-ai probe`, `dns-ai test-doh` and Windows'
//! own list of programs. The one thing that is offered besides settings is the service, because
//! that genuinely changes what the program can do while nobody is logged in.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dns_ai_core::config::{self, Mode};
use dns_ai_core::ipc::{Request, Status};
use eframe::egui;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::autostart;
use crate::backend::Backend;
use crate::brand;
use crate::elevate;
use crate::icon;
use crate::report::{self, ActionReport};
use crate::service;
use crate::setup;

/// How often the window asks how things are.
///
/// Two intervals, because the answer is read by two different things. On screen it backs a switch
/// somebody may be flipping, so it has to be quick; in the notification area it backs an icon and a
/// menu label, which change only when something changed them. Polling a hidden window twice a
/// second is how a tray program ends up costing a laptop its battery for no visible reason.
const POLL_VISIBLE: Duration = Duration::from_secs(2);
const POLL_HIDDEN: Duration = Duration::from_secs(20);

/// How long «скопировано» stays on screen.
const COPIED_FOR: f64 = 1.5;

/// Above and below the signature line. Small on purpose: the footer is a strip, not a section, and
/// the window is 660 px tall with settings to fit into it.
const FOOTER_PAD: i8 = 5;

// The site's palette, verbatim from the `:root` block of `dns-ai/index.html` — the page that is
// live, not the old stylesheet the first version of this window was drawn from. The client and the
// landing page have to read as one product, and the two palettes had drifted apart: the old
// `--primary` was #1e60d4, a fill-only blue too dark to carry white text, and the current design
// replaced it with a lighter accent that the site itself puts white text on.
const BG: egui::Color32 = egui::Color32::from_rgb(0x0d, 0x11, 0x17);
/// `--surface-1`. Cards.
const PANEL: egui::Color32 = egui::Color32::from_rgb(0x16, 0x1b, 0x22);
/// `--surface-2`. The same card with the pointer on it — the site's only hover for a quiet control.
const PANEL_HOVER: egui::Color32 = egui::Color32::from_rgb(0x1c, 0x23, 0x2d);
const PANEL_ACTIVE: egui::Color32 = egui::Color32::from_rgb(0x23, 0x2b, 0x36);
/// `--line-strong` over a card.
const BORDER: egui::Color32 = egui::Color32::from_rgb(0x30, 0x36, 0x3d);
const BORDER_HOVER: egui::Color32 = egui::Color32::from_rgb(0x3d, 0x44, 0x4d);
/// `--line` over the page background: the hairline that separates the footer from the content.
const SEPARATOR: egui::Color32 = egui::Color32::from_rgb(0x1e, 0x22, 0x27);
/// `--fg`. Everything that is prose.
const TEXT: egui::Color32 = egui::Color32::from_rgb(0xe8, 0xec, 0xf3);
/// `--link`. Values, anything that should catch the eye.
const LINK: egui::Color32 = egui::Color32::from_rgb(0x93, 0xb4, 0xff);
const LINK_HOVER: egui::Color32 = egui::Color32::from_rgb(0xb9, 0xcd, 0xff);
/// `--fg-3`. Labels only, never a value someone has to read.
const MUTED: egui::Color32 = egui::Color32::from_rgb(0x7b, 0x84, 0x94);
/// `--accent`, and the two states the site gives it (`filter: brightness(1.08)` on hover, a press
/// that darkens rather than moves).
const PRIMARY: egui::Color32 = egui::Color32::from_rgb(0x5b, 0x8c, 0xff);
const PRIMARY_HOVER: egui::Color32 = egui::Color32::from_rgb(0x76, 0x9f, 0xff);
const PRIMARY_ACTIVE: egui::Color32 = egui::Color32::from_rgb(0x4a, 0x7d, 0xf2);
/// `--ok`.
const OK: egui::Color32 = egui::Color32::from_rgb(0x7e, 0xe2, 0xb8);
const DANGER: egui::Color32 = egui::Color32::from_rgb(0xf8, 0x51, 0x49);

/// Segoe UI Semibold at 14 px, which is what the rest of Windows sets a settings row in.
const FONT_SIZE: f32 = 14.0;

/// What the worker thread can be asked to do. Everything here blocks.
enum Job {
    Ipc(Request),
    /// An elevated verb about the SERVICE. Short-lived: it runs, reports, and exits.
    Elevated {
        verb: &'static str,
        title: &'static str,
    },
    /// Hand the whole program over to an elevated copy of itself.
    Elevate {
        enable: bool,
    },
}

enum Reply {
    Ok(Box<Status>),
    Failed(String, Option<Box<Status>>),
    /// Only reachable with a service: the local backend is in this process and always answers.
    Unreachable(String),
    /// Whether the service exists at all, and — when it does — the executable it is registered
    /// against if that file is no longer there.
    Installed(service::Installed, Option<PathBuf>),
    /// The backend was rebuilt; `true` means this process now owns the machine.
    Backend(bool),
    /// An elevated copy is starting. This one is done.
    HandedOver,
    Output(Output),
}

/// The service's registered executable, when that file is no longer on disk.
fn stale_registration() -> Option<PathBuf> {
    let exe = service::registered_exe()?;
    (!exe.is_file()).then_some(exe)
}

/// The result of an elevated action, as it appears on screen.
struct Output {
    title: String,
    ok: bool,
    lines: Vec<String>,
}

/// What the first item of the tray menu currently means.
#[derive(PartialEq, Eq, Clone, Copy)]
enum TrayAction {
    Enable,
    Disable,
    Start,
    /// A service is registered and will not answer. Nothing the menu can do about it.
    Unavailable,
}

impl TrayAction {
    fn label(self) -> &'static str {
        match self {
            TrayAction::Enable => "Включить защиту",
            TrayAction::Disable => "Выключить защиту",
            TrayAction::Start => "Запустить службу",
            TrayAction::Unavailable => "Служба не отвечает",
        }
    }

    fn clickable(self) -> bool {
        self != TrayAction::Unavailable
    }
}

/// Opens the window, and opens it on a second graphics backend if the first one will not start.
///
/// **Neither backend runs everywhere, and the machines they fail on do not overlap.** `wgpu`
/// reaches Direct3D 12, so it works on a VM with no GPU driver and inside an RDP session, where
/// Windows still provides a software D3D12 device — and it is the first choice for exactly that
/// reason. What it cannot do is run on a Windows that predates D3D12: on 7 and 8 there is nothing
/// for it to reach. `glow` is plain OpenGL 3.2, which every machine with a real graphics driver has
/// had for fifteen years and no RDP session has ever had.
pub fn run(show_window: bool, act: Option<bool>) -> eframe::Result<()> {
    let backend = Arc::new(Mutex::new(Backend::choose()));

    let result = match start(show_window, act, eframe::Renderer::Wgpu, &backend) {
        Err(e) => {
            log::warn!("wgpu would not start ({e}); falling back to OpenGL");
            start(show_window, act, eframe::Renderer::Glow, &backend)
        }
        ok => ok,
    };

    // The last thing this process does, and the reason the backend is owned out here rather than
    // by the worker thread: this process has to let go of the resolver before it goes away. What it
    // must NOT do is put the machine's DNS back — protection is turned off by the button that says
    // so and by nothing else, closing the window included (`backend.rs`).
    if let Ok(mut b) = backend.lock() {
        b.shutdown();
    }

    // AND THEN LEAVE, RATHER THAN UNWIND. «Выход» has to end the program at once; what stands
    // between here and that is a pile of other people's destructors — the D3D12 device and its
    // DLL detach, COM (`com.rs` never calls `CoUninitialize`, deliberately), the worker thread and
    // the one parked forever in `ShowSignal::wait`. Any of them can take seconds, none of them can
    // do anything for the user, and none of them holds state worth flushing: the settings and the
    // DNS backup are written synchronously where they change, the tray icon is already gone (eframe
    // destroys it inside `run_native`), and the instance mutex is released by the kernel.
    //
    // Only on success. A failed `run_native` still has to reach `main` and be reported — that is a
    // start-up error, and exiting 0 over it would turn "the window would not open" into silence.
    if result.is_ok() {
        std::process::exit(0);
    }
    result
}

fn start(
    show_window: bool,
    act: Option<bool>,
    renderer: eframe::Renderer,
    backend: &Arc<Mutex<Backend>>,
) -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        renderer,
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 660.0])
            .with_min_inner_size([380.0, 440.0])
            // The version belongs in the title bar rather than in the window: it is what a support
            // request has to quote, and it is the one piece of text that is worth nothing until
            // somebody asks for it.
            .with_title(concat!("DNS-AI v", env!("CARGO_PKG_VERSION")))
            .with_icon(icon::window_icon())
            // Hidden only when the caller asked for it — `--tray`, i.e. the logon path. A window
            // appearing at every logon is the single most common complaint about this class of
            // program; a double-click that shows nothing at all is worse.
            .with_visible(show_window),
        ..Default::default()
    };
    let backend = backend.clone();
    eframe::run_native(
        "DNS-AI",
        options,
        Box::new(move |cc| Ok(Box::new(TrayApp::new(cc, show_window, act, backend)))),
    )
}

struct TrayApp {
    cmd_tx: Sender<Job>,
    reply_rx: Receiver<Reply>,
    menu_rx: Receiver<MenuId>,
    tray_rx: Receiver<()>,
    /// A second launch — the tray icon clicked while this window is already running — arrives here
    /// instead of becoming a second tray icon (`setup::claim_instance`).
    show_rx: Receiver<()>,
    /// How long the worker waits before polling by itself, in milliseconds.
    poll_ms: Arc<AtomicU64>,

    tray: TrayIcon,
    item_action: MenuItem,
    action: TrayAction,
    id_action: MenuId,
    id_open: MenuId,
    id_quit: MenuId,

    /// True when this process owns the resolver and the adapters (no service registered).
    local: bool,
    /// Whether this process can change adapter DNS at all. Fixed for the life of the process.
    elevated: bool,

    status: Option<Status>,
    error: Option<String>,
    /// Set when a registered service cannot be reached — a different problem from a command that
    /// failed, and it needs different advice on screen.
    offline: Option<String>,
    installed: Option<service::Installed>,
    /// Set when the service names an executable that no longer exists.
    stale: Option<PathBuf>,
    /// The mode the user just asked for, until the answer catches up. The two mode switches are
    /// mutually exclusive, and without this both would read "on" for the second or two a full
    /// off/on cycle takes.
    pending_mode: Option<Mode>,
    /// The Run key value last reconciled with the setting.
    autostart_synced: Option<bool>,
    /// What was copied, and when, so the row can say so for a moment.
    copied: Option<(String, f64)>,
    output: Option<Output>,
    busy: bool,
    working: Option<String>,
    visible: bool,
    quitting: bool,
    icon_state: Option<bool>,
}

impl TrayApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        visible: bool,
        act: Option<bool>,
        backend: Arc<Mutex<Backend>>,
    ) -> Self {
        brand::install_fonts(&cc.egui_ctx);
        style(&cc.egui_ctx);

        let local = backend.lock().is_ok_and(|b| b.is_local());
        let action = TrayAction::Enable;
        let item_action = MenuItem::new(action.label(), true, None);
        let open = MenuItem::new("Настройки", true, None);
        let quit = MenuItem::new("Выход", true, None);
        let (id_action, id_open, id_quit) = (
            item_action.id().clone(),
            open.id().clone(),
            quit.id().clone(),
        );

        let menu = Menu::new();
        let _ = menu.append(&item_action);
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&open);
        let _ = menu.append(&quit);

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            // Left click opens the settings, right click opens the menu — what every other icon in
            // the notification area does. The crate's default is to open the menu on BOTH buttons,
            // which leaves a left click doing the one thing the user did not ask for and no way at
            // all to reach the window with a single click.
            .with_menu_on_left_click(false)
            .with_tooltip("DNS-AI")
            .with_icon(icon::tray_icon(false).expect("the icon is generated, not loaded"))
            .build()
            .expect("cannot create the tray icon");

        // tray-icon delivers events to a handler OR to its global channel, never both — so the
        // handlers below forward into our own channels and wake the UI, which is the only way a
        // click reaches the update loop while the window is hidden and egui is idle.
        let (menu_tx, menu_rx) = mpsc::channel();
        let ctx = cc.egui_ctx.clone();
        let menu_tx = Mutex::new(menu_tx);
        MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
            if let Ok(tx) = menu_tx.lock() {
                let _ = tx.send(e.id);
            }
            ctx.request_repaint();
        }));

        let (tray_tx, tray_rx) = mpsc::channel();
        let ctx = cc.egui_ctx.clone();
        let tray_tx = Mutex::new(tray_tx);
        TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
            // A single left click, on the way UP — pressing the button is not yet a click, and
            // acting on the DOWN event would open the window under a finger that has not committed
            // to anything. A double click arrives as two `Click`s and a `DoubleClick`; all of them
            // mean the same thing here, and showing an already-visible window costs nothing.
            let show = match e {
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } => true,
                TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                } => true,
                _ => false,
            };
            if show {
                if let Ok(tx) = tray_tx.lock() {
                    let _ = tx.send(());
                }
                ctx.request_repaint();
            }
        }));

        let (show_tx, show_rx) = mpsc::channel();
        let ctx = cc.egui_ctx.clone();
        std::thread::spawn(move || {
            let Some(signal) = setup::ShowSignal::create() else {
                return;
            };
            while signal.wait() {
                if show_tx.send(()).is_err() {
                    return;
                }
                ctx.request_repaint();
            }
        });

        let poll_ms = Arc::new(AtomicU64::new(interval(visible).as_millis() as u64));
        let (cmd_tx, reply_rx) = spawn_worker(cc.egui_ctx.clone(), poll_ms.clone(), backend);
        // Ask immediately rather than waiting out the first poll interval.
        let _ = cmd_tx.send(Job::Ipc(Request::Status));
        // `--enable` / `--disable`: this copy was started by the previous one, with administrator
        // rights, to do exactly this. The click already happened, in the window that is now closing,
        // and **which** click it was has to survive the handover — carrying only "enable" is how
        // «Выключить» used to end as a second window with everything still on, waiting for the user
        // to press the same button again.
        match act {
            Some(true) => {
                let _ = cmd_tx.send(Job::Ipc(Request::Enable));
            }
            Some(false) => {
                let _ = cmd_tx.send(Job::Ipc(Request::Disable));
            }
            None => {}
        }

        Self {
            cmd_tx,
            reply_rx,
            menu_rx,
            tray_rx,
            show_rx,
            poll_ms,
            tray,
            item_action,
            action,
            id_action,
            id_open,
            id_quit,
            local,
            elevated: setup::is_elevated(),
            status: None,
            error: None,
            offline: None,
            installed: None,
            stale: None,
            pending_mode: None,
            autostart_synced: None,
            copied: None,
            output: None,
            busy: true,
            working: None,
            visible,
            quitting: false,
            icon_state: None,
        }
    }

    fn send(&mut self, req: Request) {
        self.busy = true;
        self.error = None;
        let _ = self.cmd_tx.send(Job::Ipc(req));
    }

    /// An elevated verb about the service. `label` is what the button says while it runs — one of
    /// these can sit on a UAC prompt indefinitely.
    fn start(&mut self, verb: &'static str, title: &'static str) {
        self.busy = true;
        self.error = None;
        self.working = Some(title.to_string());
        let _ = self.cmd_tx.send(Job::Elevated { verb, title });
    }

    /// Restarts the whole program with administrator rights, because the portable path has no
    /// service to do the work and a process cannot gain rights.
    fn elevate(&mut self, enable: bool) {
        self.busy = true;
        self.error = None;
        self.working = Some("Запрос прав администратора".into());
        let _ = self.cmd_tx.send(Job::Elevate { enable });
    }

    /// Whether this process can change the machine's DNS right now.
    fn can_change(&self) -> bool {
        !self.local || self.elevated
    }

    fn set_visible(&mut self, ctx: &egui::Context, visible: bool) {
        self.visible = visible;
        self.poll_ms
            .store(interval(visible).as_millis() as u64, Ordering::Relaxed);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(visible));
        if visible {
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            // Whatever is on screen is up to twenty seconds old.
            let _ = self.cmd_tx.send(Job::Ipc(Request::Status));
        }
    }

    fn enabled(&self) -> bool {
        self.status.as_ref().is_some_and(|s| s.enabled)
    }

    /// What the first tray item should do right now.
    fn tray_action(&self) -> TrayAction {
        match (&self.offline, &self.installed) {
            (None, _) if self.enabled() => TrayAction::Disable,
            (None, _) => TrayAction::Enable,
            (Some(_), Some(service::Installed::Stopped)) if self.stale.is_none() => {
                TrayAction::Start
            }
            (Some(_), _) => TrayAction::Unavailable,
        }
    }

    fn drain_events(&mut self, ctx: &egui::Context) {
        while let Ok(id) = self.menu_rx.try_recv() {
            if id == self.id_action {
                match self.action {
                    TrayAction::Enable if !self.can_change() => self.elevate(true),
                    TrayAction::Enable => self.send(Request::Enable),
                    TrayAction::Disable if !self.can_change() => self.elevate(false),
                    TrayAction::Disable => self.send(Request::Disable),
                    TrayAction::Start => {
                        self.start("start", "Запуск");
                        self.set_visible(ctx, true);
                    }
                    TrayAction::Unavailable => {}
                }
            } else if id == self.id_open {
                self.set_visible(ctx, true);
            } else if id == self.id_quit {
                self.quitting = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
        while self.tray_rx.try_recv().is_ok() {
            self.set_visible(ctx, true);
        }
        while self.show_rx.try_recv().is_ok() {
            self.set_visible(ctx, true);
        }

        while let Ok(reply) = self.reply_rx.try_recv() {
            self.busy = false;
            self.working = None;
            match reply {
                Reply::Ok(s) => {
                    // The Run key is checked against the setting here rather than only when the
                    // switch is flipped: it defaults to on, so on a machine where nobody has ever
                    // touched it the switch used to say "on" while no value existed anywhere.
                    if self.autostart_synced != Some(s.settings.autostart_tray) {
                        match autostart::reconcile(s.settings.autostart_tray) {
                            Ok(()) => self.autostart_synced = Some(s.settings.autostart_tray),
                            Err(e) => log::warn!("autostart: {e:#}"),
                        }
                    }
                    if self.pending_mode == Some(s.settings.mode) {
                        self.pending_mode = None;
                    }
                    self.status = Some(*s);
                    // `error` is deliberately NOT cleared here. A `Status` request cannot fail, so
                    // the routine poll would wipe the only report a failed Enable ever produced —
                    // including the emergency `netsh` line that is the whole recovery path when a
                    // revert has left a machine without DNS.
                    self.offline = None;
                    self.installed = None;
                    self.stale = None;
                }
                Reply::Failed(e, s) => {
                    self.error = Some(e);
                    self.offline = None;
                    self.pending_mode = None;
                    if let Some(s) = s {
                        self.status = Some(*s);
                    }
                }
                Reply::Unreachable(e) => {
                    self.offline = Some(e);
                    self.status = None;
                    self.pending_mode = None;
                }
                Reply::Installed(i, stale) => {
                    self.installed = Some(i);
                    self.stale = stale;
                }
                Reply::Backend(local) => {
                    self.local = local;
                    self.autostart_synced = None;
                }
                Reply::HandedOver => {
                    // An elevated copy of this program is starting. Two windows and two tray icons
                    // polling the same machine is exactly what the instance guard exists to
                    // prevent, so this one leaves.
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                Reply::Output(o) => self.output = Some(o),
            }
        }
    }

    fn refresh_tray(&mut self) {
        let on = self.enabled();
        if self.icon_state != Some(on) {
            self.icon_state = Some(on);
            if let Some(i) = icon::tray_icon(on) {
                let _ = self.tray.set_icon(Some(i));
            }
            let _ = self.tray.set_tooltip(Some(if on {
                "DNS-AI — защита включена"
            } else {
                "DNS-AI — защита выключена"
            }));
        }
        // The label follows the state for the same reason the icon does, and it matters more: the
        // handler acts on what the item MEANS, and this is the only control reachable while the
        // window is hidden.
        let action = self.tray_action();
        if self.action != action {
            self.action = action;
            self.item_action.set_text(action.label());
            self.item_action.set_enabled(action.clickable());
        }
    }
}

impl eframe::App for TrayApp {
    /// Runs even while the window is hidden — which is precisely what a tray application needs: a
    /// click on the menu has to be acted on when there is no window on screen at all.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events(ctx);
        self.refresh_tray();

        // The window closes to the tray instead of ending the process — except when this process
        // is the one resolving. There, closing the window would take DNS with it, so the X button
        // hides it exactly as before and only «Выход» ends the program.
        if !self.quitting && ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.set_visible(ctx, false);
        }

        ctx.request_repaint_after(interval(self.visible));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // The signature line is a panel rather than the last thing in the scroll area, so it is
        // always on screen — a user who has to scroll to find where the program came from is a user
        // who never finds it. It takes the space it needs first; the settings get what is left.
        egui::Panel::bottom("footer")
            .frame(egui::Frame::NONE.fill(BG).inner_margin(egui::Margin {
                left: 16,
                right: 16,
                top: FOOTER_PAD,
                bottom: FOOTER_PAD,
            }))
            .show(ui, draw_footer);
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(BG).inner_margin(16.0))
            .show(ui, |ui| self.draw(ui));
    }
}

impl TrayApp {
    fn draw(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            brand::wordmark(ui, 21.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (text, colour) = match (&self.offline, self.enabled()) {
                    (Some(_), _) => ("нет службы", DANGER),
                    (None, true) => ("включено", OK),
                    (None, false) => ("выключено", MUTED),
                };
                ui.label(egui::RichText::new(text).color(colour));
            });
        });

        ui.add_space(14.0);

        egui::ScrollArea::vertical()
            .id_salt("main")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if self.offline.is_some() {
                    self.draw_service_trouble(ui);
                } else {
                    if let Some(e) = self.error.clone() {
                        banner(ui, DANGER, &e);
                        ui.add_space(10.0);
                    }
                    self.draw_toggle(ui);
                    if let Some(status) = self.status.clone() {
                        ui.add_space(16.0);
                        // The mode and the service are one subject: both answer "by what mechanism
                        // is this machine protected", and the service is the only one of the two
                        // that a user might have to install. Splitting them put the button that
                        // completes the choice at the bottom of the window, below settings that
                        // have nothing to do with it.
                        self.draw_mode(ui, &status);
                        ui.add_space(10.0);
                        self.draw_service(ui);
                        ui.add_space(16.0);
                        self.draw_switches(ui, &status);
                        ui.add_space(16.0);
                        // Two read-only lists. They are what somebody opens once — to copy an
                        // address onto another device, or to see what an adapter really has — and
                        // then never again, so they are folded away by default and the settings
                        // above them fit on one screen.
                        self.draw_adapters(ui, &status);
                        ui.add_space(8.0);
                        self.draw_endpoints(ui);
                    }
                }
                self.draw_output(ui);
            });
    }

    /// The screen for a service that is registered and will not answer.
    ///
    /// It is not the first-run screen any more — a portable copy with no service does not come here
    /// at all, it simply works. This is the repair screen, and the last button on it is the one that
    /// matters most: removing a broken service is what returns the machine to the portable path.
    fn draw_service_trouble(&mut self, ui: &mut egui::Ui) {
        let (headline, hint, action) = match (self.stale.clone(), self.installed.as_ref()) {
            (Some(missing), _) => (
                "Служба указывает на исчезнувший файл".to_string(),
                format!(
                    "Зарегистрировано: {}\nЭтого файла больше нет. Удалите службу — программа \
                     продолжит работать без неё.",
                    missing.display()
                ),
                None,
            ),
            (None, Some(service::Installed::Stopped)) => (
                "Служба остановлена".to_string(),
                "Пока она не запущена, защиту включить нельзя.".to_string(),
                Some(("Запустить службу", "start", "Запуск")),
            ),
            (None, Some(service::Installed::Running)) => (
                "Служба запущена, но не отвечает".to_string(),
                "Обычно так бывает, если файл программы заменили, а службу не перезапустили."
                    .to_string(),
                Some(("Перезапустить службу", "restart", "Перезапуск")),
            ),
            (None, Some(service::Installed::Other(word))) => (
                format!("Служба {word}"),
                "Подождите несколько секунд — состояние обновляется само.".to_string(),
                None,
            ),
            (None, Some(service::Installed::Unknown(e))) => (
                "Не удалось узнать состояние службы".to_string(),
                e.clone(),
                None,
            ),
            // `Installed::No` with the pipe unreachable is a race with the first poll, not a state.
            (None, None) | (None, Some(service::Installed::No)) => {
                ("Проверяю службу…".to_string(), String::new(), None)
            }
        };

        banner(ui, DANGER, &headline);
        ui.add_space(10.0);
        if !hint.is_empty() {
            ui.label(egui::RichText::new(hint).color(MUTED));
            ui.add_space(12.0);
        }

        if let Some((label, verb, title)) = action {
            if primary_button(ui, label, !self.busy).clicked() {
                self.start(verb, title);
            }
            ui.add_space(8.0);
        }
        if secondary(ui, ui.available_width(), "Удалить службу", !self.busy).clicked()
        {
            self.start("uninstall", "Удаление службы");
        }
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new("Windows спросит разрешение администратора.")
                .small()
                .color(MUTED),
        );
    }

    fn draw_toggle(&mut self, ui: &mut egui::Ui) {
        let on = self.enabled();
        let label = if on {
            "Выключить"
        } else {
            "Включить"
        };
        // Off: the accent, because turning protection ON is what this screen is for. On: a quiet
        // card, because the loud button on a working machine is the one that breaks it.
        let clicked = ui
            .scope(|ui| {
                if on {
                    button_colours(
                        ui,
                        [PANEL, PANEL_HOVER, PANEL_ACTIVE],
                        [BORDER, BORDER_HOVER, BORDER_HOVER],
                    );
                } else {
                    button_colours(
                        ui,
                        [PRIMARY, PRIMARY_HOVER, PRIMARY_ACTIVE],
                        [PRIMARY, PRIMARY_HOVER, PRIMARY_ACTIVE],
                    );
                }
                centred(ui, |ui| {
                    let button = egui::Button::new(
                        egui::RichText::new(label).size(16.0).strong().color(if on {
                            TEXT
                        } else {
                            egui::Color32::WHITE
                        }),
                    )
                    .min_size(egui::vec2(ui.available_width(), 44.0))
                    .corner_radius(BUTTON_RADIUS);
                    ui.add_enabled(!self.busy, button).clicked()
                })
            })
            .inner;

        if clicked {
            if self.can_change() {
                let req = if on {
                    Request::Disable
                } else {
                    Request::Enable
                };
                self.send(req);
            } else {
                // No service and no rights: the only way to do this is to become an administrator,
                // which for a process means being a different one.
                self.elevate(!on);
            }
        }

        if !self.can_change() {
            ui.add_space(6.0);
            // Says what is true rather than only what is about to happen. An adapter's DNS lives in
            // HKLM and only an administrator may write it — Windows offers no per-user path to it
            // at all — but what does get written STAYS written across a reboot. A user who believes
            // otherwise is a user who never turns it on: the prompt is the price of SWITCHING, not
            // the price of keeping it switched.
            ui.label(
                egui::RichText::new(
                    "Менять настройки DNS в Windows может только администратор: при переключении \
                     программа перезапустится и запросит права. Уже включённая защита сохраняется \
                     и после перезагрузки — права нужны только на переключение. Чтобы их не \
                     спрашивали каждый раз, установите службу.",
                )
                .small()
                .color(MUTED),
            );
        }
    }

    /// The two mechanisms, as two mutually exclusive switches.
    ///
    /// One of them is always on and the other is always off; turning the active one off is ignored,
    /// because there is no third state in which the machine resolves through us. Turning the other
    /// one on switches modes — and the service disables the current one before applying the new one,
    /// which is what `pending_mode` shows on screen while it happens.
    ///
    /// **Which one is recommended is decided by the Windows version, and shown as a badge rather
    /// than said in the description.** A user reading two paragraphs to find the word
    /// "рекомендуется" is a user who has already had to think about a choice this program should
    /// have made for them.
    fn draw_mode(&mut self, ui: &mut egui::Ui, s: &Status) {
        section(ui, "Способ защиты DNS-запросов");
        let mut next = editable(s);
        let mut changed = false;

        // Every row is dead while a change is in flight. The worker is one thread and a mode change
        // is a full disable/enable cycle of `netsh` calls, so the status on screen stays the
        // PRE-change one for seconds — long enough for a second click to send a stale value back.
        //
        // The same rule as the settings below, and for the same reason: with protection OFF the
        // mode is a line in a file this process owns, and demanding administrator rights to choose
        // it before turning anything on would be asking for them to do nothing.
        let live = !self.busy && (!s.enabled || self.can_change());
        let win11 = s.native_supported;
        let shown = self.pending_mode.unwrap_or(s.settings.mode);

        card(ui, |ui| {
            let mut local = shown == Mode::Stub;
            if brand::switch(
                ui,
                &mut local,
                "Legacy DNS перехват",
                (!win11).then_some("рекомендуется"),
                live,
                // The second sentence is the price of this mode and it is not obvious: the resolver
                // lives in this process, so «Выход» leaves the adapters pointing at a loopback
                // address with nothing behind it. The program no longer undoes anything on its way
                // out, which makes saying so here mandatory rather than nice.
                Some(
                    "Запросы идут на 127.0.0.1, программа шифрует их сама. \
                     Работает, только пока программа запущена.",
                ),
            ) && local
            {
                next.mode = Mode::Stub;
                changed = true;
            }

            ui.add_space(10.0);

            let mut native = shown == Mode::Native;
            // Disabled rather than merely discouraged below Windows 11: there the DoH client does
            // not exist and our nodes refuse plain :53, so the mode would produce no DNS at all.
            if brand::switch(
                ui,
                &mut native,
                "Native DNS support",
                win11.then_some("рекомендуется"),
                live && win11,
                Some(if win11 {
                    "Адреса DNS-AI прописываются в адаптеры, шифрует сама Windows."
                } else {
                    "Недоступно: встроенный DoH-клиент появился только в Windows 11."
                }),
            ) && native
            {
                next.mode = Mode::Native;
                changed = true;
            }
        });

        if changed {
            self.pending_mode = Some(next.mode);
            self.send(Request::SetSettings { settings: next });
        }
    }

    fn draw_switches(&mut self, ui: &mut egui::Ui, s: &Status) {
        section(ui, "Настройки");
        let mut next = editable(s);
        let mut changed = false;
        // Settings that only reach the machine while protection is ON. With it off, changing one
        // writes a file this process owns and needs nothing from anybody.
        let live = !self.busy && (!s.enabled || self.can_change());

        card(ui, |ui| {
            changed |= brand::switch(
                ui,
                &mut next.ipv6,
                "Поддержка IPv6",
                None,
                live,
                Some("Без неё IPv6-адреса DNS очищаются, чтобы запросы не уходили мимо."),
            );
            ui.add_space(10.0);
            changed |= brand::switch(
                ui,
                &mut next.include_vpn_adapters,
                "Настраивать VPN-адаптеры",
                None,
                live,
                Some("По умолчанию выключено: VPN-клиенты сами перезаписывают свой DNS."),
            );
            ui.add_space(10.0);

            let mut auto = next.autostart_tray;
            if brand::switch(
                ui,
                &mut auto,
                "Автозапуск приложения",
                None,
                !self.busy,
                Some("Значок в трее появляется при входе в систему."),
            ) {
                next.autostart_tray = auto;
                changed = true;
                // Written from here because it lives in THIS user's registry hive.
                if let Err(e) = autostart::set(auto) {
                    log::warn!("autostart: {e:#}");
                }
            }

            // Only with a service: it is that registration's start type, and there is nothing to
            // set when no service exists. The offer to create one is its own section below.
            if !self.local {
                ui.add_space(10.0);
                let mut svc = next.service_autostart;
                if brand::switch(
                    ui,
                    &mut svc,
                    "Автозапуск службы в фоне",
                    None,
                    !self.busy,
                    Some("Защита включается вместе с Windows, до входа пользователя."),
                ) {
                    next.service_autostart = svc;
                    changed = true;
                }
            }
        });

        if changed {
            self.send(Request::SetSettings { settings: next });
        }
    }

    /// The settings the user chose, as they ended up on this machine — and the only place an
    /// address can be copied from without retyping it.
    fn draw_adapters(&mut self, ui: &mut egui::Ui, s: &Status) {
        // The one state where "включено" is a lie: this program believes it configured the machine,
        // and the resolver those adapters point at is not running. Drawn OUTSIDE the fold, because
        // an alarm nobody can see until they expand a list is not an alarm.
        if s.enabled && s.settings.mode == Mode::Stub && !s.stub_running {
            banner(ui, DANGER, "Локальный резолвер не запущен");
            ui.add_space(8.0);
        }
        let mut copy: Option<String> = None;
        let time = ui.input(|i| i.time);
        let copied = self.copied.clone();
        spoiler(ui, "adapters", "Адаптеры", |ui| {
            card(ui, |ui| {
                if s.adapters.is_empty() {
                    ui.label(
                        egui::RichText::new(
                            "Ни одного подходящего адаптера: все виртуальные, туннельные или без шлюза.",
                        )
                        .small()
                        .color(MUTED),
                    );
                    return;
                }
                for (i, a) in s.adapters.iter().enumerate() {
                    if i > 0 {
                        ui.add_space(4.0);
                    }
                    if copy_row(ui, &a.alias, &a.current_v4, &copied, time) {
                        copy = Some(a.current_v4.clone());
                    }
                    if s.settings.ipv6 && copy_row(ui, "IPv6", &a.current_v6, &copied, time) {
                        copy = Some(a.current_v6.clone());
                    }
                }
            });
        });
        self.take_copy(ui, copy, time);
    }

    /// The addresses themselves, because the other device in the house has to be configured by hand
    /// and this is where somebody looks for them.
    fn draw_endpoints(&mut self, ui: &mut egui::Ui) {
        let mut copy: Option<String> = None;
        let time = ui.input(|i| i.time);
        let copied = self.copied.clone();
        spoiler(ui, "endpoints", "Серверы DNS-AI", |ui| {
            card(ui, |ui| {
                let mut row = |key: &str, value: &str| {
                    if copy_row(ui, key, value, &copied, time) {
                        copy = Some(value.to_string());
                    }
                };
                for ip in config::resolver_ips_text() {
                    row("IPv4", &ip);
                }
                for ip in config::resolver_ipv6_text() {
                    row("IPv6", &ip);
                }
                row("DoH / DoH3", config::DOH_URL);
                row("DoT / DoQ", config::DOT_DOQ_HOST);
            });
        });
        self.take_copy(ui, copy, time);
    }

    fn take_copy(&mut self, ui: &mut egui::Ui, value: Option<String>, time: f64) {
        if let Some(v) = value {
            ui.ctx().copy_text(v.clone());
            self.copied = Some((v, time));
        }
    }

    /// The service — optional, and the only thing on this screen that is not a setting.
    ///
    /// The program does not need it: it resolves in this process. What a service adds is the two
    /// things a user process cannot do — work before anybody logs in, and change adapters without
    /// a UAC prompt each time.
    fn draw_service(&mut self, ui: &mut egui::Ui) {
        let (label, verb, title) = if self.local {
            ("Установить службу Windows", "install", "Установка службы")
        } else {
            ("Удалить службу Windows", "uninstall", "Удаление службы")
        };
        if secondary(ui, ui.available_width(), label, !self.busy).clicked() {
            self.start(verb, title);
        }
        ui.add_space(6.0);
        let text = if self.local {
            "Без службы защита работает, пока открыта программа. Служба включает её до входа в \
             систему и убирает запрос прав администратора при каждом переключении."
        } else {
            "Установлена. Защита работает независимо от этого окна, в том числе до входа в систему."
        };
        ui.label(egui::RichText::new(text).small().color(MUTED));
    }

    /// Whatever the last elevated verb produced.
    fn draw_output(&mut self, ui: &mut egui::Ui) {
        if let Some(label) = self.working.clone() {
            ui.add_space(14.0);
            ui.label(egui::RichText::new(format!("{label}…")).color(LINK));
            return;
        }
        if self.output.is_none() {
            return;
        }

        let mut close = false;
        ui.add_space(14.0);
        {
            let out = self.output.as_ref().expect("checked just above");
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(&out.title)
                        .color(if out.ok { OK } else { DANGER })
                        .strong(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("×").clicked() {
                        close = true;
                    }
                });
            });
            ui.add_space(4.0);
            card(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("output")
                    .max_height(170.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for line in &out.lines {
                            ui.label(egui::RichText::new(line).monospace().size(11.0).color(TEXT));
                        }
                    });
            });
        }
        if close {
            self.output = None;
        }
    }
}

/// Where the program came from: pinned to the bottom edge of the window by the panel that calls it.
///
/// The version used to be on this line and is now in the title bar. A signature is read once; a
/// version is quoted in a support request, and the title bar is where the rest of Windows keeps it.
fn draw_footer(ui: &mut egui::Ui) {
    // The hairline above this strip is the panel's own separator, drawn in
    // `widgets.noninteractive.bg_stroke` — which `style` sets to the site's `--line` for exactly
    // this. Painting a second one here put two lines a pixel apart.
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 5.0;
        ui.label(egui::RichText::new("Сайт:").small().color(MUTED));
        if link(ui, "DNS-AI.RU").clicked() {
            open("https://dns-ai.ru");
        }
        ui.label(egui::RichText::new("·").small().color(MUTED));
        ui.label(egui::RichText::new("Группа:").small().color(MUTED));
        if link(ui, "t.me/nova_txt").clicked() {
            open("https://t.me/nova_txt");
        }
    });
}

/// Laid out and painted by hand rather than added as a `Label`, for one reason: the colour has to
/// depend on the hover state, and the hover state does not exist until the space is allocated.
/// `Color32::PLACEHOLDER` is what lets the galley be measured before its colour is decided.
/// The site's links change colour on hover and nothing else; so does this one.
fn link(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let font = egui::TextStyle::Small.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font, egui::Color32::PLACEHOLDER);
    let (rect, response) = ui.allocate_exact_size(galley.size(), egui::Sense::click());
    let colour = if response.hovered() { LINK_HOVER } else { LINK };
    ui.painter().galley(rect.min, galley, colour);
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Hands a URL to whatever opens one. Failure is silent: there is nothing useful to say on a
/// settings screen about a browser that would not start, and nothing depends on it.
fn open(url: &str) {
    use std::os::windows::process::CommandExt;
    let _ = std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .creation_flags(dns_ai_core::netif::no_window())
        .spawn();
}

// =================================================================================================
// Widgets
// =================================================================================================

/// The radius the site gives a button (`.btn`) and a card (`.tile`).
const BUTTON_RADIUS: u8 = 10;
const CARD_RADIUS: u8 = 12;

/// Gives every button state its own colours — and the same geometry.
///
/// **The border width is 1 px in all four states, and that is the whole point.** egui derives a
/// button's inner margin from `button_padding + expansion - bg_stroke.width`, so a state that
/// borrows a thicker border, or any expansion at all, draws its label somewhere else: the button
/// twitches under the pointer. The site does not do that — `.btn:hover` changes brightness,
/// `.btn.secondary:hover` changes the background, and neither moves a pixel — so neither does this.
///
/// `noninteractive` is set too, because that is what a disabled button falls back to: without it a
/// button that is briefly not clickable would repaint itself in egui's default grey.
fn button_colours(ui: &mut egui::Ui, fill: [egui::Color32; 3], stroke: [egui::Color32; 3]) {
    let widgets = &mut ui.visuals_mut().widgets;
    let states = [
        (&mut widgets.noninteractive, 0),
        (&mut widgets.inactive, 0),
        (&mut widgets.hovered, 1),
        (&mut widgets.active, 2),
    ];
    for (visuals, i) in states {
        visuals.weak_bg_fill = fill[i];
        visuals.bg_fill = fill[i];
        visuals.bg_stroke = egui::Stroke::new(1.0, stroke[i]);
        visuals.corner_radius = egui::CornerRadius::same(BUTTON_RADIUS);
        visuals.expansion = 0.0;
    }
}

/// Centres what a widget draws inside the space it was given.
///
/// egui takes a button's text alignment from the layout of the `Ui` it lands in, and a settings
/// column is top-down/left — which pins the label of a full-width button to its left edge, where
/// every button on the site has it in the middle.
fn centred<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.with_layout(egui::Layout::top_down(egui::Align::Center), add)
        .inner
}

/// The one button on a screen that has a single thing to do.
fn primary_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    ui.scope(|ui| {
        button_colours(
            ui,
            [PRIMARY, PRIMARY_HOVER, PRIMARY_ACTIVE],
            [PRIMARY, PRIMARY_HOVER, PRIMARY_ACTIVE],
        );
        centred(ui, |ui| {
            let button = egui::Button::new(
                egui::RichText::new(label)
                    .size(15.0)
                    .strong()
                    .color(egui::Color32::WHITE),
            )
            .min_size(egui::vec2(ui.available_width(), 42.0))
            .corner_radius(BUTTON_RADIUS);
            ui.add_enabled(enabled, button)
        })
    })
    .inner
}

fn secondary(ui: &mut egui::Ui, width: f32, label: &str, enabled: bool) -> egui::Response {
    ui.scope(|ui| {
        button_colours(
            ui,
            [PANEL, PANEL_HOVER, PANEL_ACTIVE],
            [BORDER, BORDER_HOVER, BORDER_HOVER],
        );
        centred(ui, |ui| {
            let button = egui::Button::new(egui::RichText::new(label).color(if enabled {
                TEXT
            } else {
                MUTED
            }))
            .min_size(egui::vec2(width, 34.0))
            .corner_radius(BUTTON_RADIUS);
            ui.add_enabled(enabled, button)
        })
    })
    .inner
}

/// A section title, set the way the site sets one: small, upper-case, letter-spaced, `--fg-3`.
/// The site calls the class `.eyebrow`, and it is the one piece of typography that makes a window
/// look like it belongs to a page.
fn section_job(ui: &egui::Ui, title: &str) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    job.append(
        &title.to_uppercase(),
        0.0,
        egui::TextFormat {
            font_id: egui::TextStyle::Small.resolve(ui.style()),
            color: egui::Color32::PLACEHOLDER,
            extra_letter_spacing: 1.2,
            ..Default::default()
        },
    );
    job
}

fn section(ui: &mut egui::Ui, title: &str) {
    let galley = ui.painter().layout_job(section_job(ui, title));
    let (rect, _) = ui.allocate_exact_size(galley.size(), egui::Sense::hover());
    ui.painter().galley(rect.min, galley, MUTED);
    ui.add_space(6.0);
}

/// A section that folds away: the same title as [`section`], a triangle that turns, and a body that
/// is drawn only when it is open.
///
/// Closed by default and remembered for the life of the process, not longer. Both of these lists
/// are things somebody opens once — to copy an address onto a phone, or to see what an adapter
/// really has — and a window that reopens them at every start is a window that has to be scrolled
/// before it can be used.
fn spoiler(ui: &mut egui::Ui, key: &str, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    /// The triangle's box, and the gap to the title.
    const MARK: f32 = 9.0;
    const MARK_GAP: f32 = 7.0;

    let id = ui.make_persistent_id(key);
    let mut open = ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false);

    let galley = ui.painter().layout_job(section_job(ui, title));
    let height = galley.size().y.max(MARK + 6.0);
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::click(),
    );
    if response.clicked() {
        open = !open;
        ui.data_mut(|d| d.insert_temp(id, open));
    }

    let colour = if response.hovered() { TEXT } else { MUTED };
    // Painted rather than typed, for the same reason as the copy icon: the arrow glyphs are not in
    // Segoe UI, and a missing glyph on this screen is a box (`brand.rs`).
    let turn = ui.ctx().animate_bool(id, open) * std::f32::consts::FRAC_PI_2;
    let (sin, cos) = turn.sin_cos();
    let centre = egui::pos2(rect.left() + MARK / 2.0, rect.center().y);
    let radius = MARK / 2.0;
    let points = [(-0.45, -0.85), (-0.45, 0.85), (0.85, 0.0)]
        .iter()
        .map(|(x, y)| {
            let (x, y) = (x * radius, y * radius);
            egui::pos2(centre.x + x * cos - y * sin, centre.y + x * sin + y * cos)
        })
        .collect();
    ui.painter().add(egui::Shape::convex_polygon(
        points,
        colour,
        egui::Stroke::NONE,
    ));
    ui.painter().galley(
        egui::pos2(
            rect.left() + MARK + MARK_GAP,
            rect.center().y - galley.size().y / 2.0,
        ),
        galley,
        colour,
    );
    response.on_hover_cursor(egui::CursorIcon::PointingHand);

    if open {
        ui.add_space(6.0);
        body(ui);
    }
}

fn banner(ui: &mut egui::Ui, colour: egui::Color32, text: &str) {
    egui::Frame::NONE
        .fill(PANEL)
        .stroke(egui::Stroke::new(1.0, colour))
        .inner_margin(10.0)
        .corner_radius(CARD_RADIUS)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(egui::RichText::new(text).color(colour));
        });
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::NONE
        .fill(PANEL)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .inner_margin(12.0)
        .corner_radius(CARD_RADIUS)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        });
}

/// A label, a value that can be copied, and a small button that says so. Returns `true` when the
/// user asked for the value.
///
/// **The value itself is the button too.** Reaching for a 20 px glyph to copy an IPv6 address is
/// the kind of aim a settings screen should not ask for, and the address is right there under the
/// pointer already.
fn copy_row(
    ui: &mut egui::Ui,
    key: &str,
    value: &str,
    copied: &Option<(String, f64)>,
    time: f64,
) -> bool {
    let just_copied = copied
        .as_ref()
        .is_some_and(|(v, at)| v == value && time - at < COPIED_FOR);
    let mut asked = false;
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(key).color(MUTED).small());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // An icon rather than a word: the row is already two pieces of text, and a third
            // would be read as part of the value.
            if brand::copy_icon(ui).on_hover_text("Копировать").clicked() {
                asked = true;
            }
            let shown = if just_copied {
                "скопировано"
            } else {
                value
            };
            let colour = if just_copied { OK } else { LINK };
            let label = egui::Label::new(
                egui::RichText::new(shown)
                    .monospace()
                    .size(11.0)
                    .color(colour),
            )
            .sense(egui::Sense::click())
            .truncate();
            if ui
                .add(label)
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                asked = true;
            }
        });
    });
    asked
}

fn interval(visible: bool) -> Duration {
    if visible {
        POLL_VISIBLE
    } else {
        POLL_HIDDEN
    }
}

/// The settings as the window may change them.
///
/// `service_autostart` comes from the SCM rather than from the settings file, and that is the whole
/// point of the copy: the two are allowed to disagree, and a click on some other switch must not
/// quietly push the file's opinion back onto the machine.
fn editable(s: &Status) -> dns_ai_core::config::Settings {
    dns_ai_core::config::Settings {
        service_autostart: s.service_autostart,
        ..s.settings.clone()
    }
}

fn style(ctx: &egui::Context) {
    // Pinned to dark BEFORE the visuals are set, and this is not a preference. egui keeps a style
    // per theme and follows the system by default, while `set_visuals` writes only into the theme
    // that is active at that moment. On a machine set to Light, everything below would land in the
    // dark style, egui would then draw with the untouched light one, and the window would be our
    // dark frames with egui's light scrollbars and dark grey text on #0d1117.
    ctx.set_theme(egui::ThemePreference::Dark);

    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = BG;
    visuals.extreme_bg_color = PANEL;
    visuals.selection.bg_fill = PRIMARY;
    // The hairline the bottom panel draws between itself and the content, and every other
    // separator egui puts in on its own. `--line` over the page background, not the card border:
    // the footer is a division, not an edge.
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, SEPARATOR);
    // Nothing on this screen grows when the pointer arrives. egui already defaults `expansion` to
    // zero; it is written down because a button that moves under the cursor is the defect this
    // program had, and a default is not a decision until somebody makes it one (`button_colours`).
    for state in [
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        state.expansion = 0.0;
        state.corner_radius = egui::CornerRadius::same(BUTTON_RADIUS);
    }
    // The fix for "dark text on a dark background": egui's default body colour is a mid grey that
    // disappears against #0d1117.
    visuals.override_text_color = Some(TEXT);
    ctx.set_visuals_of(egui::Theme::Dark, visuals.clone());
    ctx.set_visuals(visuals);

    ctx.all_styles_mut(|style| {
        // One size for the whole window, and it is Windows' own: Segoe UI Semibold at 14 px is what
        // a settings row is set in. `brand::install_fonts` supplies the face.
        use egui::{FontFamily, FontId, TextStyle};
        style.text_styles = [
            (
                TextStyle::Body,
                FontId::new(FONT_SIZE, FontFamily::Proportional),
            ),
            (
                TextStyle::Button,
                FontId::new(FONT_SIZE, FontFamily::Proportional),
            ),
            (
                TextStyle::Heading,
                FontId::new(19.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Small,
                FontId::new(12.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(12.0, FontFamily::Monospace),
            ),
        ]
        .into();
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);
    });
}

// =================================================================================================
// The worker
// =================================================================================================

/// Every blocking call in the program happens here, one at a time, so the window keeps drawing and
/// two jobs can never overlap. The idle path doubles as the poll that keeps the tray icon honest.
fn spawn_worker(
    ctx: egui::Context,
    poll_ms: Arc<AtomicU64>,
    backend: Arc<Mutex<Backend>>,
) -> (Sender<Job>, Receiver<Reply>) {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Job>();
    let (reply_tx, reply_rx) = mpsc::channel::<Reply>();

    std::thread::spawn(move || loop {
        let wait = Duration::from_millis(poll_ms.load(Ordering::Relaxed).max(500));
        let job = match cmd_rx.recv_timeout(wait) {
            Ok(j) => j,
            Err(RecvTimeoutError::Timeout) => Job::Ipc(Request::Status),
            Err(RecvTimeoutError::Disconnected) => break,
        };

        let mut replies = Vec::new();
        match job {
            Job::Ipc(req) => replies.push(ask(&backend, &req)),
            Job::Elevate { enable } => {
                // The verb goes with it. An elevated copy started with no arguments is just the
                // window again: it would come up with protection still on and the user would have
                // to press «Выключить» a second time, in a second window, to get the thing they
                // already asked for.
                let args: &[&str] = if enable {
                    &["--enable"]
                } else {
                    &["--disable"]
                };
                // The claim on "being the window" goes first. Held until this process exits, it
                // would make the copy we are about to start decide that a window already exists and
                // quietly do nothing — leaving the user with a UAC prompt and no window at all.
                setup::release_instance();
                match elevate::run_self_detached(args) {
                    Ok(elevate::Outcome::Declined) => {
                        setup::claim_instance();
                        replies.push(Reply::Output(Output {
                            title: "Права администратора".into(),
                            ok: false,
                            lines: vec![
                                "Отменено. Без них программа не может менять настройки DNS."
                                    .to_string(),
                            ],
                        }));
                    }
                    Ok(_) => replies.push(Reply::HandedOver),
                    Err(e) => {
                        setup::claim_instance();
                        replies.push(Reply::Output(Output {
                            title: "Права администратора".into(),
                            ok: false,
                            lines: vec![format!("{e:#}")],
                        }));
                    }
                }
            }
            Job::Elevated { verb, title } => {
                // A local backend has to let go of the machine before a service can take it over:
                // both would otherwise want `127.0.0.1:53`, and the second one to ask loses. The
                // backend is left without its runtime for the duration; `Backend::choose()` below
                // replaces the whole value, and nothing asks it anything in between — this worker
                // is the only thread that does, and it is right here.
                if let Ok(mut b) = backend.lock() {
                    b.shutdown();
                }
                replies.push(Reply::Output(elevated(verb, title)));

                // Whatever ran may have created or destroyed the service, so the answer to "who
                // owns this machine" is re-asked rather than assumed.
                let now_local = match backend.lock() {
                    Ok(mut b) => {
                        *b = Backend::choose();
                        b.is_local()
                    }
                    Err(_) => false,
                };
                replies.push(Reply::Backend(now_local));

                // `StartService` returns once the SCM has LAUNCHED the process, not once it can
                // answer: the service reports Running before its pipe listener exists, so the first
                // status call lands in a window of a few hundred milliseconds where the honest
                // answer is "unreachable". Reported straight through, that draws «Служба запущена,
                // но не отвечает» on top of an install that worked perfectly.
                let mut reply = ask(&backend, &Request::Status);
                for _ in 0..10 {
                    if !matches!(reply, Reply::Unreachable(_)) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(300));
                    reply = ask(&backend, &Request::Status);
                }
                replies.push(reply);
            }
        }

        // The service screen needs to know whether the service exists, and it only ever draws when
        // the pipe is unreachable — so ask exactly then, and in the same batch, so the two facts
        // reach the window together and cannot contradict each other for a frame.
        if replies.iter().any(|r| matches!(r, Reply::Unreachable(_))) {
            replies.push(Reply::Installed(
                service::query_installed(),
                stale_registration(),
            ));
        }

        for reply in replies {
            if reply_tx.send(reply).is_err() {
                return;
            }
        }
        ctx.request_repaint();
    });

    (cmd_tx, reply_rx)
}

fn ask(backend: &Arc<Mutex<Backend>>, req: &Request) -> Reply {
    let answer = match backend.lock() {
        Ok(b) => b.ask(req),
        Err(e) => Err(anyhow::anyhow!("{e}")),
    };
    match answer {
        Ok(r) if r.ok => match r.status {
            Some(s) => Reply::Ok(Box::new(s)),
            None => Reply::Failed("ответ без состояния".into(), None),
        },
        Ok(r) => Reply::Failed(
            r.error.unwrap_or_else(|| "неизвестная ошибка".into()),
            r.status.map(Box::new),
        ),
        Err(e) => Reply::Unreachable(format!("{e:#}")),
    }
}

/// Runs one verb elevated and turns whatever came back into something worth reading.
///
/// Three outcomes have to stay distinguishable, because the next thing to do differs in each: the
/// user declined the prompt, the verb ran and failed for its own reason, or the child vanished
/// without leaving a report.
fn elevated(verb: &'static str, title: &'static str) -> Output {
    let nonce = report::new_nonce();
    match elevate::run_self(&[verb, "--report", &nonce]) {
        Ok(elevate::Outcome::Declined) => Output {
            title: title.into(),
            ok: false,
            lines: vec!["Отменено. Без прав администратора службой управлять нельзя.".to_string()],
        },
        Ok(elevate::Outcome::Exited(code)) => match ActionReport::load(&nonce) {
            Some(report) => {
                let mut lines = report.lines;
                if let Some(e) = report.error {
                    lines.push(e);
                }
                Output {
                    title: title.into(),
                    ok: report.ok,
                    lines,
                }
            }
            None => Output {
                title: title.into(),
                ok: code == 0,
                lines: vec![
                    format!("Процесс завершился с кодом {code}, но отчёт не записан."),
                    format!("Журнал: {}", dns_ai_core::paths::service_log().display()),
                ],
            },
        },
        Err(e) => Output {
            title: title.into(),
            ok: false,
            lines: vec![format!("{e:#}")],
        },
    }
}
