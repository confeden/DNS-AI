//! The mark, in the two shapes the running program needs.
//!
//! The geometry itself lives in [`crate::mark`], which has no dependencies so that `build.rs` can
//! `include!` it and emit the same drawing as the executable's icon *resource* — the one the Start
//! menu, the taskbar and "Apps & features" read off the disk before the process exists.

use eframe::egui;

use crate::mark;

pub fn tray_icon(active: bool) -> Option<tray_icon::Icon> {
    tray_icon::Icon::from_rgba(mark::rgba(32, active), 32, 32).ok()
}

/// The window and taskbar icon. Bigger, because Windows scales this one down itself and a 32-pixel
/// source in a 48-pixel slot looks like a mistake.
pub fn window_icon() -> egui::IconData {
    const N: u32 = 128;
    egui::IconData {
        rgba: mark::rgba(N as usize, true),
        width: N,
        height: N,
    }
}
