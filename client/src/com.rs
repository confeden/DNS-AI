//! COM, initialised once per thread and never torn down.
//!
//! Two unrelated things in this program need it — `ShellExecuteEx` with the `runas` verb goes to
//! the Application Information service over COM (`elevate.rs`), and the Start-menu shortcut is a
//! COM object (`shell_link.rs`) — and they run on different threads in different processes. The
//! rule is per *thread*, so a single flag would be wrong; a `thread_local` is the shape the
//! requirement actually has.

use std::cell::Cell;

use windows_sys::Win32::System::Com::{
    CoInitializeEx, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
};

thread_local! {
    static READY: Cell<bool> = const { Cell::new(false) };
}

/// Makes COM usable on this thread. Cheap and idempotent after the first call.
///
/// Never uninitialised. Both callers live for as long as the process does, and `CoUninitialize`
/// on a thread that still holds an interface pointer is worse than not calling it at all.
pub fn ensure() {
    READY.with(|ready| {
        if ready.get() {
            return;
        }
        // The result is deliberately ignored. `S_FALSE` means somebody already initialised this
        // thread and `RPC_E_CHANGED_MODE` means they did it in the other apartment model — both
        // leave COM usable, which is all this needs, and neither is a reason to refuse to try.
        unsafe {
            CoInitializeEx(
                std::ptr::null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            )
        };
        ready.set(true);
    });
}
