//! The Start-menu shortcut, written through the shell's own COM object.
//!
//! A `.lnk` is not a text file with a path in it. It is a serialised structure with an item-ID
//! list, a tracker record and a link-target reference, and the only supported way to produce one
//! is to ask the shell: `CoCreateInstance(ShellLink)`, set the properties, and `IPersistFile::Save`.
//! Hand-assembling the bytes is possible and is what every "how do I make a shortcut without COM"
//! answer does; it also produces a file that resolves on the machine that wrote it and quietly
//! fails to follow the target anywhere else.
//!
//! **The vtables are declared here because `windows-sys` does not ship COM interfaces.** It emits
//! functions, structs, constants and CLSIDs — `ShellLink` among them — but no interface
//! definitions, by design; those live in the much larger `windows` crate. Pulling that in for one
//! shortcut is not worth it, so the two vtables are written out below.
//!
//! A wrong slot here is an access violation at run time, not a compile error, so the layouts were
//! taken from the SDK's own headers rather than from memory:
//! `ShObjIdl_core.h` for `IShellLinkWVtbl` (21 slots, `SetPath` **last**, which is the surprising
//! one) and `ObjIdl.h` for `IPersistFileVtbl` (9 slots, `Save` at 6). Slots this module does not
//! call are typed as opaque pointers so that a mistake cannot become a call.

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::{bail, Result};
use windows_sys::core::{GUID, HRESULT, PCWSTR};
use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
use windows_sys::Win32::UI::Shell::ShellLink;

use crate::com;

/// `IShellLinkW`. Confirmed against `ShObjIdl_core.h`.
const IID_ISHELLLINKW: GUID = GUID::from_u128(0x000214f9_0000_0000_c000_000000000046);
/// `IPersistFile`. Confirmed against the interface registration on a live machine.
const IID_IPERSISTFILE: GUID = GUID::from_u128(0x0000010b_0000_0000_c000_000000000046);

#[repr(C)]
struct IShellLinkWVtbl {
    query_interface:
        unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    get_path: *const c_void,
    get_id_list: *const c_void,
    set_id_list: *const c_void,
    get_description: *const c_void,
    set_description: unsafe extern "system" fn(*mut c_void, PCWSTR) -> HRESULT,
    get_working_directory: *const c_void,
    set_working_directory: unsafe extern "system" fn(*mut c_void, PCWSTR) -> HRESULT,
    get_arguments: *const c_void,
    set_arguments: unsafe extern "system" fn(*mut c_void, PCWSTR) -> HRESULT,
    get_hotkey: *const c_void,
    set_hotkey: *const c_void,
    get_show_cmd: *const c_void,
    set_show_cmd: *const c_void,
    get_icon_location: *const c_void,
    set_icon_location: unsafe extern "system" fn(*mut c_void, PCWSTR, i32) -> HRESULT,
    set_relative_path: *const c_void,
    resolve: *const c_void,
    set_path: unsafe extern "system" fn(*mut c_void, PCWSTR) -> HRESULT,
}

#[repr(C)]
struct IPersistFileVtbl {
    query_interface: *const c_void,
    add_ref: *const c_void,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    get_class_id: *const c_void,
    is_dirty: *const c_void,
    load: *const c_void,
    save: unsafe extern "system" fn(*mut c_void, PCWSTR, BOOL) -> HRESULT,
    save_completed: *const c_void,
    get_cur_file: *const c_void,
}

/// A COM pointer that releases itself. Every early return below is a failure path, and each one
/// would otherwise leak an interface reference into a process that outlives it.
struct Com(*mut c_void, unsafe extern "system" fn(*mut c_void) -> u32);

impl Drop for Com {
    fn drop(&mut self) {
        unsafe { (self.1)(self.0) };
    }
}

/// Writes `lnk` pointing at `target`, replacing whatever was there.
///
/// The icon is taken from the target's own resource (`build.rs` puts one there), so the shortcut
/// cannot end up pointing at an icon file that a later version moves or a partial uninstall
/// leaves behind.
///
/// **`description` is stored in the machine's ANSI code page, not Unicode, and that is the shell's
/// doing rather than ours.** Measured: a shortcut written by Windows' own `WScript.Shell` on an
/// ACP-1252 machine loses Cyrillic from this field in exactly the same way, character for
/// character. It is kept in Russian anyway — on the ru-RU machines this ships to, ACP 1251 carries
/// it correctly, and the field is a hover tooltip. The link *target* is unaffected: it is
/// `%ProgramFiles%\DNS-AI\dns-ai.exe`, which is ASCII on every Windows regardless of language,
/// because that folder is only localised for display.
pub fn create(lnk: &Path, target: &Path, description: &str) -> Result<()> {
    com::ensure();

    let target_w = wide(target.as_os_str());
    let workdir_w = wide(target.parent().unwrap_or(Path::new("")).as_os_str());
    let desc_w = wide(OsStr::new(description));
    let lnk_w = wide(lnk.as_os_str());

    unsafe {
        let mut raw: *mut c_void = std::ptr::null_mut();
        let hr = CoCreateInstance(
            &ShellLink,
            std::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_ISHELLLINKW,
            &mut raw,
        );
        if hr < 0 || raw.is_null() {
            bail!("не удалось создать объект ярлыка (COM 0x{hr:08x})");
        }
        let vtbl = *(raw as *const *const IShellLinkWVtbl);
        let link = Com(raw, (*vtbl).release);

        check("SetPath", ((*vtbl).set_path)(link.0, target_w.as_ptr()))?;
        check(
            "SetWorkingDirectory",
            ((*vtbl).set_working_directory)(link.0, workdir_w.as_ptr()),
        )?;
        check(
            "SetDescription",
            ((*vtbl).set_description)(link.0, desc_w.as_ptr()),
        )?;
        // No arguments: bare invocation is what shows the window. `--tray` is the logon form and
        // belongs only in the Run key (`autostart.rs`) — a Start-menu entry that starts something
        // invisible is indistinguishable from one that is broken.
        let no_args = wide(OsStr::new(""));
        check(
            "SetArguments",
            ((*vtbl).set_arguments)(link.0, no_args.as_ptr()),
        )?;
        check(
            "SetIconLocation",
            ((*vtbl).set_icon_location)(link.0, target_w.as_ptr(), 0),
        )?;

        let mut file_raw: *mut c_void = std::ptr::null_mut();
        check(
            "QueryInterface(IPersistFile)",
            ((*vtbl).query_interface)(link.0, &IID_IPERSISTFILE, &mut file_raw),
        )?;
        if file_raw.is_null() {
            bail!("оболочка вернула пустой IPersistFile");
        }
        let file_vtbl = *(file_raw as *const *const IPersistFileVtbl);
        let file = Com(file_raw, (*file_vtbl).release);

        // `fRemember = 0`: do not adopt this path as the object's current file. We save once and
        // drop the object, so remembering it only creates state nobody reads.
        check("Save", ((*file_vtbl).save)(file.0, lnk_w.as_ptr(), 0))?;
    }
    Ok(())
}

fn check(what: &str, hr: HRESULT) -> Result<()> {
    if hr < 0 {
        bail!("{what} не удался (COM 0x{hr:08x})");
    }
    Ok(())
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vtable layouts above are the one thing in this program that fails as an access
    /// violation rather than as an error, so they get a test that actually calls through them.
    ///
    /// It writes a real shortcut to a real path, because there is no way to check a hand-written
    /// vtable except by using it: a wrong slot would either crash here or produce a file the shell
    /// cannot read. The file is left behind on purpose — `%TEMP%\dns-ai-shell-link-test\probe.lnk`
    /// is where to look when this passes and a shortcut still misbehaves on a real machine.
    #[test]
    fn writes_a_shortcut_through_the_hand_written_vtables() {
        let dir = std::env::temp_dir().join("dns-ai-shell-link-test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let lnk = dir.join("probe.lnk");
        let _ = std::fs::remove_file(&lnk);

        // The test binary itself: a file that certainly exists, so the shell has something real
        // to record a link-target reference for.
        let target = std::env::current_exe().expect("current exe");
        create(&lnk, &target, "DNS-AI — проверка").expect("the shell accepted every property");

        let written = std::fs::metadata(&lnk).expect("the shortcut was saved");
        assert!(
            written.len() > 100,
            "a shortcut this small is not a serialised link: {} bytes",
            written.len()
        );
    }
}
