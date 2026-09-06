//! Where the program lives on the machine, and how it gets there and away again.
//!
//! Until this module existed, `dns-ai.exe` was a loose file: whoever ran it registered a service
//! pointing at wherever it happened to be sitting. That is fine exactly once. Move the file, empty
//! the Downloads folder, or let a browser save the next version beside the first, and the service
//! points at a path that no longer holds a program — a state the machine cannot recover from on
//! its own, because the thing that would repair it is the file that is gone. The setup screen then
//! offers «Запустить службу» forever and it never starts.
//!
//! So the program now has an address: `%ProgramFiles%\DNS-AI\dns-ai.exe`. Everything else here
//! follows from that one decision — the copy that puts it there, the Start-menu entry and the
//! "Apps & features" row that point at it, and the removal that takes all three away.
//!
//! **Per-machine, not per-user, and that is not a preference.** The thing being installed is a
//! LocalSystem service; a per-user layout under `%LOCALAPPDATA%` would still need administrator
//! rights for the service and would buy nothing but a second place to look.
//!
//! **`%ProgramFiles%` needs no DACL of its own** — unlike `%ProgramData%\DNS-AI`, which the
//! service hardens at every start because a standard user can pre-create it
//! (`core/src/paths.rs`). This folder inherits an ACL that already denies non-administrators
//! write access, and re-asserting one here would only add a way to get it wrong.

use std::ffi::{c_void, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateMutexW, GetCurrentProcess, OpenEventW, OpenProcessToken, SetEvent,
    WaitForSingleObject, EVENT_MODIFY_STATE, INFINITE,
};
use windows_sys::Win32::UI::Shell::{FOLDERID_CommonPrograms, SHGetKnownFolderPath};
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

use crate::shell_link;

/// The folder name under `%ProgramFiles%`, the Start-menu entry and the "Apps & features" row all
/// carry the product name; only the executable is lower-case, because a command line has to type it.
const FOLDER: &str = "DNS-AI";
const EXE: &str = "dns-ai.exe";
const SHORTCUT: &str = "DNS-AI.lnk";

/// Windows' own list of installed programs. The key name is ours to choose and is never shown; the
/// values inside it are.
const ARP_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DNS-AI";

pub const DISPLAY_NAME: &str = "DNS-AI — защищённый DNS";

pub fn install_dir() -> PathBuf {
    // `ProgramFiles` is per-architecture: a 32-bit process reads it as `Program Files (x86)`. This
    // binary is built for x86_64, so the variable and the intent agree; a 32-bit build would need
    // `ProgramW6432` instead.
    let base = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    base.join(FOLDER)
}

pub fn install_exe() -> PathBuf {
    install_dir().join(EXE)
}

// `CoTaskMemFree`, declared against `ole32` rather than taken from `windows-sys`.
//
// This one declaration is the difference between a binary that starts on Windows 7 and one that
// does not. `windows-sys` links the function against `combase.dll`, which is where Windows 8 moved
// COM's allocator — and a Windows 7 machine has no such file, so the loader refuses the whole
// program before `main` runs, with an error naming a DLL nobody has heard of. `ole32.dll` has
// exported it since COM existed and forwards to combase on newer Windows, so this is the spelling
// that works on every version. Visible only in the import table (`dumpbin /imports`), which is why
// the Windows 7 build is checked there rather than by reading the source.
#[link(name = "ole32")]
extern "system" {
    fn CoTaskMemFree(pv: *const c_void);
}

/// The all-users Start menu, asked for rather than assembled.
///
/// `%ProgramData%\Microsoft\Windows\Start Menu\Programs` is the answer on every machine anyone is
/// likely to see, and it is still the wrong thing to hard-code: the folder is relocatable, and a
/// known-folder id is the only supported way to ask where it went.
pub fn shortcut_path() -> Result<PathBuf> {
    unsafe {
        let mut raw: *mut u16 = std::ptr::null_mut();
        let hr = SHGetKnownFolderPath(&FOLDERID_CommonPrograms, 0, std::ptr::null_mut(), &mut raw);
        if hr < 0 || raw.is_null() {
            bail!("не удалось определить папку меню «Пуск» (COM 0x{hr:08x})");
        }
        let mut len = 0usize;
        while *raw.add(len) != 0 {
            len += 1;
        }
        let dir = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(raw, len)));
        CoTaskMemFree(raw as *const c_void);
        Ok(dir.join(SHORTCUT))
    }
}

/// Where the running image is, relative to where the program belongs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// This process is the installed copy. The ordinary case once setup has run.
    Installed,
    /// An installed copy exists and this is not it — a downloaded file run a second time, or a
    /// newer build about to replace an older one.
    Elsewhere { installed: PathBuf },
    /// Nothing is installed. First run.
    NotInstalled,
}

/// Two stat calls and a string compare, so the window can ask without elevation and without a
/// round trip to the service.
pub fn placement() -> Placement {
    let installed = install_exe();
    let current = std::env::current_exe().unwrap_or_default();
    if same_file(&current, &installed) {
        return Placement::Installed;
    }
    if installed.is_file() {
        Placement::Elsewhere { installed }
    } else {
        Placement::NotInstalled
    }
}

/// Whether two paths name the same file.
///
/// `canonicalize` is the honest answer — it resolves `..`, short names and symlinks — but it fails
/// on a path that does not exist, which is the common case here. So it is tried first and a
/// case-insensitive comparison is the fallback, Windows paths not being case-sensitive.
fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a.as_os_str().eq_ignore_ascii_case(b.as_os_str()),
    }
}

/// Whether this process is running with administrator rights.
///
/// Needed because "Apps & features" runs `UninstallString` with the caller's ordinary token, so
/// the `remove` verb has to notice and ask for elevation itself rather than failing at the first
/// call into the service manager.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut info = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut info as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && info.TokenIsElevated != 0
    }
}

/// What [`ensure_installed`] did.
pub struct Placed {
    /// Where the program now is — the path the service must be registered against.
    pub exe: PathBuf,
    /// Whether a file was written. False when we were already the installed copy.
    pub copied: bool,
    pub warnings: Vec<String>,
}

/// Puts this executable at [`install_exe`], replacing an older one if necessary.
///
/// **Precondition: the service is already stopped.** A running service holds its own image open,
/// and the rename below would then have to move a file that Windows is executing — which works,
/// but leaves a service running code that is no longer at the path it is registered against.
///
/// The replacement is rename-aside-then-copy, not overwrite. A running image cannot be *written*
/// to, but it can be *renamed* within the same volume: the loader keeps its handle to the same
/// file under its new name, and the old name comes free for the new file. That is what makes it
/// possible to upgrade while the tray from the previous version is still on screen — and it is the
/// one assumption in this module that only a real machine can confirm.
pub fn ensure_installed() -> Result<Placed> {
    let src = std::env::current_exe().context("не удалось определить путь к собственному файлу")?;
    let dst = install_exe();
    let mut warnings = Vec::new();

    if same_file(&src, &dst) {
        return Ok(Placed {
            exe: dst,
            copied: false,
            warnings,
        });
    }

    let dir = install_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("не удалось создать {}", dir.display()))?;

    // The outgoing file is moved aside but NOT destroyed until the new one is in place. Deleting
    // it first would mean a failed copy leaves `%ProgramFiles%\DNS-AI` with no program in it at
    // all, while the Start-menu shortcut and the "Apps & features" row still point there — worse
    // than the stale registration this whole module exists to prevent.
    let mut moved_aside = None;
    if dst.exists() {
        match aside_path(&dir) {
            // A rename failure is not fatal: the old file may simply be a leftover nobody is
            // running, in which case the copy below overwrites it and nothing was lost.
            Some(aside) => match std::fs::rename(&dst, &aside) {
                Ok(()) => moved_aside = Some(aside),
                Err(e) => warnings.push(format!("не удалось отодвинуть прежний файл: {e}")),
            },
            None => warnings.push("не нашлось свободного имени для прежнего файла".into()),
        }
    }

    if let Err(e) = std::fs::copy(&src, &dst) {
        // Put it back. A machine that was working before this attempt is working after it.
        if let Some(aside) = &moved_aside {
            if std::fs::rename(aside, &dst).is_err() {
                warnings.push(format!(
                    "прежняя версия осталась под именем {}",
                    aside.display()
                ));
            }
        }
        return Err(e).with_context(|| {
            format!(
                "не удалось скопировать программу в {} (файл занят?)",
                dst.display()
            )
        });
    }

    if let Some(aside) = moved_aside {
        if !delete_now_or_at_reboot(&aside) {
            warnings.push(format!(
                "предыдущая версия ещё выполняется и исчезнет после перезагрузки: {}",
                aside.display()
            ));
        }
    }

    Ok(Placed {
        exe: dst,
        copied: true,
        warnings,
    })
}

/// A free name to move the outgoing executable to.
///
/// Bounded rather than unique: a machine that has ten undeletable old copies has a problem this
/// function is not going to solve, and an unbounded search would just fill the folder.
fn aside_path(dir: &Path) -> Option<PathBuf> {
    for n in 0..10 {
        let name = if n == 0 {
            format!("{EXE}.old")
        } else {
            format!("{EXE}.old{n}")
        };
        let candidate = dir.join(name);
        if !candidate.exists() || std::fs::remove_file(&candidate).is_ok() {
            return Some(candidate);
        }
    }
    None
}

// =================================================================================================
// The two places Windows keeps a list of programs
// =================================================================================================

/// The "Apps & features" row: what it says, and what it runs when the user clicks Uninstall.
pub fn write_arp_entry(exe: &Path) -> Result<()> {
    let (key, _) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .create_subkey(ARP_KEY)
        .context("не удалось создать запись в списке программ")?;

    let quoted = format!("\"{}\"", exe.display());
    key.set_value("DisplayName", &DISPLAY_NAME.to_string())?;
    key.set_value("DisplayVersion", &env!("CARGO_PKG_VERSION").to_string())?;
    key.set_value("Publisher", &"Brent".to_string())?;
    key.set_value("URLInfoAbout", &"https://dns-ai.ru".to_string())?;
    // Windows shows this as the row's "Support" link. It is the group rather than the site on
    // purpose: somebody opening the uninstall list has a problem, and the site cannot answer back.
    key.set_value("HelpLink", &"https://t.me/nova_txt".to_string())?;
    key.set_value("InstallLocation", &install_dir().display().to_string())?;
    // `,0` names the first icon in the executable's resources — the one `build.rs` puts there.
    key.set_value("DisplayIcon", &format!("{},0", exe.display()))?;
    key.set_value("UninstallString", &format!("{quoted} remove"))?;
    key.set_value("QuietUninstallString", &format!("{quoted} remove --quiet"))?;
    // Neither modify nor repair exists, so saying so keeps Windows from offering buttons that
    // would run the uninstaller with arguments it does not understand.
    key.set_value("NoModify", &1u32)?;
    key.set_value("NoRepair", &1u32)?;
    if let Ok(meta) = std::fs::metadata(exe) {
        // Windows wants kilobytes, and shows the value as-is.
        key.set_value("EstimatedSize", &((meta.len() / 1024) as u32))?;
    }
    Ok(())
}

pub fn remove_arp_entry() -> Result<()> {
    match RegKey::predef(HKEY_LOCAL_MACHINE).delete_subkey_all(ARP_KEY) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("не удалось удалить запись из списка программ"),
    }
}

pub fn write_shortcut(exe: &Path) -> Result<()> {
    let path = shortcut_path()?;
    shell_link::create(&path, exe, DISPLAY_NAME)
}

pub fn remove_shortcut() -> Result<()> {
    let path = shortcut_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("не удалось удалить {}", path.display())),
    }
}

// =================================================================================================
// Taking it away
// =================================================================================================

/// Deletes `path`, or asks Windows to do it at the next boot. Returns whether it went immediately.
///
/// The reboot fallback is what makes an uninstaller able to remove its own executable. Copying
/// ourselves into `%TEMP%` and re-running from there is the alternative and is what commercial
/// installers do; it is also — a self-copy into a temporary folder that then deletes a service and
/// a Program Files directory — an excellent impression of malware, and this program is already
/// fighting SmartScreen without help.
pub fn delete_now_or_at_reboot(path: &Path) -> bool {
    if !path.exists() {
        return true;
    }
    if std::fs::remove_file(path).is_ok() {
        return true;
    }
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // A null destination means "delete". Needs administrator rights, which every caller has.
    unsafe { MoveFileExW(wide.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) != 0 }
}

/// Puts `path` — a file or a directory — on Windows' pending-rename list, without trying to delete
/// it now.
///
/// Distinct from [`delete_now_or_at_reboot`] and the distinction is load-bearing: the report the
/// window is waiting to read must survive until the window has read it, and "try to delete it
/// first" would take it away immediately, since nothing is holding it open.
fn schedule_delete_at_reboot(path: &Path) {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe { MoveFileExW(wide.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
}

/// Removes `%ProgramFiles%\DNS-AI`, including the executable that is running this code.
///
/// Files first, then the folder. Both may end up on the pending-rename list, and Windows works
/// through that list in order — a folder scheduled before its contents is a folder that is still
/// not empty when the boot loader reaches it.
///
/// **A busy file is renamed aside before it is scheduled, and that is not tidiness.** Windows'
/// pending-rename list is keyed by PATH, with no check that the file it finds at boot is the one
/// that was queued, and nothing ever takes an entry off it. Scheduling
/// `%ProgramFiles%\DNS-AI\dns-ai.exe` — the canonical path, the one a reinstall writes to — means
/// that a user who uninstalls, changes their mind, reinstalls, and only then reboots loses the
/// executable at that boot, silently, leaving a registered service with no image and a machine
/// that has to be repaired by hand. Scheduling a unique aside name instead leaves the canonical
/// path free the moment this function returns.
fn remove_program_files() -> Vec<String> {
    let mut out = Vec::new();
    let dir = install_dir();
    if !dir.exists() {
        return out;
    }

    // Collected before anything is touched. The loop renames files inside this very directory,
    // and a live enumeration that sees its own renames can hand back the same file twice under
    // two names.
    let entries: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries.flatten().map(|e| e.path()).collect(),
        Err(_) => Vec::new(),
    };

    let mut deferred = false;
    for path in entries {
        if std::fs::remove_file(&path).is_ok() {
            continue;
        }
        // Busy — almost always this very executable. Move it out of the way, under a name nothing
        // is ever installed to, and queue THAT.
        let queued = match aside_path(&dir) {
            Some(aside) if std::fs::rename(&path, &aside).is_ok() => aside,
            _ => path,
        };
        schedule_delete_at_reboot(&queued);
        deferred = true;
    }
    if std::fs::remove_dir(&dir).is_err() {
        // Left non-empty by the aside file above. Scheduling the folder is still right: at the
        // next boot its contents go first and the folder follows. If a reinstall has meanwhile
        // put a program back in it, the folder is not empty at that point and the queued removal
        // simply fails — which is the outcome we want.
        schedule_delete_at_reboot(&dir);
        deferred = true;
    }
    if deferred {
        out.push("Файл программы сейчас выполняется — он исчезнет после перезагрузки.".into());
    } else {
        out.push("Файлы программы удалены.".into());
    }
    out
}

/// Removes the contents of `%ProgramData%\DNS-AI`, except the report the window is about to read.
///
/// **The folder survives one specific failure on purpose.** If `dns-backup.json` is still there,
/// the machine's previous DNS settings were never restored, and deleting the folder would destroy
/// the only record of what they were. In every other case everything goes, the log included: a log
/// for a program that is no longer installed is litter, and the one situation where it would have
/// been worth keeping is exactly the one that keeps it.
fn remove_data_files() -> Vec<String> {
    let mut out = Vec::new();
    let data = dns_ai_core::paths::data_dir();
    if !data.exists() {
        return out;
    }
    // Checked again here, not only in `ensure_data_dir`, because this is the dangerous half: an
    // administrator deleting every file in a folder that a standard user replaced with a junction
    // is an arbitrary-file-delete, and `mklink /J` needs no privilege at all. `symlink_metadata`
    // does not follow the reparse point, which is the whole reason it is the one used.
    match std::fs::symlink_metadata(&data) {
        Ok(meta) if meta.file_type().is_symlink() => {
            out.push(format!(
                "{} — это ссылка, а не папка; ничего в ней не тронуто.",
                data.display()
            ));
            return out;
        }
        Ok(_) => {}
        Err(_) => return out,
    }
    if dns_ai_core::backup::DnsBackup::exists() {
        out.push(format!(
            "Резервная копия настроек DNS осталась — папка {} сохранена.",
            data.display()
        ));
        return out;
    }
    let keep = dns_ai_core::paths::last_action_file();
    if let Ok(entries) = std::fs::read_dir(&data) {
        for entry in entries.flatten() {
            if entry.path() != keep {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    out
}

/// The last step, and it has to be the last one: the window reads its report out of this folder.
///
/// Called from `main.rs` *after* the report has been written, so what is left — the report itself
/// and the empty folder — goes at the next boot instead of now. Deleting the folder here would
/// leave the window with an uninstall that says «отчёт не записан» after doing everything right.
pub fn schedule_data_dir_removal() {
    if dns_ai_core::backup::DnsBackup::exists() {
        return;
    }
    let data = dns_ai_core::paths::data_dir();
    if !data.exists() {
        return;
    }
    // Same reason as in `remove_data_files`: a queued delete against a junction's target is still
    // a delete against somebody else's directory, it just happens at the next boot.
    if std::fs::symlink_metadata(&data).is_ok_and(|m| m.file_type().is_symlink()) {
        return;
    }
    // Scheduled, never deleted now: nothing is holding the report open, so "try it immediately"
    // would succeed and the window would be left reading a file that had just been taken away —
    // reporting «отчёт не записан» after an uninstall that did everything right.
    //
    // Order matters. Windows works through the pending-rename list top to bottom, and a directory
    // scheduled before its contents is a directory that is still not empty when its turn comes.
    schedule_delete_at_reboot(&dns_ai_core::paths::last_action_file());
    schedule_delete_at_reboot(&data);
}

// =================================================================================================
// The two verbs
// =================================================================================================

/// Installs the program: file, Start-menu entry, "Apps & features" row, service.
///
/// The order is the design. The service is stopped before its image is touched; the shell entries
/// are written before the service is registered, so a machine that fails at the last step still
/// has a program that can be uninstalled through Windows rather than an orphaned folder in
/// `%ProgramFiles%`; and the service is registered against the path a file was actually written
/// to — never against a path we merely intended to write.
pub fn install_program() -> Result<Vec<String>> {
    let mut out = Vec::new();

    // Only when the file has to be replaced. A repair run — the program is already where it
    // belongs and is only missing its Start-menu entry, or its service registration — has no
    // reason to interrupt anybody's DNS, and `change_config` needs no stop.
    let replacing = std::env::current_exe()
        .map(|src| !same_file(&src, &install_exe()))
        .unwrap_or(true);
    if replacing {
        out.extend(crate::service::stop_for_upgrade());
    }

    let placed = match ensure_installed() {
        Ok(p) => p,
        Err(e) => {
            // Not fatal. Registering the service where the executable already sits is what the
            // program did before there was an installer, and it works — it is only fragile.
            out.push(format!("Не удалось установить программу: {e:#}"));
            out.push("Служба будет зарегистрирована по текущему пути файла.".into());
            Placed {
                exe: std::env::current_exe()
                    .context("не удалось определить путь к собственному файлу")?,
                copied: false,
                warnings: Vec::new(),
            }
        }
    };
    out.extend(placed.warnings.iter().cloned());
    if placed.copied {
        out.push(format!("Программа установлена: {}", placed.exe.display()));
    }

    // Only when the file really is where it belongs. An "Apps & features" row pointing into a
    // Downloads folder is worse than no row at all: the button in it would stop working the
    // moment the user tidies up.
    if same_file(&placed.exe, &install_exe()) {
        match write_shortcut(&placed.exe) {
            Ok(()) => out.push("Ярлык в меню «Пуск» создан.".into()),
            Err(e) => out.push(format!("Предупреждение: ярлык не создан: {e:#}")),
        }
        if let Err(e) = write_arp_entry(&placed.exe) {
            out.push(format!(
                "Предупреждение: запись в списке программ не создана: {e:#}"
            ));
        }
    }

    out.extend(crate::service::install_at(&placed.exe)?);
    Ok(out)
}

/// Removes everything this program put on the machine, in the order that keeps DNS working.
///
/// `service::uninstall` comes first and does the part that matters: it stops the service, which
/// restores the adapters, and falls back to the backup file if the service never got to. Only
/// once the machine resolves names again do the files go.
pub fn remove_program() -> Result<Vec<String>> {
    let mut out = crate::service::uninstall()?;

    match remove_shortcut() {
        Ok(()) => {}
        Err(e) => out.push(format!("Предупреждение: {e:#}")),
    }
    if let Err(e) = remove_arp_entry() {
        out.push(format!("Предупреждение: {e:#}"));
    }
    out.extend(remove_data_files());
    out.extend(remove_program_files());
    out.push("DNS-AI удалён.".into());
    Ok(out)
}

// =================================================================================================
// One window, not several
// =================================================================================================

/// The name of the mutex that says "a window is already open", and of the event that asks it to
/// come to the front. `Local\` — per session, because two users logged in at once should each get
/// their own window, and only the service is machine-wide.
const INSTANCE_MUTEX: &str = r"Local\DNS-AI-tray-instance";
pub const SHOW_EVENT: &str = r"Local\DNS-AI-tray-show";

/// Held for the life of the process — or until [`release_instance`] hands the role over.
struct InstanceLock(HANDLE);

// The handle is only ever closed, by whichever thread empties the static below.
unsafe impl Send for InstanceLock {}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Kept here rather than threaded through the UI, because exactly one thing in the program cares
/// about it and it has to be released from deep inside a button handler.
static INSTANCE: std::sync::Mutex<Option<InstanceLock>> = std::sync::Mutex::new(None);

/// The other half of [`claim_instance`]: an auto-reset event the running window waits on, so a
/// second launch can bring it forward instead of opening anything.
pub struct ShowSignal(HANDLE);

// Waited on by one dedicated thread and signalled from another process; the handle itself is
// never shared between our own threads except by moving it once.
unsafe impl Send for ShowSignal {}

impl ShowSignal {
    /// Created by the instance that won the mutex, before it starts drawing.
    pub fn create() -> Option<Self> {
        let name = wide(SHOW_EVENT);
        // Auto-reset, initially clear: each signal wakes exactly one wait, which is all there is.
        let handle = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) };
        (!handle.is_null()).then_some(Self(handle))
    }

    /// Blocks until somebody asks for the window. `false` means the wait itself failed and the
    /// caller should stop trying rather than spin.
    pub fn wait(&self) -> bool {
        const WAIT_OBJECT_0: u32 = 0;
        unsafe { WaitForSingleObject(self.0, INFINITE) == WAIT_OBJECT_0 }
    }
}

impl Drop for ShowSignal {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Asks the running window to show itself. Best effort: if there is no event, there is no window
/// to ask, and the caller is about to exit anyway.
pub fn signal_show() {
    let name = wide(SHOW_EVENT);
    unsafe {
        let handle = OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr());
        if !handle.is_null() {
            SetEvent(handle);
            CloseHandle(handle);
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Claims the right to be *the* window, or reports that somebody else already has it.
///
/// This mattered little while the program was one loose file that people double-clicked once. It
/// matters now: there is a Start-menu entry, a Run key and a tray icon, and clicking the first of
/// them while the other two have already done their work would otherwise put a second icon in the
/// notification area, polling the same service and disagreeing with the first one about what it
/// says.
pub fn claim_instance() -> bool {
    let name = wide(INSTANCE_MUTEX);
    let lock = unsafe {
        let handle = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
        if handle.is_null() {
            // Cannot tell. Better a second window than none: the guard is a convenience, and
            // refusing to start on a question we could not ask would trade it for a defect.
            InstanceLock(std::ptr::null_mut())
        } else if windows_sys::Win32::Foundation::GetLastError() == ERROR_ALREADY_EXISTS {
            CloseHandle(handle);
            return false;
        } else {
            InstanceLock(handle)
        }
    };
    if let Ok(mut slot) = INSTANCE.lock() {
        *slot = Some(lock);
    }
    true
}

/// Gives up the claim on "being the window", so a replacement can take it.
///
/// One caller: the hand-over to an elevated copy of ourselves. It has to let go *before* spawning,
/// or the new process finds the mutex still held by a program that is about to exit, decides a
/// window already exists, and quietly does nothing.
pub fn release_instance() {
    if let Ok(mut slot) = INSTANCE.lock() {
        slot.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything here runs without administrator rights, which is the point: these are the parts
    /// of the installer that can be checked at all without a UAC prompt and a real machine.
    #[test]
    fn the_install_location_is_a_real_place() {
        let dir = install_dir();
        assert!(
            dir.parent().is_some_and(|p| p.is_dir()),
            "the parent of {} should exist on any Windows",
            dir.display()
        );
        assert_eq!(dir.file_name().unwrap(), FOLDER);
        assert_eq!(install_exe().file_name().unwrap(), EXE);
    }

    /// `SHGetKnownFolderPath` is asked rather than the path being assembled, so this checks that
    /// the answer is a folder that exists — a wrong known-folder id would still return a string.
    #[test]
    fn the_start_menu_is_found_by_asking_windows() {
        let lnk = shortcut_path().expect("the common Programs folder");
        assert_eq!(lnk.file_name().unwrap(), SHORTCUT);
        let dir = lnk.parent().expect("a parent");
        assert!(dir.is_dir(), "{} should be a real folder", dir.display());
        // Not asserted as an exact string — the folder is relocatable, which is why it is asked
        // for — but on any ordinary machine it is the all-users Start menu.
        assert!(
            dir.to_string_lossy().contains("Start Menu"),
            "unexpected Programs folder: {}",
            dir.display()
        );
    }

    /// A test binary is never `%ProgramFiles%\DNS-AI\dns-ai.exe`, so this must never say it is —
    /// the answer that would make the window hide the install button on a machine with nothing
    /// installed.
    #[test]
    fn a_test_binary_is_not_the_installed_copy() {
        assert_ne!(placement(), Placement::Installed);
    }

    #[test]
    fn same_file_ignores_case_when_neither_path_exists() {
        assert!(same_file(
            Path::new(r"C:\Program Files\DNS-AI\dns-ai.exe"),
            Path::new(r"c:\program files\dns-ai\DNS-AI.EXE")
        ));
        assert!(!same_file(
            Path::new(r"C:\Program Files\DNS-AI\dns-ai.exe"),
            Path::new(r"C:\Users\someone\Downloads\dns-ai.exe")
        ));
    }

    /// The rename-aside dance reuses `dns-ai.exe.old` when it can be deleted, and steps to a
    /// numbered name when it cannot. Only the first half is testable without a locked file.
    #[test]
    fn the_aside_name_is_reused_once_the_old_file_can_go() {
        let dir = std::env::temp_dir().join("dns-ai-aside-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");

        assert_eq!(aside_path(&dir), Some(dir.join(format!("{EXE}.old"))));

        std::fs::write(dir.join(format!("{EXE}.old")), b"previous version").expect("write");
        assert_eq!(
            aside_path(&dir),
            Some(dir.join(format!("{EXE}.old"))),
            "a deletable leftover should be removed and its name reused"
        );
        assert!(!dir.join(format!("{EXE}.old")).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Not an assertion about the answer — a test runner may be elevated or not. It asserts the
    /// call is safe, which is the part that is written in `unsafe`.
    #[test]
    fn the_elevation_check_answers_without_crashing() {
        let _ = is_elevated();
    }
}
