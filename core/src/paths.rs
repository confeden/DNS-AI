//! The one folder the client owns — normally `config\<этот компьютер>` beside the executable.
//!
//! **The program is portable.** One file is handed to a user, they run it from wherever they put
//! it, and everything it remembers goes into a `config` folder next to it. Nothing is written to
//! `%ProgramFiles%`, and `%ProgramData%` is only a fallback for the case where the executable is
//! sitting somewhere it cannot write.
//!
//! **Per machine, and that is not tidiness.** The same folder can travel — a USB stick moved
//! between two computers is the ordinary case — and `dns-backup.json` holds the DNS configuration
//! of *one* machine. Restoring the other computer's adapters from it would be a fault the user
//! could not undo, so each computer gets its own subfolder named after it and never reads the
//! other's.

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use anyhow::{Context, Result};

use crate::netif::no_window;

/// Decided once per process. Every caller has to agree — the service and the window are two
/// processes reading the same files — and re-deciding it per call would also mean touching the
/// disk on every path lookup.
static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn data_dir() -> PathBuf {
    DATA_DIR.get_or_init(choose_data_dir).clone()
}

/// True when the files live beside the executable rather than under `%ProgramData%`.
pub fn is_portable() -> bool {
    portable_dir().is_some_and(|p| p == data_dir())
}

fn choose_data_dir() -> PathBuf {
    if let Some(dir) = portable_dir() {
        // Writability is the whole question, and it is answered by trying rather than by reasoning
        // about the path: a USB stick, a network share and `%ProgramFiles%` all look alike from
        // here and behave differently. A user who put the program where they cannot write gets the
        // shared folder instead of an error they can do nothing about.
        if std::fs::create_dir_all(&dir).is_ok() && writable(&dir) {
            return dir;
        }
    }
    program_data_dir()
}

fn portable_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    // An installed copy is never portable, and this check is what keeps the two halves of the
    // program from disagreeing about where the files are. `%ProgramFiles%` is writable by SYSTEM
    // and not by the user, so "can I create the folder?" alone would answer yes for the service and
    // no for the window — and they would then read different settings and different backups.
    if in_program_files(dir) {
        return None;
    }
    Some(dir.join("config").join(machine_folder()))
}

fn in_program_files(dir: &Path) -> bool {
    ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .filter_map(std::env::var_os)
        .any(|base| {
            dir.to_string_lossy()
                .to_lowercase()
                .starts_with(&base.to_string_lossy().to_lowercase())
        })
}

fn program_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("DNS-AI")
}

fn writable(dir: &Path) -> bool {
    let probe = dir.join(".write-test");
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// This computer's name, reduced to something that is safe as a folder name.
///
/// The name rather than a machine GUID because a person opening the `config` folder should be able
/// to tell whose settings are whose. Two machines with the same name sharing one stick would share
/// a folder; that is a stranger situation than this program needs to solve.
fn machine_folder() -> String {
    let raw = computer_name().unwrap_or_default();
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "this-pc".to_string()
    } else {
        cleaned
    }
}

/// `%COMPUTERNAME%`, which Windows puts in every process environment — a service's included.
///
/// `GetComputerNameW` would be the API answer and lives in `Win32::System::WindowsProgramming`,
/// a whole `windows-sys` feature to pull in for a string the environment already carries.
fn computer_name() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}

pub fn settings_file() -> PathBuf {
    data_dir().join("settings.json")
}

/// The record of what the machine's DNS looked like before we touched it. One file, rewritten
/// after every mutating step: what the revert can undo is exactly what reached the disk.
pub fn backup_file() -> PathBuf {
    data_dir().join("dns-backup.json")
}

pub fn service_log() -> PathBuf {
    data_dir().join("service.log")
}

/// Where an elevated run of this program leaves the outcome of an install or an uninstall, for the
/// unelevated window that asked for it to read back.
///
/// The path is FIXED, not passed on the command line. Handing an administrator process a
/// caller-chosen path to write is the standard shape of a local privilege-escalation bug, and the
/// window doing the asking is deliberately unelevated. This directory is `Users: RX` (see
/// [`ensure_data_dir`]), so a standard user cannot plant a forged report here either — which is
/// what makes the file worth reading at all. Freshness is a separate problem and is solved by the
/// nonce inside: nothing here can delete the file, because the reader has no write access to the
/// folder it lives in.
pub fn last_action_file() -> PathBuf {
    data_dir().join("last-action.json")
}

/// Creates the folder if it is missing and gives it an explicit DACL — **every time**, not only
/// when it creates it.
///
/// The permissions are explicit because the service reads privileged input out of this folder:
/// the backup file drives adapter reconfiguration. Inheritance is removed so a permissive ACE on
/// `%ProgramData%` cannot make it user-writable. Well-known SIDs, never names — `Administrators`
/// and `Users` are localised, and this ships to Russian-language machines.
///
/// The early return this used to have on `dir.exists()` was the whole guarantee, silently. On the
/// first machine it ran against, `C:\ProgramData\DNS-AI` had been created weeks earlier by the
/// PowerShell installer, so the folder simply kept `%ProgramData%`'s inherited ACL — including
/// `Users: Write` — and the service never noticed. A folder somebody else can pre-create with
/// permissions of their choosing is the standard opening move against a SYSTEM service that reads
/// files from a fixed path, so re-asserting the DACL is cheap insurance against a hole we cannot
/// see from inside.
pub fn ensure_data_dir() -> Result<()> {
    let dir = data_dir();

    // The hardened DACL below is for the SHARED folder only. Beside a portable executable it would
    // be both wrong and pointless: wrong, because the window runs as the user and has to be able to
    // write its own settings there, and `Users: RX` would stop it; pointless, because anybody who
    // can write that folder can replace `dns-ai.exe` in the folder above it, which is a great deal
    // more than editing a config file. The folder inherits whatever the user's own directory has.
    if is_portable() {
        if !dir.exists() {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
        }
        return Ok(());
    }

    // A reparse point here is not a configuration to fix, it is an attack, and the only safe
    // response is to refuse. `mklink /J` needs no privilege, so a standard user can leave a
    // junction at this path aiming anywhere on the disk; every write below — and, worse, the
    // uninstall's sweep of this folder — would then be performed by SYSTEM against somebody
    // else's directory. Nothing legitimate ever puts one here.
    if let Ok(meta) = std::fs::symlink_metadata(&dir) {
        if meta.file_type().is_symlink() {
            anyhow::bail!(
                "{} is a link rather than a real folder; refusing to use it",
                dir.display()
            );
        }
    }

    if !dir.exists() {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
    }

    // Three commands, and each one closes a hole the previous shape left open. Measured, not
    // reasoned about: with the old single `/grant` call, a `BUILTIN\Guests:(OI)(CI)F` ACE planted
    // on a pre-created folder survived verbatim and the pre-creating user stayed its owner.
    //
    //  1. `/setowner` — an owner has implicit `WRITE_DAC`, so whoever created the folder can put
    //     any DACL back at any time. Until ownership moves, everything after this is advisory.
    //  2. `/reset` — drops EVERY explicit ACE, including ones somebody else planted. `/grant`
    //     merges and `/grant:r` only replaces the principals it names, so neither can do this.
    //  3. `/inheritance:r` then `/grant:r` — turn the inherited ACEs into explicit ones and then
    //     replace them with exactly ours. Note `%ProgramData%` grants `Users` create rights by
    //     inheritance; without this step they would survive here.
    //
    // `/T` reaches files already inside, so a planted FILE cannot keep a permissive ACE of its
    // own. Well-known SIDs, never names — `Administrators` and `Users` are localised, and this
    // ships to Russian-language machines.
    let icacls = |args: &[&str]| -> Result<std::process::Output> {
        Command::new("icacls")
            .arg(&dir)
            .args(args)
            .creation_flags(no_window())
            .output()
            .context("cannot run icacls")
    };

    let steps: [(&str, Vec<&str>); 3] = [
        (
            "take ownership",
            vec!["/setowner", "*S-1-5-32-544", "/T", "/C"],
        ),
        ("drop planted ACEs", vec!["/reset", "/T", "/C"]),
        (
            "apply our DACL",
            vec![
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F", // LOCAL SYSTEM
                "/grant:r",
                "*S-1-5-32-544:(OI)(CI)F", // Administrators
                "/grant:r",
                "*S-1-5-32-545:(OI)(CI)RX", // Users — read + execute, never write
            ],
        ),
    ];

    for (what, args) in steps {
        let out = icacls(&args)?;
        if !out.status.success() {
            // Not fatal on its own — the service still has to run — but it must be loud: an
            // unexpected DACL here is exactly the condition that makes the backup file
            // untrustworthy, and the backup drives adapter reconfiguration.
            log::warn!(
                "icacls could not {what} on {} (exit {:?}): {}",
                dir.display(),
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }
    Ok(())
}
