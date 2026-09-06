//! A file logger, deliberately hand-rolled.
//!
//! A Windows service has no console, so without a file there is nothing to read after a failed
//! start — and "nothing to read" is how the first VM session gets wasted. Local time comes from
//! `GetLocalTime` so the log lines match what the operator sees in Event Viewer.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use log::{Level, LevelFilter, Metadata, Record};
use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

/// Roll at 2 MB. One file, one rename: enough to survive a debugging session, small enough to
/// paste into a support ticket.
const MAX_BYTES: u64 = 2 * 1024 * 1024;

struct Logger {
    file: Option<Mutex<File>>,
    stderr: bool,
}

impl log::Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        m.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} {:<5} {}: {}\r\n",
            now(),
            record.level(),
            record.target(),
            record.args()
        );
        if self.stderr {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
        if let Some(f) = &self.file {
            if let Ok(mut f) = f.lock() {
                let _ = f.write_all(line.as_bytes());
                let _ = f.flush();
            }
        }
    }

    fn flush(&self) {}
}

fn now() -> String {
    // SAFETY: GetLocalTime only writes into the struct we hand it.
    let st: SYSTEMTIME = unsafe {
        let mut st = std::mem::zeroed();
        GetLocalTime(&mut st);
        st
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
    )
}

/// Installs the global logger. Failing to open the log file is not fatal — a service that
/// refuses to run because it cannot write a log is worse than one that runs silently.
pub fn init(path: &Path, stderr: bool) {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_BYTES {
            let _ = std::fs::rename(path, path.with_extension("log.1"));
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
        .map(Mutex::new);

    let logger = Box::leak(Box::new(Logger { file, stderr }));
    let _ = log::set_logger(logger);
    log::set_max_level(LevelFilter::Debug);
}
