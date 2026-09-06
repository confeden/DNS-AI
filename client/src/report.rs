//! What an elevated verb leaves behind for the window that asked for it.
//!
//! Without this the window would only ever learn an exit code, and "не удалось (код 1)" is not a
//! diagnosis — the useful sentence is the one the command-line version prints, "не удалось создать
//! службу (возможно, она уже установлена)". So the elevated child writes what it would have
//! printed, and the window reads it back.
//!
//! **The nonce is the whole freshness mechanism, and it has to be.** The file lives in
//! `%ProgramData%\DNS-AI`, which is `Users: RX`: the elevated child can write it, and the
//! unelevated window cannot — not to forge one, which is the point, but also not to delete a stale
//! one before it asks. So the window generates a nonce, passes it on the command line, and refuses
//! any report that does not carry it back. A file left by an earlier click, or by a run that
//! crashed before finishing, is then simply invisible rather than being mistaken for this answer.

use serde::{Deserialize, Serialize};

use dns_ai_core::paths;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionReport {
    /// Echoed from the command line. See the module note: this is what makes the file trustworthy
    /// as an answer to *this* click.
    pub nonce: String,
    /// Which verb ran, for the window's heading.
    pub verb: String,
    pub ok: bool,
    /// Everything the command-line form of the verb would have printed.
    pub lines: Vec<String>,
    /// Present when the verb failed, in the words the user needs to read.
    pub error: Option<String>,
}

impl ActionReport {
    pub fn from_outcome(verb: &str, nonce: &str, outcome: &anyhow::Result<Vec<String>>) -> Self {
        match outcome {
            Ok(lines) => Self {
                nonce: nonce.to_string(),
                verb: verb.to_string(),
                ok: true,
                lines: lines.clone(),
                error: None,
            },
            Err(e) => Self {
                nonce: nonce.to_string(),
                verb: verb.to_string(),
                ok: false,
                lines: Vec::new(),
                // `{:#}` so the whole `anyhow` context chain survives: the outermost message alone
                // is usually the least specific half of the explanation.
                error: Some(format!("{e:#}")),
            },
        }
    }

    /// Best effort by design. This runs at the very end of a verb that has already done its work,
    /// so a failure to write the report must not turn a successful install into a failed one; the
    /// window falls back to the exit code and says so.
    pub fn save(&self) {
        // The folder may not exist yet — on a first install nothing of ours has ever run. We are
        // the elevated half, so we are also the half that can create it with the right DACL.
        if let Err(e) = paths::ensure_data_dir() {
            eprintln!("предупреждение: не удалось подготовить папку данных: {e:#}");
            return;
        }
        match serde_json::to_vec_pretty(self) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(paths::last_action_file(), bytes) {
                    eprintln!("предупреждение: не удалось записать отчёт: {e}");
                }
            }
            Err(e) => eprintln!("предупреждение: не удалось сериализовать отчёт: {e}"),
        }
    }

    /// Reads the report for `nonce`, or nothing at all. Any failure — missing file, unreadable,
    /// unparseable, wrong nonce — is the same answer: there is no report for this click.
    pub fn load(nonce: &str) -> Option<Self> {
        let bytes = std::fs::read(paths::last_action_file()).ok()?;
        let report: Self = serde_json::from_slice(&bytes).ok()?;
        (report.nonce == nonce).then_some(report)
    }
}

/// A value that differs between clicks. It is a freshness token, not a secret — nothing is
/// authorised by it — so the clock and the process id are enough, and pulling in a random-number
/// dependency for it would be dressing up what it does.
pub fn new_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}-{:x}", std::process::id(), nanos)
}
