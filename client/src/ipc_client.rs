//! Talking to the service. Blocking on purpose — it runs on a worker thread, never on the UI one.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

use anyhow::{Context, Result};
use dns_ai_core::ipc::{Request, Response, PIPE_NAME};

/// All pipe instances busy. The service creates a fresh instance after each accept, so this is a
/// race with another client, not a wall — worth a short retry.
const ERROR_PIPE_BUSY: i32 = 231;

pub fn request(req: &Request) -> Result<Response> {
    let mut pipe = open_pipe()?;

    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    pipe.write_all(&line)
        .context("не удалось отправить запрос службе")?;
    pipe.flush()?;

    let mut reader = BufReader::new(pipe);
    let mut text = String::new();
    reader.read_line(&mut text).context("служба не ответила")?;

    serde_json::from_str(text.trim()).context("не удалось разобрать ответ службы")
}

fn open_pipe() -> Result<std::fs::File> {
    let mut last = None;
    for _ in 0..10 {
        match OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
            Ok(f) => return Ok(f),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                std::thread::sleep(Duration::from_millis(50));
                last = Some(e);
            }
            Err(e) => {
                // Names no command on purpose. This text is the one the window shows when the
                // pipe is unreachable, and directly underneath it the setup screen offers the
                // button that fits the machine's actual state — which is not always an install.
                // It used to advise `dns-ai-svc.exe install`, a file that stopped existing when
                // the two binaries became one.
                return Err(e).context("служба DNS-AI не отвечает");
            }
        }
    }
    Err(last.unwrap()).context("служба занята")
}
