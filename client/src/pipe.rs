//! The named-pipe server the tray talks to.

use std::ffi::c_void;
use std::iter::once;
use std::ptr::null_mut;
use std::sync::Arc;

use anyhow::{bail, Result};
use dns_ai_core::ipc::{Request, Response, PIPE_NAME, PIPE_SDDL};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{watch, Mutex};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

use crate::app::App;

/// A security descriptor that lives for the life of the process. Wrapped because a raw pointer
/// is not `Send`, and this one is only ever read.
struct Descriptor(*mut c_void);
unsafe impl Send for Descriptor {}
unsafe impl Sync for Descriptor {}

fn build_descriptor() -> Result<Descriptor> {
    let sddl: Vec<u16> = PIPE_SDDL.encode_utf16().chain(once(0)).collect();
    let mut psd: *mut c_void = null_mut();
    // SAFETY: `sddl` is NUL-terminated and outlives the call; `psd` receives an allocation the
    // process keeps until it exits.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            null_mut(),
        )
    };
    if ok == 0 {
        bail!(
            "could not parse the pipe security descriptor: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(Descriptor(psd))
}

fn create_pipe(sd: &Descriptor, first: bool) -> Result<NamedPipeServer> {
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: `attrs` outlives the call, and the descriptor it points at outlives the process.
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            // The tray is a local UI. Nothing about this protocol should be reachable from
            // another machine.
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                PIPE_NAME,
                &mut attrs as *mut SECURITY_ATTRIBUTES as *mut c_void,
            )?
    };
    Ok(server)
}

pub async fn serve(app: Arc<Mutex<App>>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let sd = build_descriptor()?;
    let mut first = true;

    loop {
        let server = create_pipe(&sd, first)?;
        first = false;

        tokio::select! {
            _ = shutdown.changed() => break,
            r = server.connect() => {
                if let Err(e) = r {
                    log::warn!("pipe connect failed: {e}");
                    continue;
                }
            }
        }

        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(server, app).await {
                log::debug!("pipe session ended: {e:#}");
            }
        });
    }
    log::info!("pipe server stopped");
    Ok(())
}

async fn handle(server: NamedPipeServer, app: Arc<Mutex<App>>) -> Result<()> {
    let mut reader = BufReader::new(server);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let response = match serde_json::from_str::<Request>(line.trim()) {
        Ok(req) => {
            log::debug!("request: {req:?}");
            dispatch(req, &app).await
        }
        Err(e) => Response::err(format!("некорректный запрос: {e}")),
    };

    let mut out = serde_json::to_vec(&response)?;
    out.push(b'\n');

    let mut server = reader.into_inner();
    server.write_all(&out).await?;
    server.flush().await?;
    // Let the client finish reading before the handle drops.
    let _ = server.disconnect();
    Ok(())
}

/// What a request means, once, for both halves of the program.
///
/// The service calls this from its pipe listener; the local backend calls it directly with its own
/// `App` (`backend.rs`). One implementation, so "включить" cannot come to mean two different things
/// depending on which of them is running.
pub async fn dispatch(req: Request, app: &Arc<Mutex<App>>) -> Response {
    let mut guard = app.lock().await;
    let result = match req {
        Request::Status => Ok(()),
        Request::Enable => guard.enable().await,
        Request::Disable => guard.disable().await,
        Request::SetSettings { settings } => guard.set_settings(settings).await,
    };
    match result {
        Ok(()) => Response::ok(guard.status()),
        Err(e) => {
            log::error!("{req_err:#}", req_err = e);
            // The status still goes back on failure: the UI has to show what the machine looks
            // like *now*, which after a failed enable is the most important thing on screen.
            Response {
                ok: false,
                error: Some(format!("{e:#}")),
                status: Some(guard.status()),
            }
        }
    }
}
