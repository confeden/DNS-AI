//! Shared logic for the DNS-AI Windows client.
//!
//! The split is deliberate: every function that MUTATES system state lives here and is called
//! only by the service (`dns-ai-svc`). The tray UI never touches adapters, the registry or the
//! backup file — it asks the service over a named pipe. Two writers of the same state is how a
//! machine ends up in a shape nobody can explain (see `infra/client/windows/README.md` §4.8).

pub mod backup;
pub mod config;
pub mod dnsmsg;
pub mod ipc;
pub mod logging;
pub mod netif;
pub mod paths;
#[cfg(feature = "stub")]
pub mod stub;

pub use config::{Settings, RESOLVER_HOST, RESOLVER_IPS};
