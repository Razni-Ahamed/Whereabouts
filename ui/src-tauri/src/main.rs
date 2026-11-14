//! Whereabouts desktop app: shows what the Whereabouts service sees.
//!
//! It reads data only from the service's local pipe (checked to really be
//! the Whereabouts service before anything is sent) and makes no network
//! requests of its own. The web view can call exactly two read-only
//! commands, `live` and `history` (see `build.rs`).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::{Arc, Mutex, PoisonError};

use serde::Serialize;
use whereabouts_client::{Client, Problem, unexpected};
use whereabouts_ipc::{
    AppTotals, FlowView, MAX_HOURS, MAX_ROWS, PIPE_NAME, Request, Response, Status,
};

/// The service's status and current flows.
#[derive(Debug, Serialize)]
struct Live {
    version: String,
    status: Status,
    flows: Vec<FlowView>,
}

/// One connection to the service, reused between requests and opened again
/// after it is lost (for example when the service restarts).
#[derive(Debug, Default)]
struct Connection(Mutex<Option<Client>>);

impl Connection {
    /// Runs `ask` with a connected client: the open one if it still works,
    /// otherwise a newly connected one.
    fn with<T>(&self, ask: impl Fn(&mut Client) -> Result<T, Problem>) -> Result<T, Problem> {
        let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(client) = slot.as_mut() {
            if let Ok(value) = ask(client) {
                return Ok(value);
            }
            *slot = None;
        }
        let mut client = Client::connect(PIPE_NAME)?;
        let value = ask(&mut client)?;
        *slot = Some(client);
        Ok(value)
    }
}

/// Runs blocking pipe work off the UI thread.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, Problem> + Send + 'static,
) -> Result<T, Problem> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|e| Problem::other(format!("Internal error: {e}")))?
}

#[tauri::command]
async fn live(limit: u32, connection: tauri::State<'_, Arc<Connection>>) -> Result<Live, Problem> {
    let connection = Arc::clone(&connection);
    let limit = limit.min(MAX_ROWS);
    blocking(move || {
        connection.with(|client| {
            let mut status = match client.ask(&Request::Status {})? {
                Response::Status(status) => status,
                other => return Err(unexpected(&other)),
            };
            // The service (SYSTEM) may be allowed what ordinary programs are
            // not; check again from this app's ordinary account.
            status.kernel_events_protected =
                whereabouts_client::kernel_events_protected(status.kernel_events_protected);
            let flows = match client.ask(&Request::LiveFlows { limit })? {
                Response::LiveFlows { flows } => flows,
                other => return Err(unexpected(&other)),
            };
            Ok(Live {
                version: client.version().to_owned(),
                status,
                flows,
            })
        })
    })
    .await
}

#[tauri::command]
async fn history(
    hours: u32,
    limit: u32,
    connection: tauri::State<'_, Arc<Connection>>,
) -> Result<Vec<AppTotals>, Problem> {
    let connection = Arc::clone(&connection);
    let (hours, limit) = (hours.min(MAX_HOURS), limit.min(MAX_ROWS));
    blocking(move || {
        connection.with(
            |client| match client.ask(&Request::History { hours, limit })? {
                Response::History { apps } => Ok(apps),
                other => Err(unexpected(&other)),
            },
        )
    })
    .await
}

fn main() {
    tauri::Builder::default()
        .manage(Arc::new(Connection::default()))
        .invoke_handler(tauri::generate_handler![live, history])
        .run(tauri::generate_context!())
        .expect("failed to start the Whereabouts app");
}
