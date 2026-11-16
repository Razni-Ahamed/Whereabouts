//! Whereabouts desktop app: shows what the Whereabouts service sees.
//!
//! It reads data only from the service's local pipe (checked to really be
//! the Whereabouts service before anything is sent) and makes no network
//! requests of its own. The web view can call exactly four commands (see
//! `build.rs`): `live` and `history` read data; `export_history` and
//! `delete_history` take no arguments from the web view and ask the user
//! through native Windows dialogs (where to save; whether to delete).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::File;
use std::io::{BufWriter, Seek, Write};
use std::sync::{Arc, Mutex, PoisonError};

use serde::Serialize;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use whereabouts_client::{Client, Problem, unexpected};
use whereabouts_ipc::{
    AppTotals, DELETE_ALL_CONFIRMATION, EXPORT_PAGE_ROWS, FlowView, MAX_HOURS, MAX_ROWS, PIPE_NAME,
    Request, Response, Status,
};

/// The service's status and current flows.
#[derive(Debug, Serialize)]
struct Live {
    version: String,
    status: Status,
    flows: Vec<FlowView>,
    /// Process IDs that are Whereabouts (this app, its WebView2 helpers and
    /// the service), so the Privacy screen counts all of their connections.
    own_pids: Vec<u32>,
}

/// One connection to the service, reused between requests and opened again
/// after it is lost (for example when the service restarts).
#[derive(Debug, Default)]
struct Connection(Mutex<Option<Client>>);

impl Connection {
    /// Runs `ask` with a connected client: the open one if it still works,
    /// otherwise a newly connected one.
    fn with<T>(
        &self,
        mut ask: impl FnMut(&mut Client) -> Result<T, Problem>,
    ) -> Result<T, Problem> {
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
                own_pids: whereabouts_client::own_process_ids(),
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

/// Where an export was saved.
#[derive(Debug, Serialize)]
struct Exported {
    path: String,
    rows: u64,
}

/// Asks where to save, then writes all saved flows there as CSV, page by
/// page. `None` if the user cancelled.
#[tauri::command]
async fn export_history(
    app: tauri::AppHandle,
    connection: tauri::State<'_, Arc<Connection>>,
) -> Result<Option<Exported>, Problem> {
    let connection = Arc::clone(&connection);
    blocking(move || {
        let Some(choice) = app
            .dialog()
            .file()
            .set_title("Export Whereabouts history")
            .set_file_name("whereabouts-history.csv")
            .add_filter("CSV file", &["csv"])
            .blocking_save_file()
        else {
            return Ok(None);
        };
        let path = choice
            .into_path()
            .map_err(|e| Problem::other(format!("Cannot save there ({e}).")))?;
        let file = File::create(&path)
            .map_err(|e| Problem::other(format!("Could not create {} ({e}).", path.display())))?;
        let mut out = BufWriter::new(file);
        let io = |e: std::io::Error| Problem::other(format!("Could not write the export ({e})."));
        let rows = connection.with(|client| {
            // Start again from the top if a lost connection is retried.
            out.rewind().map_err(io)?;
            out.get_ref().set_len(0).map_err(io)?;
            let mut after = 0;
            let mut rows = 0;
            loop {
                let request = Request::ExportPage {
                    after,
                    limit: EXPORT_PAGE_ROWS,
                };
                match client.ask(&request)? {
                    Response::ExportPage {
                        header,
                        csv,
                        rows: page_rows,
                        last,
                    } => {
                        if let Some(header) = header {
                            writeln!(out, "{header}").map_err(io)?;
                        }
                        out.write_all(csv.as_bytes()).map_err(io)?;
                        rows += page_rows;
                        match last {
                            Some(last) => after = last,
                            None => return Ok(rows),
                        }
                    }
                    other => return Err(unexpected(&other)),
                }
            }
        })?;
        out.flush().map_err(io)?;
        Ok(Some(Exported {
            path: path.display().to_string(),
            rows,
        }))
    })
    .await
}

/// Asks the user, in a native Windows dialog, whether to delete all saved
/// data, and if they agree asks the service to do it. `false` if the user
/// said no.
#[tauri::command]
async fn delete_history(
    app: tauri::AppHandle,
    connection: tauri::State<'_, Arc<Connection>>,
) -> Result<bool, Problem> {
    let connection = Arc::clone(&connection);
    blocking(move || {
        let confirmed = app
            .dialog()
            .message(
                "All saved connection history and hourly totals will be deleted and overwritten. \
                 This cannot be undone.\n\nWhereabouts keeps recording new connections afterwards.",
            )
            .title("Delete everything Whereabouts saved?")
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(
                String::from("Delete everything"),
                String::from("Cancel"),
            ))
            .blocking_show();
        if !confirmed {
            return Ok(false);
        }
        connection.with(|client| {
            let request = Request::DeleteAll {
                confirm: String::from(DELETE_ALL_CONFIRMATION),
            };
            match client.ask(&request)? {
                Response::Deleted {} => Ok(true),
                other => Err(unexpected(&other)),
            }
        })
    })
    .await
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(Connection::default()))
        .invoke_handler(tauri::generate_handler![
            live,
            history,
            export_history,
            delete_history
        ])
        .run(tauri::generate_context!())
        .expect("failed to start the Whereabouts app");
}
