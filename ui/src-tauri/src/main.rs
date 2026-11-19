//! Whereabouts desktop app: shows what the Whereabouts service sees.
//!
//! It reads data only from the service's local pipe (checked to really be
//! the Whereabouts service before anything is sent) and makes no network
//! requests of its own. The web view can call exactly these commands (see
//! `build.rs`): `live`, `history` and `rules` read data; `export_history`
//! and `delete_history` take no arguments from the web view and ask the
//! user through native Windows dialogs (where to save; whether to delete);
//! `add_rule` shows what will be blocked in a native Windows dialog and
//! blocks only if the user agrees; `remove_rule` and `set_blocking_paused`
//! lift blocks (the safe direction).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod background;
mod settings;

use std::fs::File;
use std::io::{BufWriter, Seek, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use settings::{AppState, SettingsFile};
use tauri::{Manager, RunEvent};
use whereabouts_win_startup::BACKGROUND_ARG;

use serde::Serialize;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use whereabouts_client::{Client, Problem, unexpected};
use whereabouts_core::text::display_safe;
use whereabouts_ipc::{
    AppTotals, DELETE_ALL_CONFIRMATION, EXPORT_PAGE_ROWS, FlowView, MAX_HOURS, MAX_ROWS, PIPE_NAME,
    Request, Response, RuleSpec, RuleView, Status,
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

/// The blocking rules and whether blocking is paused.
#[derive(Debug, Serialize)]
struct Rules {
    rules: Vec<RuleView>,
    paused: bool,
}

/// Asks the service and expects the rule list back.
fn ask_rules(client: &mut Client, request: &Request) -> Result<Rules, Problem> {
    match client.ask(request)? {
        Response::Rules { rules, paused } => Ok(Rules { rules, paused }),
        other => Err(unexpected(&other)),
    }
}

#[tauri::command]
async fn rules(connection: tauri::State<'_, Arc<Connection>>) -> Result<Rules, Problem> {
    let connection = Arc::clone(&connection);
    blocking(move || connection.with(|client| ask_rules(client, &Request::ListRules {}))).await
}

/// A program's file name, for people.
fn program_name(path: &str) -> String {
    display_safe(
        &Path::new(path)
            .file_name()
            .map_or_else(|| path.to_owned(), |n| n.to_string_lossy().into_owned()),
    )
}

/// What the confirmation dialog says for `rule`: its title and text.
fn describe(rule: &RuleSpec) -> (String, String) {
    const DOMAIN_NOTE: &str = "Whereabouts blocks the addresses Windows' DNS service confirms \
                               for it, so a connection that is already starting may still get \
                               through once.";
    const EVERY_APP_NOTE: &str = "This applies to every app on this computer. Whereabouts never \
                                  blocks addresses that other, unblocked sites also use, nor what \
                                  Windows needs to stay online.";
    let undo = "You can unblock it at any time on the Rules screen.";
    match rule {
        RuleSpec::App { path } => (
            format!("Block {}?", program_name(path)),
            format!(
                "Every connection {} makes will be blocked, until you unblock it.\n\n{}\n\n{undo}",
                program_name(path),
                display_safe(path)
            ),
        ),
        RuleSpec::Domain {
            name,
            app: Some(app),
        } => (
            format!("Block {} for {}?", display_safe(name), program_name(app)),
            format!(
                "{} will not be able to connect to {} or its subdomains.\n\n{}\n\n{DOMAIN_NOTE}\n\n\
                 {undo}",
                program_name(app),
                display_safe(name),
                display_safe(app)
            ),
        ),
        RuleSpec::Domain { name, app: None } => (
            format!("Block {} for every app?", display_safe(name)),
            format!(
                "No app will be able to connect to {} or its subdomains.\n\n{EVERY_APP_NOTE}\n\n\
                 {DOMAIN_NOTE}\n\n{undo}",
                display_safe(name)
            ),
        ),
        RuleSpec::Address { ip, app: Some(app) } => (
            format!("Block {ip} for {}?", program_name(app)),
            format!(
                "{} will not be able to connect to {ip}.\n\n{}\n\nOther sites can share this \
                 address, so this may block more than one site for this app.\n\n{undo}",
                program_name(app),
                display_safe(app)
            ),
        ),
        RuleSpec::Address { ip, app: None } => (
            format!("Block {ip} for every app?"),
            format!(
                "No app will be able to connect to {ip}.\n\nOther sites can share this address, \
                 so this may block more than one site for every app.\n\n{undo}"
            ),
        ),
    }
}

/// Shows exactly what will be blocked in a native Windows dialog and, if
/// the user agrees, asks the service to block it. `None` if the user said
/// no; otherwise the rule's ID.
#[tauri::command]
async fn add_rule(
    rule: RuleSpec,
    app: tauri::AppHandle,
    connection: tauri::State<'_, Arc<Connection>>,
) -> Result<Option<i64>, Problem> {
    let connection = Arc::clone(&connection);
    blocking(move || {
        let (title, message) = describe(&rule);
        let confirmed = app
            .dialog()
            .message(message)
            .title(title)
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(
                String::from("Block"),
                String::from("Cancel"),
            ))
            .blocking_show();
        if !confirmed {
            return Ok(None);
        }
        let request = Request::AddRule { rule };
        connection.with(|client| match client.ask(&request)? {
            Response::RuleAdded { id } => Ok(Some(id)),
            other => Err(unexpected(&other)),
        })
    })
    .await
}

/// Deletes a rule and lifts its block.
#[tauri::command]
async fn remove_rule(
    id: i64,
    connection: tauri::State<'_, Arc<Connection>>,
) -> Result<Rules, Problem> {
    let connection = Arc::clone(&connection);
    blocking(move || connection.with(|client| ask_rules(client, &Request::RemoveRule { id }))).await
}

/// Pauses (lifts every block, keeps the rules) or resumes blocking.
#[tauri::command]
async fn set_blocking_paused(
    paused: bool,
    connection: tauri::State<'_, Arc<Connection>>,
) -> Result<Rules, Problem> {
    let connection = Arc::clone(&connection);
    blocking(move || {
        connection.with(|client| ask_rules(client, &Request::SetBlockingPaused { paused }))
    })
    .await
}

/// Saved alerts of the last `hours`, newest first.
#[tauri::command]
async fn alerts(
    hours: u32,
    limit: u32,
    connection: tauri::State<'_, Arc<Connection>>,
) -> Result<Vec<whereabouts_ipc::AlertView>, Problem> {
    let connection = Arc::clone(&connection);
    let (hours, limit) = (hours.min(MAX_HOURS), limit.min(MAX_ROWS));
    blocking(move || {
        connection.with(
            |client| match client.ask(&Request::Alerts { hours, limit })? {
                Response::Alerts { alerts } => Ok(alerts),
                other => Err(unexpected(&other)),
            },
        )
    })
    .await
}

/// Marks an alert as seen and fine; with `allow`, alerts like it stop.
/// Stopping alerts about a risky network is confirmed in a native Windows
/// dialog first, so the web view cannot silence them on its own. `false` if
/// the user said no.
#[tauri::command]
async fn dismiss_alert(
    id: i64,
    allow: bool,
    app: tauri::AppHandle,
    connection: tauri::State<'_, Arc<Connection>>,
) -> Result<bool, Problem> {
    let connection = Arc::clone(&connection);
    blocking(move || {
        if allow {
            let alert = connection.with(|client| {
                match client.ask(&Request::Alerts {
                    hours: MAX_HOURS,
                    limit: MAX_ROWS,
                })? {
                    Response::Alerts { alerts } => Ok(alerts.into_iter().find(|a| a.id == id)),
                    other => Err(unexpected(&other)),
                }
            })?;
            let Some(alert) = alert else {
                return Err(Problem::other("That alert no longer exists."));
            };
            if alert.severity >= whereabouts_ipc::Severity::High {
                let program = alert
                    .path
                    .as_deref()
                    .or(alert.app.as_deref())
                    .map_or_else(|| String::from("this app"), display_safe);
                let target = alert
                    .detail
                    .as_deref()
                    .or(alert.target.as_deref())
                    .map_or_else(|| String::from("this network"), display_safe);
                let confirmed = app
                    .dialog()
                    .message(format!(
                        "Whereabouts will no longer warn you when this program connects to this \
                         network:\n\n{program}\n{target}\n\nOnly do this if you trust both."
                    ))
                    .title("Stop these warnings?")
                    .kind(MessageDialogKind::Warning)
                    .buttons(MessageDialogButtons::OkCancelCustom(
                        String::from("Stop these warnings"),
                        String::from("Cancel"),
                    ))
                    .blocking_show();
                if !confirmed {
                    return Ok(false);
                }
            }
        }
        connection.with(
            |client| match client.ask(&Request::DismissAlert { id, allow })? {
                Response::AlertDismissed {} => Ok(true),
                other => Err(unexpected(&other)),
            },
        )
    })
    .await
}

/// The app's settings, as the window shows them.
#[derive(Debug, Serialize)]
struct SettingsView {
    /// Whether Windows starts the app in the tray at sign-in.
    start_at_sign_in: bool,
    /// Whether starting at sign-in can be changed (only for the installed
    /// app, not a developer build).
    can_start_at_sign_in: bool,
    notifications: bool,
    show_names: bool,
    first_run_done: bool,
}

/// The installed app's program file, if this is it.
fn installed_exe() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = whereabouts_client::install_dir().ok()?;
    let installed = dir.join(whereabouts_client::APP_PROGRAM);
    whereabouts_win_capture::identity::same_file(&exe, &installed).then_some(installed)
}

fn settings_view(state: &AppState) -> SettingsView {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let exe = installed_exe();
    SettingsView {
        start_at_sign_in: exe
            .as_deref()
            .is_some_and(|exe| whereabouts_win_startup::is_enabled(exe).unwrap_or(false)),
        can_start_at_sign_in: exe.is_some(),
        notifications: settings.notifications,
        show_names: settings.show_names,
        first_run_done: settings.first_run_done,
    }
}

#[tauri::command]
fn get_settings(state: tauri::State<'_, AppState>) -> SettingsView {
    settings_view(&state)
}

/// Saves the user's choices (and marks the first-run question answered).
#[tauri::command]
fn set_settings(
    start_at_sign_in: bool,
    notifications: bool,
    show_names: bool,
    state: tauri::State<'_, AppState>,
) -> Result<SettingsView, Problem> {
    match (installed_exe(), start_at_sign_in) {
        (Some(exe), true) => whereabouts_win_startup::enable(&exe),
        (_, false) => whereabouts_win_startup::disable(),
        (None, true) => {
            return Err(Problem::other(
                "Starting at sign-in works for the installed app only.",
            ));
        }
    }
    .map_err(|e| Problem::other(format!("Could not change starting at sign-in ({e}).")))?;
    let saved = {
        let mut settings = state
            .settings
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        settings.notifications = notifications;
        settings.show_names = show_names;
        settings.first_run_done = true;
        settings.clone()
    };
    state
        .file
        .save(&saved)
        .map_err(|e| Problem::other(format!("Could not save the settings ({e}).")))?;
    Ok(settings_view(&state))
}

/// Whether closing the window should leave the app running in the tray.
fn keeps_running(app: &tauri::AppHandle) -> bool {
    let state = app.state::<AppState>();
    state.background
        || installed_exe()
            .is_some_and(|exe| whereabouts_win_startup::is_enabled(&exe).unwrap_or(false))
}

fn main() {
    tauri::Builder::default()
        // First, so a second start only brings the running app forward.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if !args.iter().any(|arg| arg == BACKGROUND_ARG) {
                background::show_main(app);
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(Arc::new(Connection::default()))
        .setup(|app| {
            let background_start = std::env::args().any(|arg| arg == BACKGROUND_ARG);
            let file = SettingsFile::in_dir(&app.path().app_config_dir()?);
            let settings = file.load();
            app.manage(AppState {
                file,
                settings: Mutex::new(settings),
                background: background_start,
            });
            background::create_tray(app.handle())?;
            if !background_start {
                background::show_main(app.handle());
            }
            background::start_checker(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            live,
            history,
            export_history,
            delete_history,
            rules,
            add_rule,
            remove_rule,
            set_blocking_paused,
            get_settings,
            set_settings,
            alerts,
            dismiss_alert
        ])
        .build(tauri::generate_context!())
        .expect("failed to start the Whereabouts app")
        .run(|app, event| {
            // The last window closed: stay in the tray if the user chose to
            // run in the background; otherwise quit.
            if let RunEvent::ExitRequested {
                code: None, api, ..
            } = event
                && keeps_running(app)
            {
                api.prevent_exit();
                let state = app.state::<AppState>();
                let first_time = {
                    let mut settings = state
                        .settings
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    let first = !settings.tray_hint_shown;
                    settings.tray_hint_shown = true;
                    first.then(|| settings.clone())
                };
                if let Some(settings) = first_time {
                    let _ = state.file.save(&settings);
                    background::notify(
                        app,
                        "Whereabouts is still in the tray",
                        "It keeps an eye on your connections. Open it from the tray icon, or \
                         close it from the icon's menu.",
                    );
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmations_say_exactly_what_is_blocked() {
        let app = String::from(r"C:\Apps\Chat\chat.exe");
        let (title, text) = describe(&RuleSpec::App { path: app.clone() });
        assert_eq!(title, "Block chat.exe?");
        assert!(text.contains(&app));

        let (title, text) = describe(&RuleSpec::Domain {
            name: String::from("ads.example.com"),
            app: None,
        });
        assert_eq!(title, "Block ads.example.com for every app?");
        assert!(text.contains("every app on this computer"));

        // Rules for one app always show that app's full path, so two
        // programs with the same name cannot be confused.
        let (title, text) = describe(&RuleSpec::Address {
            ip: "203.0.113.5".parse().unwrap(),
            app: Some(app.clone()),
        });
        assert_eq!(title, "Block 203.0.113.5 for chat.exe?");
        assert!(text.contains(&app));
        let (_, text) = describe(&RuleSpec::Domain {
            name: String::from("ads.example.com"),
            app: Some(app.clone()),
        });
        assert!(text.contains(&app));
    }

    #[test]
    fn confirmations_cannot_be_spoofed_with_control_characters() {
        let (title, _) = describe(&RuleSpec::Domain {
            name: String::from("evil.example\u{202e}moc.knab"),
            app: None,
        });
        assert!(!title.contains('\u{202e}'), "{title:?}");
    }
}
