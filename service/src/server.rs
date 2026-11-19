//! Local pipe server: answers requests from Whereabouts clients, such as
//! `--status` now and the desktop app later (design spec §5.8).
//!
//! Who may connect:
//! - The pipe's permissions allow only SYSTEM, Administrators and the
//!   account running Whereabouts, from this computer only.
//! - The program on the other end must be Whereabouts itself: the file it
//!   runs must be the same file as ours, or another program installed next
//!   to ours in the protected installation folder (the desktop app); see
//!   [`peer::is_trusted_client`]. Other programs are disconnected before
//!   anything is read from them.
//!
//! Clients can only send the typed requests of `whereabouts-ipc`, and every
//! request's limits are clamped before it is answered.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use whereabouts_client::peer;
use whereabouts_ipc::{
    AppTotals, DELETE_ALL_CONFIRMATION, EXPORT_PAGE_BYTES, FlowView, MAX_NOTICES, Notice,
    NoticeKind, PROTOCOL_VERSION, Request, Response, Status, read_message, write_message,
};
use whereabouts_store::{Store, csv_header};
use whereabouts_win_pipe::{PipeConnection, PipeListener, current_user_sid};

/// Most clients served at the same time.
const MAX_CLIENTS: usize = 4;

/// How long a client waits for the engine to delete everything.
const DELETE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a client waits for the engine to change the blocking rules.
const RULES_TIMEOUT: Duration = Duration::from_secs(30);

/// Work only the engine can do, asked for by a client.
#[derive(Debug)]
pub enum EngineCommand {
    /// Delete all saved data, including finished flows not saved yet, and
    /// send back the result.
    DeleteAll {
        /// Where to send the result.
        reply: Sender<Result<(), String>>,
    },
    /// Load the offline data again (a data update was installed).
    ReloadData,
    /// Load Spamhaus DROP again (downloaded or removed).
    ReloadDrop,
    /// List or change the blocking rules, and send back the answer.
    Rules {
        /// What to do.
        command: crate::blocking::RuleCommand,
        /// Where to send the answer.
        reply: Sender<Response>,
    },
}

/// What the engine publishes for clients after each refresh.
#[derive(Debug, Default)]
pub struct LiveState {
    /// Counters and health.
    pub status: Status,
    /// Current flows, largest first, at most [`whereabouts_ipc::MAX_ROWS`].
    pub flows: Vec<FlowView>,
    /// Where to send [`EngineCommand`]s; `None` until the engine runs.
    pub commands: Option<Sender<EngineCommand>>,
    /// The newest notices, oldest first, at most [`MAX_NOTICES`].
    pub notices: VecDeque<Notice>,
    /// The ID of the newest notice (0 before the first).
    pub last_notice: u64,
    /// List updates, as the updater last saw them.
    pub lists: whereabouts_ipc::ListsView,
    /// Where to send the list updater commands; `None` until it runs.
    pub updates: Option<Sender<crate::updates::UpdaterCommand>>,
}

impl LiveState {
    /// Adds a notice for clients, dropping the oldest beyond the limit.
    pub fn push_notice(&mut self, kind: NoticeKind, at: SystemTime) {
        self.last_notice += 1;
        if self.notices.len() >= MAX_NOTICES {
            self.notices.pop_front();
        }
        self.notices.push_back(Notice {
            id: self.last_notice,
            at_secs: at
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            kind,
        });
    }
}

/// The live state shared between the engine and the pipe threads.
pub type SharedState = Arc<Mutex<LiveState>>;

/// Creates the pipe `name` and starts answering clients in the background.
/// `client_sid` is the account allowed to connect besides SYSTEM and
/// Administrators; `None` means the account running this process. Fails if
/// the pipe already exists (for example, Whereabouts is already running, or
/// another program took the name).
pub fn start(name: &str, client_sid: Option<&str>, state: SharedState) -> Result<(), String> {
    let sid = match client_sid {
        Some(sid) => sid.to_owned(),
        None => {
            current_user_sid().map_err(|e| format!("could not read the current account ({e})"))?
        }
    };
    let listener = PipeListener::bind(name, &sid).map_err(|e| {
        format!("could not create the pipe {name} ({e}); is Whereabouts already running?")
    })?;
    std::thread::Builder::new()
        .name(String::from("pipe-server"))
        .spawn(move || accept_loop(listener, &state))
        .map_err(|e| format!("could not start the pipe server ({e})"))?;
    Ok(())
}

/// Counts a client while it is being served, even if serving panics.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn accept_loop(mut listener: PipeListener, state: &SharedState) {
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let connection = match listener.accept() {
            Ok(connection) => connection,
            Err(error) => {
                report!("warning: pipe: {error}");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        // Dropping the connection disconnects the client.
        if !peer::is_trusted_client(connection.peer_pid(), connection.connected_by()) {
            continue;
        }
        // Only this thread adds clients, so the check cannot be raced past.
        if active.load(Ordering::Acquire) >= MAX_CLIENTS {
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let slot = Slot(Arc::clone(&active));
        let state = Arc::clone(state);
        // If the thread cannot start, the closure (and the slot) is dropped.
        let _ = std::thread::Builder::new()
            .name(String::from("pipe-client"))
            .spawn(move || {
                let _slot = slot;
                serve(connection, &state);
            });
    }
}

/// Answers one client until it disconnects or sends something invalid.
fn serve(mut connection: PipeConnection, state: &Mutex<LiveState>) {
    // The first message must be a Hello in our protocol version.
    match read_message::<Request>(&mut connection) {
        Ok(Request::Hello { protocol }) if protocol == PROTOCOL_VERSION => {}
        Ok(Request::Hello { protocol }) => {
            let _ = write_message(
                &mut connection,
                &Response::Error {
                    message: format!(
                        "protocol version {protocol} is not supported; this service speaks \
                         version {PROTOCOL_VERSION}"
                    ),
                },
            );
            return;
        }
        _ => return,
    }
    if write_message(&mut connection, &hello()).is_err() {
        return;
    }
    let mut store = None;
    while let Ok(request) = read_message::<Request>(&mut connection) {
        let response = answer(request.clamped(), state, &mut store);
        if write_message(&mut connection, &response).is_err() {
            return;
        }
    }
}

fn hello() -> Response {
    Response::Hello {
        protocol: PROTOCOL_VERSION,
        version: String::from(env!("CARGO_PKG_VERSION")),
    }
}

fn lock(state: &Mutex<LiveState>) -> MutexGuard<'_, LiveState> {
    // A panic elsewhere must not stop clients from being answered.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Answers one (already clamped) request. The store is opened the first
/// time saved data is asked for, and kept for the rest of the connection.
fn answer(request: Request, state: &Mutex<LiveState>, store: &mut Option<Store>) -> Response {
    match request {
        Request::Hello { .. } => hello(),
        Request::Status {} => {
            let state = lock(state);
            let mut status = state.status.clone();
            status.lists = state.lists.clone();
            Response::Status(status)
        }
        Request::SetListUpdates { data, drop } => match open_store(store) {
            Ok(store) => match crate::updates::set_switches(store, data, drop) {
                Ok(()) => {
                    let mut state = lock(state);
                    let checking = state.lists.checking;
                    state.lists = crate::updates::view(store);
                    state.lists.checking = checking;
                    if let Some(updates) = &state.updates {
                        let _ = updates.send(crate::updates::UpdaterCommand::SettingsChanged);
                    }
                    Response::Lists(state.lists.clone())
                }
                Err(message) => Response::Error {
                    message: format!("could not save the choice: {message}"),
                },
            },
            Err(response) => *response,
        },
        Request::CheckListsNow {} => {
            let mut state = lock(state);
            if let Some(updates) = &state.updates {
                let _ = updates.send(crate::updates::UpdaterCommand::CheckNow);
                state.lists.checking = true;
            }
            Response::Lists(state.lists.clone())
        }
        Request::LiveFlows { limit } => Response::LiveFlows {
            flows: lock(state)
                .flows
                .iter()
                .take(usize::try_from(limit).unwrap_or(usize::MAX))
                .cloned()
                .collect(),
        },
        Request::History { hours, limit } => match open_store(store) {
            Ok(store) => history(store, hours, limit),
            Err(response) => *response,
        },
        Request::ExportPage { after, limit } => match open_store(store) {
            Ok(store) => export_page(store, after, limit),
            Err(response) => *response,
        },
        Request::DeleteAll { confirm } => delete_all(state, &confirm),
        Request::ListRules {} => rules(state, crate::blocking::RuleCommand::List),
        Request::AddRule { rule } => rules(state, crate::blocking::RuleCommand::Add(rule)),
        Request::RemoveRule { id } => rules(state, crate::blocking::RuleCommand::Remove(id)),
        Request::SetBlockingPaused { paused } => {
            rules(state, crate::blocking::RuleCommand::SetPaused(paused))
        }
        Request::Alerts { hours, limit } => match open_store(store) {
            Ok(store) => alerts(store, hours, limit),
            Err(response) => *response,
        },
        Request::DismissAlert { id, allow } => match open_store(store) {
            Ok(store) => match store.dismiss_alert(id, allow, SystemTime::now()) {
                Ok(true) => Response::AlertDismissed {},
                Ok(false) => Response::Error {
                    message: format!("there is no alert {id}"),
                },
                Err(error) => Response::Error {
                    message: format!("could not change the alert: {error}"),
                },
            },
            Err(response) => *response,
        },
        Request::Notices { after } => {
            let state = lock(state);
            Response::Notices {
                notices: state
                    .notices
                    .iter()
                    .filter(|notice| notice.id > after)
                    .cloned()
                    .collect(),
                last: state.last_notice,
            }
        }
    }
}

/// Asks the engine to list or change the blocking rules, and waits for the
/// answer.
fn rules(state: &Mutex<LiveState>, command: crate::blocking::RuleCommand) -> Response {
    let Some(commands) = lock(state).commands.clone() else {
        return Response::Error {
            message: String::from("Whereabouts is still starting"),
        };
    };
    let (reply, answer) = mpsc::channel();
    if commands
        .send(EngineCommand::Rules { command, reply })
        .is_err()
    {
        return Response::Error {
            message: String::from("Whereabouts is stopping"),
        };
    }
    answer
        .recv_timeout(RULES_TIMEOUT)
        .unwrap_or_else(|_| Response::Error {
            message: String::from("Whereabouts did not answer in time"),
        })
}

/// The connection's store, opened on first use.
fn open_store(store: &mut Option<Store>) -> Result<&mut Store, Box<Response>> {
    if store.is_none() {
        let opened = crate::storage::open().map_err(|error| {
            Box::new(Response::Error {
                message: format!("history is not available: {error}"),
            })
        })?;
        *store = Some(opened);
    }
    store.as_mut().ok_or_else(|| {
        Box::new(Response::Error {
            message: String::from("history is not available"),
        })
    })
}

fn alerts(store: &Store, hours: u32, limit: u32) -> Response {
    let since = SystemTime::now()
        .checked_sub(Duration::from_secs(u64::from(hours) * 60 * 60))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    match store.alerts(since, usize::try_from(limit).unwrap_or(usize::MAX)) {
        Ok(alerts) => Response::Alerts {
            alerts: alerts.into_iter().map(crate::alerts::view).collect(),
        },
        Err(error) => Response::Error {
            message: format!("could not read the alerts: {error}"),
        },
    }
}

fn export_page(store: &Store, after: i64, limit: u32) -> Response {
    let rows = usize::try_from(limit).unwrap_or(usize::MAX);
    match store.export_page(after, rows, EXPORT_PAGE_BYTES) {
        Ok(page) => Response::ExportPage {
            header: (after == 0).then(csv_header),
            csv: page.csv,
            rows: page.rows,
            last: page.last_id,
        },
        Err(error) => Response::Error {
            message: format!("could not export: {error}"),
        },
    }
}

/// Asks the engine to delete everything saved, and waits for the result.
fn delete_all(state: &Mutex<LiveState>, confirm: &str) -> Response {
    if confirm != DELETE_ALL_CONFIRMATION {
        return Response::Error {
            message: String::from("not deleted: the confirmation did not match"),
        };
    }
    let Some(commands) = lock(state).commands.clone() else {
        return Response::Error {
            message: String::from("not deleted: Whereabouts is still starting"),
        };
    };
    let (reply, result) = mpsc::channel();
    if commands.send(EngineCommand::DeleteAll { reply }).is_err() {
        return Response::Error {
            message: String::from("not deleted: Whereabouts is stopping"),
        };
    }
    match result.recv_timeout(DELETE_TIMEOUT) {
        Ok(Ok(())) => Response::Deleted {},
        Ok(Err(error)) => Response::Error {
            message: format!("could not delete: {error}"),
        },
        Err(_) => Response::Error {
            message: String::from("could not delete: Whereabouts did not answer in time"),
        },
    }
}

fn history(store: &Store, hours: u32, limit: u32) -> Response {
    let since = SystemTime::now()
        .checked_sub(Duration::from_secs(u64::from(hours) * 60 * 60))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    match store.top_apps(since, usize::try_from(limit).unwrap_or(usize::MAX)) {
        Ok(apps) => Response::History {
            apps: apps
                .into_iter()
                .map(|app| AppTotals {
                    app: app.app_name,
                    publisher: app.publisher,
                    flows: app.flows,
                    destinations: app.destinations,
                    bytes_sent: app.bytes_sent,
                    bytes_received: app.bytes_received,
                })
                .collect(),
        },
        Err(error) => Response::Error {
            message: format!("could not read history: {error}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    fn unique_name() -> String {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        format!(
            r"\\.\pipe\whereabouts-server-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn flow(pid: u32) -> FlowView {
        FlowView {
            pid,
            app: String::from("curl.exe"),
            path: None,
            publisher: String::from("Microsoft Windows"),
            publisher_confirmed: true,
            protocol: String::from("TCP"),
            domain: Some(String::from("example.com")),
            domain_trust: Some(whereabouts_ipc::DomainTrust::Verified),
            via: None,
            owner: None,
            country: Some(String::from("US")),
            remote: String::from("93.184.215.14:443"),
            bytes_sent: 100,
            bytes_received: 1000,
            active: true,
        }
    }

    fn shared(flows: usize) -> SharedState {
        Arc::new(Mutex::new(LiveState {
            status: Status {
                events: 42,
                ..Status::default()
            },
            flows: (0..flows)
                .map(|i| flow(u32::try_from(i).unwrap()))
                .collect(),
            commands: None,
            notices: VecDeque::new(),
            last_notice: 0,
            lists: whereabouts_ipc::ListsView::default(),
            updates: None,
        }))
    }

    #[test]
    fn deleting_needs_the_exact_confirmation() {
        let state = shared(1);
        let mut store = None;
        let wrong = answer(
            Request::DeleteAll {
                confirm: String::from("yes"),
            },
            &state,
            &mut store,
        );
        assert!(matches!(wrong, Response::Error { .. }), "{wrong:?}");
    }

    #[test]
    fn deleting_is_done_by_the_engine() {
        let state = shared(1);
        let (sender, commands) = mpsc::channel();
        lock(&state).commands = Some(sender);
        // A stand-in for the engine that answers one command.
        let engine = std::thread::spawn(move || match commands.recv().unwrap() {
            EngineCommand::DeleteAll { reply } => reply.send(Ok(())).unwrap(),
            other => panic!("unexpected command {other:?}"),
        });
        let mut store = None;
        let done = answer(
            Request::DeleteAll {
                confirm: String::from(DELETE_ALL_CONFIRMATION),
            },
            &state,
            &mut store,
        );
        engine.join().unwrap();
        assert_eq!(done, Response::Deleted {});
    }

    #[test]
    fn deleting_reports_when_the_engine_is_not_there() {
        let state = shared(1);
        let mut store = None;
        let request = || Request::DeleteAll {
            confirm: String::from(DELETE_ALL_CONFIRMATION),
        };
        // Not started yet.
        assert!(matches!(
            answer(request(), &state, &mut store),
            Response::Error { .. }
        ));
        // Stopped: the receiving end is gone.
        let (sender, commands) = mpsc::channel();
        drop(commands);
        lock(&state).commands = Some(sender);
        assert!(matches!(
            answer(request(), &state, &mut store),
            Response::Error { .. }
        ));
    }

    #[test]
    fn rule_requests_are_passed_to_the_engine() {
        let state = shared(1);
        let (sender, commands) = mpsc::channel();
        lock(&state).commands = Some(sender);
        let engine = std::thread::spawn(move || match commands.recv().unwrap() {
            EngineCommand::Rules {
                command: crate::blocking::RuleCommand::Remove(7),
                reply,
            } => reply
                .send(Response::Rules {
                    rules: Vec::new(),
                    paused: false,
                })
                .unwrap(),
            other => panic!("{other:?}"),
        });
        let mut store = None;
        let answer = answer(Request::RemoveRule { id: 7 }, &state, &mut store);
        engine.join().unwrap();
        assert_eq!(
            answer,
            Response::Rules {
                rules: Vec::new(),
                paused: false
            }
        );
    }

    #[test]
    fn notices_are_kept_bounded_and_listed_after_an_id() {
        let state = shared(0);
        for i in 0..(MAX_NOTICES + 5) {
            lock(&state).push_notice(
                NoticeKind::NewApp {
                    app: format!("app{i}.exe"),
                    path: format!(r"C:\Apps\app{i}.exe"),
                },
                SystemTime::UNIX_EPOCH,
            );
        }
        let mut store = None;
        match answer(Request::Notices { after: 0 }, &state, &mut store) {
            Response::Notices { notices, last } => {
                assert_eq!(notices.len(), MAX_NOTICES);
                assert_eq!(last, (MAX_NOTICES + 5) as u64);
                assert_eq!(notices[0].id, 6, "the oldest were dropped");
            }
            other => panic!("{other:?}"),
        }
        match answer(Request::Notices { after: 104 }, &state, &mut store) {
            Response::Notices { notices, .. } => assert_eq!(notices.len(), 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn answers_are_limited_to_what_was_asked() {
        let state = shared(3);
        let mut store = None;
        match answer(Request::LiveFlows { limit: 2 }, &state, &mut store) {
            Response::LiveFlows { flows } => assert_eq!(flows.len(), 2),
            other => panic!("{other:?}"),
        }
        match answer(Request::Status {}, &state, &mut store) {
            Response::Status(status) => assert_eq!(status.events, 42),
            other => panic!("{other:?}"),
        }
    }

    /// Sends `request` and reads the answer.
    fn ask(connection: &mut PipeConnection, request: &Request) -> std::io::Result<Response> {
        write_message(connection, request)?;
        read_message(connection)
    }

    #[test]
    fn serves_requests_over_the_pipe() {
        let name = unique_name();
        start(&name, None, shared(3)).unwrap();
        let mut client = whereabouts_win_pipe::connect(&name).unwrap();
        assert!(peer::runs_same_file(
            client.peer_pid(),
            client.connected_by()
        ));
        let greeting = ask(
            &mut client,
            &Request::Hello {
                protocol: PROTOCOL_VERSION,
            },
        )
        .unwrap();
        assert!(
            matches!(greeting, Response::Hello { protocol, .. } if protocol == PROTOCOL_VERSION)
        );
        match ask(&mut client, &Request::LiveFlows { limit: 100 }).unwrap() {
            Response::LiveFlows { flows } => assert_eq!(flows.len(), 3),
            other => panic!("{other:?}"),
        }
        match ask(&mut client, &Request::Status {}).unwrap() {
            Response::Status(status) => assert_eq!(status.events, 42),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_client_must_say_hello_in_our_protocol_first() {
        let name = unique_name();
        start(&name, None, shared(1)).unwrap();

        // Skipping Hello: the connection is closed without an answer.
        let mut client = whereabouts_win_pipe::connect(&name).unwrap();
        assert!(ask(&mut client, &Request::Status {}).is_err());

        // A different protocol version: an error, then the connection closes.
        let mut client = whereabouts_win_pipe::connect(&name).unwrap();
        let answer = ask(
            &mut client,
            &Request::Hello {
                protocol: PROTOCOL_VERSION + 1,
            },
        )
        .unwrap();
        assert!(matches!(answer, Response::Error { .. }), "{answer:?}");
        assert!(ask(&mut client, &Request::Status {}).is_err());
    }

    #[test]
    fn garbage_closes_the_connection() {
        use std::io::{Read, Write};
        let name = unique_name();
        start(&name, None, shared(1)).unwrap();
        let mut client = whereabouts_win_pipe::connect(&name).unwrap();
        client.write_all(&[0xFF; 16]).unwrap();
        let mut buffer = [0u8; 1];
        // The server hangs up instead of answering.
        assert!(matches!(client.read(&mut buffer), Ok(0) | Err(_)));
    }
}
