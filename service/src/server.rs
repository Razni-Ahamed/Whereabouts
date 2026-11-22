//! Local pipe server: answers requests from Whereabouts clients, such as
//! `--status` now and the desktop app later (design spec §5.8).
//!
//! Who may connect:
//! - The pipe's permissions allow only SYSTEM, Administrators and the
//!   account running Whereabouts, from this computer only.
//! - The program on the other end must be Whereabouts itself: the file it
//!   runs must be the same file as ours, or another program installed next
//!   to ours in the protected installation folder (the desktop app); see
//!   [`peer::trusted_client`]. Other programs are disconnected before
//!   anything is read from them.
//! - Only the desktop app, or a client running as administrator, may change
//!   what is blocked, deleted or warned about ([`Client::may_change`]). Any
//!   program can start the command line with any arguments, so without this
//!   a blocked app could run it to unblock itself.
//!
//! Clients can only send the typed requests of `whereabouts-ipc`, and every
//! request's limits are clamped before it is answered.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use whereabouts_client::peer::{self, Client};
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

/// The answer to a change asked for by a client that may not make it.
const NEEDS_ADMIN: &str = "Changing what Whereabouts blocks, deletes or warns about needs the \
                           Whereabouts app, or administrator rights, so that other programs \
                           cannot lift your blocks. Run this command from a terminal opened as \
                           administrator.";

/// Decides who a connecting client is (see [`peer::trusted_client`]).
type Trust = fn(u32, SystemTime) -> Option<Client>;

/// Work only the engine can do, asked for by a client.
#[derive(Debug)]
pub enum EngineCommand {
    /// Delete all saved data, including finished flows not saved yet, and
    /// send back the result.
    DeleteAll {
        /// Where to send the result.
        reply: Sender<Result<(), String>>,
    },
    /// Save the user's choice whether to save history and apply it (with
    /// `delete_saved`, also delete the saved history when turning it off),
    /// and send back the result.
    SetSaveHistory {
        /// Whether to save finished connections.
        save: bool,
        /// Also delete the saved connections and hourly totals.
        delete_saved: bool,
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
    start_with(name, client_sid, state, peer::trusted_client, IDLE_LIMIT)
}

/// How often the service tries again for a pipe name that was taken.
const PIPE_RETRY_EVERY: Duration = Duration::from_secs(5);

/// Like [`start`], but if the name is taken, keeps trying in the background
/// instead of giving up. While the service is stopped (updating, or
/// restarting after a failure) any program can create a pipe with our name;
/// the service then could not answer clients until its next restart. Calls
/// `ready` once the pipe is up.
pub fn start_or_retry(
    name: &'static str,
    client_sid: Option<String>,
    state: SharedState,
    ready: impl FnOnce(&SharedState) + Send + 'static,
) {
    start_or_retry_every(name, client_sid, state, ready, PIPE_RETRY_EVERY);
}

fn start_or_retry_every(
    name: &'static str,
    client_sid: Option<String>,
    state: SharedState,
    ready: impl FnOnce(&SharedState) + Send + 'static,
    every: Duration,
) {
    let error = match start(name, client_sid.as_deref(), Arc::clone(&state)) {
        Ok(()) => {
            ready(&state);
            return;
        }
        Err(error) => error,
    };
    report!("warning: {error}; trying again every {} s", every.as_secs());
    let retrying = std::thread::Builder::new()
        .name(String::from("pipe-retry"))
        .spawn(move || {
            loop {
                std::thread::sleep(every);
                if start(name, client_sid.as_deref(), Arc::clone(&state)).is_ok() {
                    report!("The pipe {name} is free again; answering clients");
                    ready(&state);
                    return;
                }
            }
        });
    if let Err(error) = retrying {
        report!("warning: could not keep trying for the pipe ({error})");
    }
}

/// Like [`start`], with tests treating every client as the desktop app.
#[cfg(test)]
pub fn start_trusting_app(name: &str, state: SharedState) -> Result<(), String> {
    start_with(name, None, state, |_, _| Some(Client::App), IDLE_LIMIT)
}

fn start_with(
    name: &str,
    client_sid: Option<&str>,
    state: SharedState,
    trust: Trust,
    idle_limit: Duration,
) -> Result<(), String> {
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
        .spawn(move || accept_loop(listener, &state, trust, idle_limit))
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

fn accept_loop(
    mut listener: PipeListener,
    state: &SharedState,
    trust: Trust,
    idle_limit: Duration,
) {
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
        let Some(client) = trust(connection.peer_pid(), connection.connected_by()) else {
            continue;
        };
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
                serve(connection, &state, client, idle_limit);
            });
    }
}

/// How long a client may stay connected without asking anything. Only a
/// few clients are served at once ([`MAX_CLIENTS`]), so one that connects
/// and then says nothing must not hold its place forever. The app asks every
/// few seconds and reconnects if it was disconnected.
const IDLE_LIMIT: Duration = Duration::from_secs(120);

/// Breaks a connection that waits too long on its client: for its next
/// request, or to take an answer (a client that stops reading would leave
/// the write blocked once the pipe buffer is full). Time spent working out
/// an answer does not count.
struct Watchdog {
    waiting_since: Arc<Mutex<Option<Instant>>>,
    done: Arc<std::sync::atomic::AtomicBool>,
}

impl Watchdog {
    /// `None` if its thread cannot start: the connection is then not served,
    /// rather than served without a limit.
    fn start(breaker: whereabouts_win_pipe::Breaker, limit: Duration) -> Option<Self> {
        let waiting_since = Arc::new(Mutex::new(None::<Instant>));
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (waiting, finished) = (Arc::clone(&waiting_since), Arc::clone(&done));
        let tick = (limit / 10).max(Duration::from_millis(20));
        std::thread::Builder::new()
            .name(String::from("pipe-watchdog"))
            .spawn(move || {
                while !finished.load(Ordering::Acquire) {
                    std::thread::sleep(tick);
                    let since = *waiting.lock().unwrap_or_else(PoisonError::into_inner);
                    if since.is_some_and(|since| since.elapsed() >= limit) {
                        breaker.break_connection();
                        return;
                    }
                }
            })
            .ok()?;
        Some(Self {
            waiting_since,
            done,
        })
    }

    /// The connection now waits on the client (reading its request, or
    /// writing an answer it has to take).
    fn on_client(&self) {
        *self
            .waiting_since
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
    }

    /// The connection is busy working out an answer.
    fn answering(&self) {
        *self
            .waiting_since
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
    }
}

/// Answers one client until it disconnects, sends something invalid or
/// stays silent longer than `idle_limit`.
fn serve(
    mut connection: PipeConnection,
    state: &Mutex<LiveState>,
    client: Client,
    idle_limit: Duration,
) {
    let Some(watchdog) = Watchdog::start(connection.breaker(), idle_limit) else {
        return;
    };
    // The first message must be a Hello in our protocol version. Every
    // read and write below waits on the client, under the time limit.
    watchdog.on_client();
    let first = read_message::<Request>(&mut connection);
    match first {
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
    loop {
        watchdog.on_client();
        let Ok(request) = read_message::<Request>(&mut connection) else {
            return;
        };
        watchdog.answering();
        let response = answer(request.clamped(), state, &mut store, client);
        watchdog.on_client();
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

/// Whether `request` changes what Whereabouts blocks, deletes or warns
/// about (or downloads), rather than only reading.
fn changes_something(request: &Request) -> bool {
    match request {
        Request::AddRule { .. }
        | Request::RemoveRule { .. }
        | Request::SetBlockingPaused { .. }
        | Request::DeleteAll { .. }
        | Request::DismissAlert { .. }
        | Request::SetListUpdates { .. }
        | Request::SetSaveHistory { .. } => true,
        Request::Hello { .. }
        | Request::Status {}
        | Request::CheckListsNow {}
        | Request::LiveFlows { .. }
        | Request::History { .. }
        | Request::ExportPage { .. }
        | Request::ListRules {}
        | Request::Alerts { .. }
        | Request::Notices { .. } => false,
    }
}

/// Answers one (already clamped) request from `client`. The store is opened
/// the first time saved data is asked for, and kept for the rest of the
/// connection.
fn answer(
    request: Request,
    state: &Mutex<LiveState>,
    store: &mut Option<Store>,
    client: Client,
) -> Response {
    if changes_something(&request) && !client.may_change() {
        return Response::Error {
            message: String::from(NEEDS_ADMIN),
        };
    }
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
        Request::SetSaveHistory { save, delete_saved } => {
            set_save_history(state, save, delete_saved)
        }
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

/// Asks the engine to save and apply the choice whether to save history,
/// and waits for the result.
fn set_save_history(state: &Mutex<LiveState>, save: bool, delete_saved: bool) -> Response {
    let Some(commands) = lock(state).commands.clone() else {
        return Response::Error {
            message: String::from("not changed: Whereabouts is still starting"),
        };
    };
    let (reply, result) = mpsc::channel();
    let command = EngineCommand::SetSaveHistory {
        save,
        delete_saved: delete_saved && !save,
        reply,
    };
    if commands.send(command).is_err() {
        return Response::Error {
            message: String::from("not changed: Whereabouts is stopping"),
        };
    }
    match result.recv_timeout(DELETE_TIMEOUT) {
        Ok(Ok(())) => {
            // Show the change before the engine's next refresh.
            let mut state = lock(state);
            state.status.save_history = Some(save);
            state.status.saving = save;
            Response::SaveHistory { save }
        }
        Ok(Err(error)) => Response::Error {
            message: format!("could not change history saving: {error}"),
        },
        Err(_) => Response::Error {
            message: String::from(
                "could not change history saving: Whereabouts did not answer in time",
            ),
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
            web_content: false,
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
            Client::App,
        );
        assert!(matches!(wrong, Response::Error { .. }), "{wrong:?}");
    }

    #[test]
    fn an_ordinary_command_line_may_read_but_not_change() {
        let state = shared(1);
        let (sender, commands) = mpsc::channel();
        lock(&state).commands = Some(sender);
        let mut store = None;
        let tool = Client::Tool { elevated: false };
        for request in [
            Request::SetBlockingPaused { paused: true },
            Request::RemoveRule { id: 1 },
            Request::AddRule {
                rule: whereabouts_ipc::RuleSpec::Address {
                    ip: "203.0.113.5".parse().unwrap(),
                    app: None,
                },
            },
            Request::DeleteAll {
                confirm: String::from(DELETE_ALL_CONFIRMATION),
            },
            Request::DismissAlert { id: 1, allow: true },
            Request::SetListUpdates {
                data: false,
                drop: false,
            },
            Request::SetSaveHistory {
                save: false,
                delete_saved: true,
            },
        ] {
            let refused = answer(request, &state, &mut store, tool);
            assert!(!NEEDS_ADMIN.contains("  "), "one space between words");
            assert_eq!(
                refused,
                Response::Error {
                    message: String::from(NEEDS_ADMIN)
                }
            );
        }
        assert!(commands.try_recv().is_err(), "nothing reached the engine");
        // Reading is fine.
        assert!(matches!(
            answer(Request::Status {}, &state, &mut store, tool),
            Response::Status(_)
        ));
        // An administrator's command line may change rules.
        let engine = std::thread::spawn(move || match commands.recv().unwrap() {
            EngineCommand::Rules { reply, .. } => reply
                .send(Response::Rules {
                    rules: Vec::new(),
                    paused: true,
                })
                .unwrap(),
            other => panic!("{other:?}"),
        });
        let paused = answer(
            Request::SetBlockingPaused { paused: true },
            &state,
            &mut store,
            Client::Tool { elevated: true },
        );
        engine.join().unwrap();
        assert!(matches!(paused, Response::Rules { paused: true, .. }));
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
            Client::App,
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
            answer(request(), &state, &mut store, Client::App),
            Response::Error { .. }
        ));
        // Stopped: the receiving end is gone.
        let (sender, commands) = mpsc::channel();
        drop(commands);
        lock(&state).commands = Some(sender);
        assert!(matches!(
            answer(request(), &state, &mut store, Client::App),
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
        let answer = answer(
            Request::RemoveRule { id: 7 },
            &state,
            &mut store,
            Client::App,
        );
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
    fn history_choices_are_passed_to_the_engine() {
        let state = shared(1);
        let (sender, commands) = mpsc::channel();
        lock(&state).commands = Some(sender);
        let engine = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..2 {
                match commands.recv().unwrap() {
                    EngineCommand::SetSaveHistory {
                        save,
                        delete_saved,
                        reply,
                    } => {
                        seen.push((save, delete_saved));
                        reply.send(Ok(())).unwrap();
                    }
                    other => panic!("{other:?}"),
                }
            }
            seen
        });
        let mut store = None;
        let off = Request::SetSaveHistory {
            save: false,
            delete_saved: true,
        };
        assert_eq!(
            answer(off, &state, &mut store, Client::App),
            Response::SaveHistory { save: false }
        );
        assert_eq!(lock(&state).status.save_history, Some(false));
        assert!(!lock(&state).status.saving);
        // Deleting only goes with turning saving off.
        let on = Request::SetSaveHistory {
            save: true,
            delete_saved: true,
        };
        assert_eq!(
            answer(on, &state, &mut store, Client::App),
            Response::SaveHistory { save: true }
        );
        assert_eq!(engine.join().unwrap(), vec![(false, true), (true, false)]);
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
        match answer(
            Request::Notices { after: 0 },
            &state,
            &mut store,
            Client::App,
        ) {
            Response::Notices { notices, last } => {
                assert_eq!(notices.len(), MAX_NOTICES);
                assert_eq!(last, (MAX_NOTICES + 5) as u64);
                assert_eq!(notices[0].id, 6, "the oldest were dropped");
            }
            other => panic!("{other:?}"),
        }
        match answer(
            Request::Notices { after: 104 },
            &state,
            &mut store,
            Client::App,
        ) {
            Response::Notices { notices, .. } => assert_eq!(notices.len(), 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn answers_are_limited_to_what_was_asked() {
        let state = shared(3);
        let mut store = None;
        match answer(
            Request::LiveFlows { limit: 2 },
            &state,
            &mut store,
            Client::App,
        ) {
            Response::LiveFlows { flows } => assert_eq!(flows.len(), 2),
            other => panic!("{other:?}"),
        }
        match answer(Request::Status {}, &state, &mut store, Client::App) {
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
    fn a_silent_client_is_disconnected_and_frees_its_place() {
        let name = unique_name();
        let limit = Duration::from_millis(300);
        start_with(&name, None, shared(1), |_, _| Some(Client::App), limit).unwrap();
        let hello = Request::Hello {
            protocol: PROTOCOL_VERSION,
        };
        // Every place taken by clients that say hello and then nothing.
        let mut silent: Vec<_> = (0..MAX_CLIENTS)
            .map(|_| {
                let mut client = whereabouts_win_pipe::connect(&name).unwrap();
                ask(&mut client, &hello).unwrap();
                client
            })
            .collect();
        // A client that keeps asking more often than the limit stays.
        std::thread::sleep(Duration::from_millis(900));
        for client in &mut silent {
            assert!(
                ask(client, &Request::Status {}).is_err(),
                "a silent client was let go"
            );
        }
        let mut busy = whereabouts_win_pipe::connect(&name).unwrap();
        ask(&mut busy, &hello).expect("its place is free again");
        for _ in 0..6 {
            std::thread::sleep(Duration::from_millis(100));
            assert!(matches!(
                ask(&mut busy, &Request::Status {}),
                Ok(Response::Status(_))
            ));
        }
    }

    #[test]
    fn a_client_that_stops_reading_answers_is_let_go_too() {
        let name = unique_name();
        let limit = Duration::from_millis(300);
        // Enough flows that the answer does not fit the pipe's buffer.
        start_with(&name, None, shared(500), |_, _| Some(Client::App), limit).unwrap();
        let hello = Request::Hello {
            protocol: PROTOCOL_VERSION,
        };
        let stuck: Vec<_> = (0..MAX_CLIENTS)
            .map(|_| {
                let mut client = whereabouts_win_pipe::connect(&name).unwrap();
                ask(&mut client, &hello).unwrap();
                // Asks for a large answer and never reads it.
                write_message(&mut client, &Request::LiveFlows { limit: 500 }).unwrap();
                client
            })
            .collect();
        std::thread::sleep(Duration::from_millis(1200));
        let mut next = whereabouts_win_pipe::connect(&name).unwrap();
        assert!(
            matches!(ask(&mut next, &hello), Ok(Response::Hello { .. })),
            "the places of clients that stopped reading are free again"
        );
        drop(stuck);
    }

    #[test]
    fn a_taken_pipe_name_is_tried_again_until_it_is_free() {
        use std::sync::atomic::AtomicBool;
        // A static name, as the real one is; unique to this test process.
        let name: &'static str = Box::leak(unique_name().into_boxed_str());
        let sid = current_user_sid().unwrap();
        // Another program took the name while the service was stopped.
        let squatter = PipeListener::bind(name, &sid).unwrap();
        let ready = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ready);
        start_or_retry_every(
            name,
            None,
            shared(1),
            move |_| flag.store(true, Ordering::SeqCst),
            Duration::from_millis(100),
        );
        std::thread::sleep(Duration::from_millis(400));
        assert!(!ready.load(Ordering::SeqCst), "the name is still taken");
        drop(squatter);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !ready.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            ready.load(Ordering::SeqCst),
            "the service took the pipe back"
        );
        let mut client = whereabouts_win_pipe::connect(name).unwrap();
        let greeting = ask(
            &mut client,
            &Request::Hello {
                protocol: PROTOCOL_VERSION,
            },
        )
        .unwrap();
        assert!(matches!(greeting, Response::Hello { .. }), "{greeting:?}");
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
