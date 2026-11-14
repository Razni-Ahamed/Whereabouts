//! Local pipe server: answers requests from Whereabouts clients, such as
//! `--status` now and the desktop app later (design spec §5.8).
//!
//! Who may connect:
//! - The pipe's permissions allow only SYSTEM, Administrators and the
//!   account running Whereabouts, from this computer only.
//! - The program on the other end must be Whereabouts itself: the file it
//!   runs must be the same file as ours (compared by file ID, not by name).
//!   Other programs are disconnected before anything is read from them.
//!
//! Clients can only send the typed requests of `whereabouts-ipc`, and every
//! request's limits are clamped before it is answered.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use whereabouts_ipc::{
    AppTotals, FlowView, PROTOCOL_VERSION, Request, Response, Status, read_message, write_message,
};
use whereabouts_store::Store;
use whereabouts_win_capture::identity::{is_same_file, lock_image_of};
use whereabouts_win_capture::process::ProcessHandle;
use whereabouts_win_pipe::{PipeConnection, PipeListener, current_user_sid};

/// Most clients served at the same time.
const MAX_CLIENTS: usize = 4;

/// What the engine publishes for clients after each refresh.
#[derive(Debug, Default)]
pub struct LiveState {
    /// Counters and health.
    pub status: Status,
    /// Current flows, largest first, at most [`whereabouts_ipc::MAX_ROWS`].
    pub flows: Vec<FlowView>,
}

/// The live state shared between the engine and the pipe threads.
pub type SharedState = Arc<Mutex<LiveState>>;

/// Creates the pipe `name` and starts answering clients in the background.
/// Fails if the pipe already exists (for example, Whereabouts is already
/// running, or another program took the name).
pub fn start(name: &str, state: SharedState) -> Result<(), String> {
    let sid =
        current_user_sid().map_err(|e| format!("could not read the current account ({e})"))?;
    let listener = PipeListener::bind(name, &sid).map_err(|e| {
        format!("could not create the pipe {name} ({e}); is Whereabouts already running?")
    })?;
    std::thread::Builder::new()
        .name(String::from("pipe-server"))
        .spawn(move || accept_loop(listener, &state))
        .map_err(|e| format!("could not start the pipe server ({e})"))?;
    Ok(())
}

/// Whether process `pid`, which connected at or before `connected_by`,
/// runs the same program file as this process.
///
/// The process is opened first and checked only through that handle, so
/// its ID cannot be handed to another process during the check. A process
/// that started after `connected_by` has a reused ID: it is not the one that
/// connected. Its running file is locked and confirmed with the kernel, as
/// for app identity, then compared with our own file by file ID.
pub fn is_whereabouts(pid: u32, connected_by: SystemTime) -> bool {
    let Some(process) = ProcessHandle::open(pid) else {
        return false;
    };
    if process
        .start_time()
        .is_none_or(|started| started > connected_by)
    {
        return false;
    }
    let Some((_, file)) = lock_image_of(&process) else {
        return false;
    };
    let Ok(own) = std::env::current_exe() else {
        return false;
    };
    is_same_file(&file, &own)
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
                eprintln!("warning: pipe: {error}");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        // Dropping the connection disconnects the client.
        if !is_whereabouts(connection.peer_pid(), connection.connected_by()) {
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
/// time history is asked for, and kept for the rest of the connection.
fn answer(request: Request, state: &Mutex<LiveState>, store: &mut Option<Store>) -> Response {
    match request {
        Request::Hello { .. } => hello(),
        Request::Status {} => Response::Status(lock(state).status.clone()),
        Request::LiveFlows { limit } => Response::LiveFlows {
            flows: lock(state)
                .flows
                .iter()
                .take(usize::try_from(limit).unwrap_or(usize::MAX))
                .cloned()
                .collect(),
        },
        Request::History { hours, limit } => history(store, hours, limit),
    }
}

fn history(store: &mut Option<Store>, hours: u32, limit: u32) -> Response {
    if store.is_none() {
        match crate::storage::open() {
            Ok(opened) => *store = Some(opened),
            Err(error) => {
                return Response::Error {
                    message: format!("history is not available: {error}"),
                };
            }
        }
    }
    let Some(store) = store.as_ref() else {
        return Response::Error {
            message: String::from("history is not available"),
        };
    };
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
            publisher: String::from("Microsoft Windows"),
            publisher_confirmed: true,
            protocol: String::from("TCP"),
            domain: Some(String::from("example.com")),
            domain_trust: Some(whereabouts_ipc::DomainTrust::Verified),
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
        }))
    }

    #[test]
    fn this_process_is_recognised_and_others_are_not() {
        let now = SystemTime::now();
        assert!(is_whereabouts(std::process::id(), now));
        assert!(!is_whereabouts(0, now));
        assert!(!is_whereabouts(4, now));
    }

    #[test]
    fn a_process_that_started_after_the_connection_is_rejected() {
        // As if the connecting process had exited and its ID been reused by
        // this process: the connection predates our start.
        let long_ago = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        assert!(!is_whereabouts(std::process::id(), long_ago));
    }

    #[test]
    fn another_program_is_rejected() {
        let mut child = std::process::Command::new(r"C:\Windows\System32\cmd.exe")
            .args(["/c", "ping -n 3 127.0.0.1 > nul"])
            .spawn()
            .unwrap();
        let rejected = !is_whereabouts(child.id(), SystemTime::now());
        let _ = child.kill();
        let _ = child.wait();
        assert!(rejected);
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
        start(&name, shared(3)).unwrap();
        let mut client = whereabouts_win_pipe::connect(&name).unwrap();
        assert!(is_whereabouts(client.peer_pid(), client.connected_by()));
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
        start(&name, shared(1)).unwrap();

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
        start(&name, shared(1)).unwrap();
        let mut client = whereabouts_win_pipe::connect(&name).unwrap();
        client.write_all(&[0xFF; 16]).unwrap();
        let mut buffer = [0u8; 1];
        // The server hangs up instead of answering.
        assert!(matches!(client.read(&mut buffer), Ok(0) | Err(_)));
    }
}
