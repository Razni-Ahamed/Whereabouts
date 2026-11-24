//! Connecting to the Whereabouts service over its local pipe, and checking
//! who is on the other end (design spec §5.8).
//!
//! Used by the service's `--status` command and by the desktop app.

#![forbid(unsafe_code)]

pub mod peer;

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::Serialize;
use whereabouts_ipc::{PROTOCOL_VERSION, Request, Response};
use whereabouts_win_pipe::PipeConnection;
use whereabouts_win_secrets::{KnownFolder, known_folder};

/// The service's name in Windows.
pub const SERVICE_NAME: &str = "Whereabouts";
/// The service's program file.
pub const SERVICE_PROGRAM: &str = "whereabouts-service.exe";
/// The desktop app's program file.
pub const APP_PROGRAM: &str = "whereabouts.exe";

/// The installation folder, `%ProgramFiles%\Whereabouts` (path from
/// Windows, not from an environment variable). Only administrators can
/// change it.
pub fn install_dir() -> io::Result<PathBuf> {
    known_folder(KnownFolder::ProgramFiles).map(|dir| dir.join("Whereabouts"))
}

/// The installed service program, if Whereabouts is installed.
pub fn installed_service() -> Option<PathBuf> {
    let exe = install_dir().ok()?.join(SERVICE_PROGRAM);
    exe.is_file().then_some(exe)
}

/// Whether ordinary programs on this computer are unable to fake kernel
/// network and process events, given the service's own answer.
///
/// The service checks by trying to register the kernel providers' IDs
/// itself. Installed, it runs as SYSTEM, which Windows allows to do that, so
/// its answer can be a false alarm: what matters is whether *ordinary*
/// programs can (malware already running as SYSTEM is out of scope). A
/// client runs as an ordinary account, so it repeats the check from there
/// (once per run). Events count as protected if either check is refused.
pub fn kernel_events_protected(service_says: bool) -> bool {
    static HERE: OnceLock<bool> = OnceLock::new();
    service_says
        || *HERE.get_or_init(whereabouts_win_capture::protection::kernel_providers_protected)
}

/// The process IDs that are Whereabouts, seen from this program: this
/// process, every process it started (such as the desktop app's WebView2
/// helper processes, which draw its window), and the installed service.
/// Used to count Whereabouts' own connections, so none are missed.
pub fn own_process_ids() -> Vec<u32> {
    let me = std::process::id();
    let mut ids = vec![me];
    ids.extend(whereabouts_win_capture::process::descendants(me));
    if let Some(service) = peer::service_process_id() {
        ids.push(service);
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Why the service could not be asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemKind {
    /// Nothing is listening: the service is not running.
    NotRunning,
    /// The pipe's permissions do not allow this account.
    AccessDenied,
    /// The program answering is not Whereabouts.
    Untrusted,
    /// Whereabouts hung up: it only answers its own programs.
    Refused,
    /// The connection broke while asking (for example the service
    /// restarted). Asking again on a new connection is safe: the request may
    /// not have arrived.
    Lost,
    /// Anything else (an error answer, an unexpected answer, another
    /// version).
    Other,
}

/// A problem talking to the service, for people.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    /// What kind of problem.
    pub kind: ProblemKind,
    /// What went wrong, in plain words.
    pub message: String,
}

impl Problem {
    /// A problem of kind [`ProblemKind::Other`].
    pub fn other(message: impl Into<String>) -> Self {
        Self::new(ProblemKind::Other, message)
    }

    fn new(kind: ProblemKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Problem {}

/// A connection to a verified Whereabouts service.
#[derive(Debug)]
pub struct Client {
    connection: PipeConnection,
    version: String,
}

impl Client {
    /// Connects to the pipe `name`, checks that the program answering is
    /// Whereabouts (see [`peer::is_trusted_server`]) before sending
    /// anything, and agrees on the protocol version.
    pub fn connect(name: &str) -> Result<Self, Problem> {
        let connection =
            whereabouts_win_pipe::connect(name).map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => {
                    Problem::new(ProblemKind::NotRunning, "Whereabouts is not running.")
                }
                io::ErrorKind::PermissionDenied => Problem::new(
                    ProblemKind::AccessDenied,
                    "Access denied: only administrators and the account that installed Whereabouts \
                 may read its data.",
                ),
                _ => Problem::new(
                    ProblemKind::Other,
                    format!("Could not connect to Whereabouts ({error})."),
                ),
            })?;
        if !peer::is_trusted_server(connection.peer_pid(), connection.connected_by()) {
            return Err(Problem::new(
                ProblemKind::Untrusted,
                "The program answering on the Whereabouts pipe is not Whereabouts, so it is not \
                 trusted.",
            ));
        }
        let mut client = Self {
            connection,
            version: String::new(),
        };
        // The service hangs up at once on programs it does not trust,
        // before answering anything.
        let greeting = client
            .ask(&Request::Hello {
                protocol: PROTOCOL_VERSION,
            })
            .map_err(|_| {
                Problem::new(
                    ProblemKind::Refused,
                    "Whereabouts closed the connection: it only answers its own programs.",
                )
            })?;
        match greeting {
            Response::Hello { protocol, version } if protocol == PROTOCOL_VERSION => {
                client.version = version;
                Ok(client)
            }
            Response::Hello { protocol, .. } => Err(Problem::new(
                ProblemKind::Other,
                format!(
                    "Whereabouts speaks protocol version {protocol}; this program speaks \
                     {PROTOCOL_VERSION}. Install matching versions."
                ),
            )),
            other => Err(unexpected(&other)),
        }
    }

    /// The service's version, e.g. `0.1.0`.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Sends one request and reads the answer.
    pub fn ask(&mut self, request: &Request) -> Result<Response, Problem> {
        whereabouts_ipc::write_message(&mut self.connection, request)
            .and_then(|()| whereabouts_ipc::read_message(&mut self.connection))
            .map_err(|e| {
                Problem::new(
                    ProblemKind::Lost,
                    format!("Lost the connection to Whereabouts ({e})."),
                )
            })
    }
}

/// A problem for an answer that does not fit the request.
pub fn unexpected(response: &Response) -> Problem {
    match response {
        Response::Error { message } => Problem::new(
            ProblemKind::Other,
            format!("Whereabouts answered: {message}"),
        ),
        _ => Problem::new(ProblemKind::Other, "Whereabouts sent an unexpected answer."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_service_is_reported_as_not_running() {
        let problem = Client::connect(r"\\.\pipe\whereabouts-test-nobody-here").unwrap_err();
        assert_eq!(problem.kind, ProblemKind::NotRunning);
    }

    #[test]
    fn problems_serialise_for_the_app() {
        let problem = Problem::new(ProblemKind::NotRunning, "Whereabouts is not running.");
        let json = serde_json::to_string(&problem).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"not_running","message":"Whereabouts is not running."}"#
        );
    }

    #[test]
    fn kernel_events_are_protected_from_an_ordinary_account() {
        // Tests run as an ordinary user or administrator, which Windows
        // refuses (design spec §8), so even a service that could register
        // them itself gets a reassuring answer.
        assert!(kernel_events_protected(false));
        assert!(kernel_events_protected(true));
    }

    #[test]
    fn own_processes_include_this_one_and_its_children() {
        let mut child = std::process::Command::new(r"C:\Windows\System32\cmd.exe")
            .args(["/c", "ping -n 3 127.0.0.1 > nul"])
            .spawn()
            .unwrap();
        let ids = own_process_ids();
        let child_id = child.id();
        let _ = child.kill();
        let _ = child.wait();
        assert!(ids.contains(&std::process::id()));
        assert!(ids.contains(&child_id), "{ids:?} should contain {child_id}");
    }

    #[test]
    fn the_install_folder_is_under_program_files() {
        let dir = install_dir().unwrap();
        assert!(dir.ends_with("Whereabouts"));
        assert!(dir.is_absolute());
    }
}
