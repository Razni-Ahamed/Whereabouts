//! `--status`: asks a running Whereabouts over its local pipe how it is
//! doing, and shows the top flows and apps.

use std::io;
use std::process::ExitCode;

use whereabouts_core::text::display_safe;
use whereabouts_ipc::{
    DomainTrust, FlowView, PIPE_NAME, PROTOCOL_VERSION, Request, Response, Status,
};
use whereabouts_win_pipe::PipeConnection;

use crate::console::{format_bytes, marked, truncate};

/// Flows shown by `--status`.
const SHOW_FLOWS: u32 = 10;
/// Apps shown by `--status`.
const SHOW_APPS: u32 = 5;

/// `--status`: prints the running service's status.
pub fn status() -> ExitCode {
    match show_status(PIPE_NAME) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// A connection to a verified Whereabouts service.
struct Client(PipeConnection);

impl Client {
    /// Connects to `name`, checks that the program answering is
    /// Whereabouts, and agrees on the protocol. Returns the service version.
    fn connect(name: &str) -> Result<(Self, String), String> {
        let connection =
            whereabouts_win_pipe::connect(name).map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => String::from(
                    "Whereabouts is not running. Start it with --console (as administrator).",
                ),
                io::ErrorKind::PermissionDenied => String::from(
                    "access denied: only administrators and the account that started Whereabouts \
                 may connect",
                ),
                _ => format!("could not connect to Whereabouts ({error})"),
            })?;
        // Before sending anything, make sure no other program has taken the
        // pipe's name to pose as Whereabouts.
        if !crate::server::is_whereabouts(connection.peer_pid()) {
            return Err(String::from(
                "the program answering on the Whereabouts pipe is not this copy of \
                 Whereabouts, so it is not trusted",
            ));
        }
        let mut client = Self(connection);
        match client.ask(&Request::Hello {
            protocol: PROTOCOL_VERSION,
        })? {
            Response::Hello { protocol, version } if protocol == PROTOCOL_VERSION => {
                Ok((client, version))
            }
            Response::Hello { protocol, .. } => Err(format!(
                "Whereabouts speaks protocol version {protocol}, this program speaks \
                 {PROTOCOL_VERSION}"
            )),
            other => Err(unexpected(&other)),
        }
    }

    fn ask(&mut self, request: &Request) -> Result<Response, String> {
        whereabouts_ipc::write_message(&mut self.0, request)
            .and_then(|()| whereabouts_ipc::read_message(&mut self.0))
            .map_err(|e| format!("lost the connection to Whereabouts ({e})"))
    }
}

fn unexpected(response: &Response) -> String {
    match response {
        Response::Error { message } => format!("Whereabouts answered: {}", display_safe(message)),
        _ => String::from("Whereabouts sent an unexpected answer"),
    }
}

fn show_status(name: &str) -> Result<(), String> {
    let (mut client, version) = Client::connect(name)?;
    let status = match client.ask(&Request::Status {})? {
        Response::Status(status) => status,
        other => return Err(unexpected(&other)),
    };
    print_status(&display_safe(&version), &status);

    match client.ask(&Request::LiveFlows { limit: SHOW_FLOWS })? {
        Response::LiveFlows { flows } => print_flows(&flows),
        other => return Err(unexpected(&other)),
    }

    match client.ask(&Request::History {
        hours: 24,
        limit: SHOW_APPS,
    })? {
        Response::History { apps } if apps.is_empty() => {
            println!("\nNothing saved in the last 24 hours.");
        }
        Response::History { apps } => {
            println!("\nTop apps, last 24 hours:");
            println!(
                "{:<24} {:<26} {:>6} {:>13} {:>10} {:>10}",
                "APP", "PUBLISHER", "FLOWS", "DESTINATIONS", "SENT", "RECEIVED"
            );
            for app in apps {
                println!(
                    "{:<24} {:<26} {:>6} {:>13} {:>10} {:>10}",
                    truncate(&app.app, 24),
                    truncate(app.publisher.as_deref().unwrap_or("-"), 26),
                    app.flows,
                    app.destinations,
                    format_bytes(app.bytes_sent),
                    format_bytes(app.bytes_received)
                );
            }
        }
        // History may be unavailable (e.g. not saving); still a success.
        other => println!("\n{}", unexpected(&other)),
    }
    Ok(())
}

fn print_status(version: &str, status: &Status) {
    let yes_no = |on: bool| if on { "yes" } else { "no" };
    println!(
        "Whereabouts {version} is running (up {}).",
        uptime(status.uptime_secs)
    );
    println!(
        "Events: {} received · {} dropped · {} unreadable · {} over limit",
        status.events, status.dropped, status.unreadable, status.over_limit
    );
    println!(
        "Active flows: {} · saving history: {} · tracker domains: {}",
        status.active_flows,
        yes_no(status.saving),
        status.tracker_domains
    );
    println!(
        "Kernel events protected from faking: {}",
        yes_no(status.kernel_events_protected)
    );
    if status.rejected > 0 {
        println!(
            "!! {} DNS events claimed to come from the Windows DNS service but did not.",
            status.rejected
        );
    }
    if status.unattributed > 0 {
        println!(
            "!! {} events could not be attributed to a process (possible evasion).",
            status.unattributed
        );
    }
}

fn print_flows(flows: &[FlowView]) {
    if flows.is_empty() {
        println!("\nNo flows yet.");
        return;
    }
    println!("\nTop flows now:");
    println!(
        "{:>6}  {:<20} {:<22} {:<5} {:<30} {:<26} {:<2} {:<40} {:>10} {:>10}",
        "PID", "APP", "PUBLISHER", "PROTO", "DOMAIN", "OWNER", "CC", "REMOTE", "SENT", "RECEIVED"
    );
    for flow in flows {
        println!(
            "{:>6}  {:<20} {:<22} {:<5} {:<30} {:<26} {:<2} {:<40} {:>10} {:>10}",
            flow.pid,
            truncate(&flow.app, 20),
            publisher_text(flow),
            truncate(&flow.protocol, 5),
            domain_text(flow),
            truncate(flow.owner.as_deref().unwrap_or("-"), 26),
            truncate(flow.country.as_deref().unwrap_or("--"), 2),
            truncate(&flow.remote, 40),
            format_bytes(flow.bytes_sent),
            format_bytes(flow.bytes_received)
        );
    }
}

/// PUBLISHER column: `?` at the end if not confirmed as the running file.
fn publisher_text(flow: &FlowView) -> String {
    let marker = if flow.publisher_confirmed { "" } else { "?" };
    marked(&flow.publisher, marker, 22)
}

/// DOMAIN column, with its trust marker. A domain without a trust level is
/// treated as app-reported (`?`), never as verified.
fn domain_text(flow: &FlowView) -> String {
    match &flow.domain {
        Some(domain) => marked(
            domain,
            flow.domain_trust.map_or("?", DomainTrust::marker),
            30,
        ),
        None => String::from("-"),
    }
}

/// Formats seconds as e.g. `2h 05m` or `3m 07s`.
fn uptime(secs: u64) -> String {
    let (hours, minutes, seconds) = (secs / 3600, secs / 60 % 60, secs % 60);
    if hours > 0 {
        format!("{hours}h {minutes:02}m")
    } else {
        format!("{minutes}m {seconds:02}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn uptime_is_readable() {
        assert_eq!(uptime(0), "0m 00s");
        assert_eq!(uptime(187), "3m 07s");
        assert_eq!(uptime(7500), "2h 05m");
    }

    #[test]
    fn trust_markers_survive_shortening() {
        let mut flow = FlowView {
            pid: 1,
            app: String::from("curl.exe"),
            publisher: String::from("Microsoft 3rd Party Application Component"),
            publisher_confirmed: false,
            protocol: String::from("TCP"),
            domain: Some(String::from("codex-cloud-environments.chatgpt.com")),
            domain_trust: Some(DomainTrust::Guessed),
            owner: None,
            country: None,
            remote: String::from("1.2.3.4:443"),
            bytes_sent: 0,
            bytes_received: 0,
            active: true,
        };
        let publisher = publisher_text(&flow);
        assert!(publisher.ends_with("…?"), "{publisher}");
        assert_eq!(publisher.chars().count(), 22);
        let domain = domain_text(&flow);
        assert!(domain.ends_with("…*"), "{domain}");
        assert_eq!(domain.chars().count(), 30);

        flow.domain = Some(String::from("example.com"));
        flow.domain_trust = None;
        assert_eq!(domain_text(&flow), "example.com?");
        flow.domain_trust = Some(DomainTrust::Verified);
        assert_eq!(domain_text(&flow), "example.com");
        flow.publisher_confirmed = true;
        flow.publisher = String::from("Google LLC");
        assert_eq!(publisher_text(&flow), "Google LLC");
    }

    #[test]
    fn missing_service_is_explained() {
        let error = show_status(r"\\.\pipe\whereabouts-test-nobody-here").unwrap_err();
        assert!(error.contains("not running"), "{error}");
    }

    #[test]
    fn connects_to_a_running_service() {
        let name = format!(r"\\.\pipe\whereabouts-client-test-{}", std::process::id());
        let state = Arc::new(Mutex::new(crate::server::LiveState::default()));
        crate::server::start(&name, state).unwrap();
        let (mut client, version) = Client::connect(&name).unwrap();
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
        assert!(matches!(
            client.ask(&Request::Status {}).unwrap(),
            Response::Status(_)
        ));
    }
}
