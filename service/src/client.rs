//! `--status` and the blocking commands: ask a running Whereabouts over its
//! local pipe how it is doing, show the top flows and apps, and list or
//! change the blocking rules.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use whereabouts_client::{Client, Problem, ProblemKind};
use whereabouts_core::text::display_safe;
use whereabouts_ipc::{
    DomainTrust, FlowView, PIPE_NAME, Request, Response, RuleSpec, RuleView, Status,
};

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

/// Explains a problem for the `--status` command, with what to do next.
fn explain(problem: &Problem) -> String {
    let installed = whereabouts_client::installed_service();
    let hint = match problem.kind {
        ProblemKind::NotRunning => Some(String::from(
            "Install it with --install, or run --console (as administrator).",
        )),
        ProblemKind::Untrusted | ProblemKind::Refused => installed.map(|exe| {
            format!(
                "To ask the installed service, run \"{}\" --status",
                exe.display()
            )
        }),
        _ => None,
    };
    match hint {
        Some(hint) => format!("{} {hint}", problem.message),
        None => problem.message.clone(),
    }
}

fn ask(client: &mut Client, request: &Request) -> Result<Response, String> {
    client.ask(request).map_err(|problem| explain(&problem))
}

fn unexpected(response: &Response) -> String {
    display_safe(&whereabouts_client::unexpected(response).message)
}

fn show_status(name: &str) -> Result<(), String> {
    let mut client = Client::connect(name).map_err(|problem| explain(&problem))?;
    let version = client.version().to_owned();
    let status = match ask(&mut client, &Request::Status {})? {
        Response::Status(status) => status,
        other => return Err(unexpected(&other)),
    };
    print_status(&display_safe(&version), &status);

    match ask(&mut client, &Request::LiveFlows { limit: SHOW_FLOWS })? {
        Response::LiveFlows { flows } => print_flows(&flows),
        other => return Err(unexpected(&other)),
    }

    match ask(
        &mut client,
        &Request::History {
            hours: 24,
            limit: SHOW_APPS,
        },
    )? {
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

/// A blocking command from the command line.
#[derive(Debug, PartialEq, Eq)]
pub enum RuleAction {
    /// `--rules`
    List,
    /// `--block-app PATH`
    BlockApp(PathBuf),
    /// `--block-domain NAME [--for PATH]`
    BlockDomain(String, Option<PathBuf>),
    /// `--block-ip IP [--for PATH]`
    BlockIp(IpAddr, Option<PathBuf>),
    /// `--unblock ID`
    Unblock(i64),
    /// `--pause-blocking` (true) or `--resume-blocking` (false)
    Pause(bool),
}

/// Runs a blocking command against the running service.
pub fn rules(action: RuleAction) -> ExitCode {
    match run_rules(PIPE_NAME, action) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// A program path as the service needs it: full, since the service runs in
/// another folder.
fn full_path(path: &Path) -> Result<String, String> {
    std::path::absolute(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .into_os_string()
        .into_string()
        .map_err(|_| String::from("the program path is not valid text"))
}

fn run_rules(name: &str, action: RuleAction) -> Result<(), String> {
    let program = |path: Option<PathBuf>| path.as_deref().map(full_path).transpose();
    let request = match action {
        RuleAction::List => Request::ListRules {},
        RuleAction::BlockApp(path) => Request::AddRule {
            rule: RuleSpec::App {
                path: full_path(&path)?,
            },
        },
        RuleAction::BlockDomain(name, app) => Request::AddRule {
            rule: RuleSpec::Domain {
                name,
                app: program(app)?,
            },
        },
        RuleAction::BlockIp(ip, app) => Request::AddRule {
            rule: RuleSpec::Address {
                ip,
                app: program(app)?,
            },
        },
        RuleAction::Unblock(id) => Request::RemoveRule { id },
        RuleAction::Pause(paused) => Request::SetBlockingPaused { paused },
    };
    let mut client = Client::connect(name).map_err(|problem| explain(&problem))?;
    let mut response = ask(&mut client, &request)?;
    if let Response::RuleAdded { id } = response {
        println!("Added rule {id}.");
        response = ask(&mut client, &Request::ListRules {})?;
    }
    match response {
        Response::Rules { rules, paused } => {
            print_rules(&rules, paused);
            Ok(())
        }
        other => Err(unexpected(&other)),
    }
}

fn print_rules(rules: &[RuleView], paused: bool) {
    if paused {
        println!("Blocking is PAUSED: nothing is blocked. Resume with --resume-blocking.");
    }
    if rules.is_empty() {
        println!("No blocking rules.");
        return;
    }
    println!("{:>5}  {:<8} {:<40} FOR", "ID", "KIND", "BLOCKS");
    for rule in rules {
        let for_app = |app: &Option<String>| {
            app.as_deref()
                .map_or_else(|| String::from("every app"), display_safe)
        };
        let (kind, blocks, app) = match &rule.rule {
            RuleSpec::App { path } => ("app", String::from("all connections"), display_safe(path)),
            RuleSpec::Domain { name, app } => (
                "domain",
                format!(
                    "{} ({} addresses now)",
                    display_safe(name),
                    rule.blocked_addresses
                ),
                for_app(app),
            ),
            RuleSpec::Address { ip, app } => ("address", ip.to_string(), for_app(app)),
        };
        println!(
            "{:>5}  {kind:<8} {:<40} {app}",
            rule.id,
            truncate(&blocks, 40)
        );
    }
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
        "Active flows: {} · saving history: {}{} · tracker domains: {}",
        status.active_flows,
        yes_no(status.saving),
        if status.save_history == Some(false) {
            " (turned off)"
        } else {
            ""
        },
        status.tracker_domains
    );
    println!(
        "Kernel events protected from faking: {}",
        yes_no(whereabouts_client::kernel_events_protected(
            status.kernel_events_protected
        ))
    );
    if status.block_rules > 0 {
        println!(
            "Blocking rules: {}{}",
            status.block_rules,
            if status.blocking_paused {
                " (PAUSED)"
            } else {
                ""
            }
        );
    }
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
            path: None,
            publisher: String::from("Microsoft 3rd Party Application Component"),
            publisher_confirmed: false,
            protocol: String::from("TCP"),
            domain: Some(String::from("codex-cloud-environments.chatgpt.com")),
            domain_trust: Some(DomainTrust::Guessed),
            via: None,
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
    fn rule_commands_reach_the_engine() {
        let name = format!(r"\\.\pipe\whereabouts-rules-test-{}", std::process::id());
        let (sender, commands) = std::sync::mpsc::channel();
        let state = Arc::new(Mutex::new(crate::server::LiveState {
            commands: Some(sender),
            ..crate::server::LiveState::default()
        }));
        crate::server::start(&name, None, state).unwrap();
        // A stand-in engine: adds a rule, then lists it.
        let engine = std::thread::spawn(move || {
            for _ in 0..2 {
                match commands.recv().unwrap() {
                    crate::server::EngineCommand::Rules { command, reply } => {
                        let answer = match command {
                            crate::blocking::RuleCommand::Add(RuleSpec::Address {
                                ip,
                                app: None,
                            }) => {
                                assert_eq!(ip, "203.0.113.5".parse::<IpAddr>().unwrap());
                                Response::RuleAdded { id: 1 }
                            }
                            crate::blocking::RuleCommand::List => Response::Rules {
                                rules: Vec::new(),
                                paused: false,
                            },
                            other => panic!("{other:?}"),
                        };
                        reply.send(answer).unwrap();
                    }
                    other => panic!("{other:?}"),
                }
            }
        });
        run_rules(
            &name,
            RuleAction::BlockIp("203.0.113.5".parse().unwrap(), None),
        )
        .unwrap();
        engine.join().unwrap();
    }

    #[test]
    fn program_paths_are_sent_in_full() {
        let full = full_path(Path::new("x.exe")).unwrap();
        assert!(Path::new(&full).is_absolute(), "{full}");
    }

    #[test]
    fn connects_to_a_running_service() {
        let name = format!(r"\\.\pipe\whereabouts-client-test-{}", std::process::id());
        let state = Arc::new(Mutex::new(crate::server::LiveState::default()));
        crate::server::start(&name, None, state).unwrap();
        let mut client = Client::connect(&name).unwrap();
        assert_eq!(client.version(), env!("CARGO_PKG_VERSION"));
        assert!(matches!(
            client.ask(&Request::Status {}).unwrap(),
            Response::Status(_)
        ));
    }
}
