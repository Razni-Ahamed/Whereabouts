//! Whereabouts background service.
//!
//! Running as a real Windows service comes later in v0.1 (design spec §5.1).
//! For now, `--console` shows live per-app network flows in the terminal and
//! saves finished flows to the encrypted store; `--history`, `--export` and
//! `--delete-all` work with what was saved.

#[macro_use]
mod log;

mod client;
mod console;
mod install;
mod server;
mod service_mode;
mod storage;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "\
Usage: whereabouts-service [OPTIONS]

Options:
  --console            Show live network flows per app in this terminal and
                       save finished flows (must run as administrator;
                       stop with Ctrl+C)
  --seconds <N>        With --console, stop after N seconds
  --status             Ask the running Whereabouts how it is doing, and show
                       the top flows and apps
  --history            Show what is saved: top apps of the last 24 hours
  --export <FILE>      Write all saved flows to a CSV file
  --delete-all --yes   Delete all saved flows and totals (cannot be undone)
  --install            Install and start Whereabouts as a Windows service that
                       runs at boot (as administrator)
  --uninstall          Stop and remove the service; saved data is kept
  --delete-data        With --uninstall, also delete all saved data
  --version            Print the version
  --help               Print this help

Saved data is kept in %ProgramData%\\Whereabouts (readable by administrators
only), encrypted. Windows starts the installed service with --service.";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Console { limit: Option<Duration> },
    Status,
    History,
    Export(PathBuf),
    DeleteAll { confirmed: bool },
    Install,
    Uninstall { delete_data: bool },
    Service { client_user: String },
    Version,
    Help,
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    let mut console = false;
    let mut seconds = None;
    let mut status = false;
    let mut history = false;
    let mut export = None;
    let mut delete_all = false;
    let mut yes = false;
    let mut install = false;
    let mut uninstall = false;
    let mut delete_data = false;
    let mut service = false;
    let mut client_user = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--console" => console = true,
            "--seconds" => {
                let value = iter.next().ok_or("--seconds needs a value")?;
                let n: u64 = value
                    .parse()
                    .map_err(|_| format!("--seconds expects a whole number, got {value:?}"))?;
                seconds = Some(Duration::from_secs(n));
            }
            "--status" => status = true,
            "--history" => history = true,
            "--export" => {
                let value = iter.next().ok_or("--export needs a file name")?;
                export = Some(PathBuf::from(value));
            }
            "--delete-all" => delete_all = true,
            "--yes" => yes = true,
            "--install" => install = true,
            "--uninstall" => uninstall = true,
            "--delete-data" => delete_data = true,
            "--service" => service = true,
            "--client-user" => {
                let value = iter.next().ok_or("--client-user needs an account ID")?;
                let valid = value.starts_with("S-")
                    && value[2..].bytes().all(|b| b.is_ascii_digit() || b == b'-');
                if !valid {
                    return Err(format!("{value:?} is not an account ID (S-1-...)"));
                }
                client_user = Some(value.clone());
            }
            "--version" | "-V" => return Ok(Command::Version),
            "--help" | "-h" => return Ok(Command::Help),
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    let chosen = [
        console,
        status,
        history,
        export.is_some(),
        delete_all,
        install,
        uninstall,
        service,
    ]
    .iter()
    .filter(|&&on| on)
    .count();
    if chosen > 1 {
        return Err(String::from(
            "choose only one of --console, --status, --history, --export, --delete-all, \
             --install, --uninstall",
        ));
    }
    if seconds.is_some() && !console {
        return Err(String::from("--seconds only works with --console"));
    }
    if yes && !delete_all {
        return Err(String::from("--yes only works with --delete-all"));
    }
    if delete_data && !uninstall {
        return Err(String::from("--delete-data only works with --uninstall"));
    }
    if client_user.is_some() != service {
        return Err(String::from("--service and --client-user go together"));
    }
    Ok(if console {
        Command::Console { limit: seconds }
    } else if status {
        Command::Status
    } else if history {
        Command::History
    } else if let Some(path) = export {
        Command::Export(path)
    } else if delete_all {
        Command::DeleteAll { confirmed: yes }
    } else if install {
        Command::Install
    } else if uninstall {
        Command::Uninstall { delete_data }
    } else if let Some(client_user) = client_user {
        Command::Service { client_user }
    } else {
        Command::Help
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(Command::Console { limit }) => console::run(limit),
        Ok(Command::Status) => client::status(),
        Ok(Command::History) => storage::show_history(),
        Ok(Command::Export(path)) => storage::export(&path),
        Ok(Command::DeleteAll { confirmed }) => storage::delete_all(confirmed),
        Ok(Command::Install) => install::install(),
        Ok(Command::Uninstall { delete_data }) => install::uninstall(delete_data),
        Ok(Command::Service { client_user }) => service_mode::run(client_user),
        Ok(Command::Version) => {
            println!(
                "whereabouts-service {} (IPC protocol v{})",
                env!("CARGO_PKG_VERSION"),
                whereabouts_ipc::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }
        Ok(Command::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_arguments_shows_help() {
        assert_eq!(parse_args(&[]), Ok(Command::Help));
    }

    #[test]
    fn parses_console_with_and_without_limit() {
        assert_eq!(
            parse_args(&args(&["--console"])),
            Ok(Command::Console { limit: None })
        );
        assert_eq!(
            parse_args(&args(&["--console", "--seconds", "30"])),
            Ok(Command::Console {
                limit: Some(Duration::from_secs(30))
            })
        );
    }

    #[test]
    fn parses_storage_commands() {
        assert_eq!(parse_args(&args(&["--status"])), Ok(Command::Status));
        assert_eq!(parse_args(&args(&["--history"])), Ok(Command::History));
        assert_eq!(
            parse_args(&args(&["--export", "out.csv"])),
            Ok(Command::Export(PathBuf::from("out.csv")))
        );
        assert_eq!(
            parse_args(&args(&["--delete-all"])),
            Ok(Command::DeleteAll { confirmed: false })
        );
        assert_eq!(
            parse_args(&args(&["--delete-all", "--yes"])),
            Ok(Command::DeleteAll { confirmed: true })
        );
    }

    #[test]
    fn parses_service_commands() {
        assert_eq!(parse_args(&args(&["--install"])), Ok(Command::Install));
        assert_eq!(
            parse_args(&args(&["--uninstall"])),
            Ok(Command::Uninstall { delete_data: false })
        );
        assert_eq!(
            parse_args(&args(&["--uninstall", "--delete-data"])),
            Ok(Command::Uninstall { delete_data: true })
        );
        assert_eq!(
            parse_args(&args(&[
                "--service",
                "--client-user",
                "S-1-5-21-1-2-3-1001"
            ])),
            Ok(Command::Service {
                client_user: String::from("S-1-5-21-1-2-3-1001")
            })
        );
    }

    #[test]
    fn rejects_bad_service_input() {
        assert!(parse_args(&args(&["--service"])).is_err());
        assert!(parse_args(&args(&["--client-user", "S-1-5-18"])).is_err());
        assert!(parse_args(&args(&["--service", "--client-user", "WD"])).is_err());
        assert!(parse_args(&args(&["--service", "--client-user", "S-1)(A;;GA;;;WD"])).is_err());
        assert!(parse_args(&args(&["--delete-data"])).is_err());
        assert!(parse_args(&args(&["--install", "--uninstall"])).is_err());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_args(&args(&["--seconds", "5"])).is_err());
        assert!(parse_args(&args(&["--console", "--seconds"])).is_err());
        assert!(parse_args(&args(&["--console", "--seconds", "-1"])).is_err());
        assert!(parse_args(&args(&["--bogus"])).is_err());
        assert!(parse_args(&args(&["--export"])).is_err());
        assert!(parse_args(&args(&["--yes"])).is_err());
        assert!(parse_args(&args(&["--console", "--history"])).is_err());
        assert!(parse_args(&args(&["--status", "--console"])).is_err());
    }
}
