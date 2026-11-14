//! Whereabouts background service.
//!
//! Running as a real Windows service comes later in v0.1 (design spec §5.1).
//! For now, `--console` shows live per-app network flows in the terminal and
//! saves finished flows to the encrypted store; `--history`, `--export` and
//! `--delete-all` work with what was saved.

mod console;
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
  --history            Show what is saved: top apps of the last 24 hours
  --export <FILE>      Write all saved flows to a CSV file
  --delete-all --yes   Delete all saved flows and totals (cannot be undone)
  --version            Print the version
  --help               Print this help

Saved data is kept in %ProgramData%\\Whereabouts (readable by administrators
only), encrypted. Running as a Windows service is not implemented yet.";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Console { limit: Option<Duration> },
    History,
    Export(PathBuf),
    DeleteAll { confirmed: bool },
    Version,
    Help,
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    let mut console = false;
    let mut seconds = None;
    let mut history = false;
    let mut export = None;
    let mut delete_all = false;
    let mut yes = false;
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
            "--history" => history = true,
            "--export" => {
                let value = iter.next().ok_or("--export needs a file name")?;
                export = Some(PathBuf::from(value));
            }
            "--delete-all" => delete_all = true,
            "--yes" => yes = true,
            "--version" | "-V" => return Ok(Command::Version),
            "--help" | "-h" => return Ok(Command::Help),
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    let chosen = [console, history, export.is_some(), delete_all]
        .iter()
        .filter(|&&on| on)
        .count();
    if chosen > 1 {
        return Err(String::from(
            "choose only one of --console, --history, --export, --delete-all",
        ));
    }
    if seconds.is_some() && !console {
        return Err(String::from("--seconds only works with --console"));
    }
    if yes && !delete_all {
        return Err(String::from("--yes only works with --delete-all"));
    }
    Ok(if console {
        Command::Console { limit: seconds }
    } else if history {
        Command::History
    } else if let Some(path) = export {
        Command::Export(path)
    } else if delete_all {
        Command::DeleteAll { confirmed: yes }
    } else {
        Command::Help
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(Command::Console { limit }) => console::run(limit),
        Ok(Command::History) => storage::show_history(),
        Ok(Command::Export(path)) => storage::export(&path),
        Ok(Command::DeleteAll { confirmed }) => storage::delete_all(confirmed),
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
    fn rejects_bad_input() {
        assert!(parse_args(&args(&["--seconds", "5"])).is_err());
        assert!(parse_args(&args(&["--console", "--seconds"])).is_err());
        assert!(parse_args(&args(&["--console", "--seconds", "-1"])).is_err());
        assert!(parse_args(&args(&["--bogus"])).is_err());
        assert!(parse_args(&args(&["--export"])).is_err());
        assert!(parse_args(&args(&["--yes"])).is_err());
        assert!(parse_args(&args(&["--console", "--history"])).is_err());
    }
}
