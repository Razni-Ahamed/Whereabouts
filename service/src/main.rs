//! Whereabouts background service.
//!
//! Running as a real Windows service comes later in v0.1 (design spec §5.1).
//! For now, `--console` shows live per-app network flows in the terminal,
//! which is how the capture layer is tested on real machines.

mod console;

use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "\
Usage: whereabouts-service [OPTIONS]

Options:
  --console            Show live network flows per app in this terminal
                       (must run as administrator; stop with Ctrl+C)
  --seconds <N>        With --console, stop after N seconds
  --version            Print the version
  --help               Print this help

Running as a Windows service is not implemented yet.";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Console { limit: Option<Duration> },
    Version,
    Help,
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    let mut console = false;
    let mut seconds = None;
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
            "--version" | "-V" => return Ok(Command::Version),
            "--help" | "-h" => return Ok(Command::Help),
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    match (console, seconds) {
        (true, limit) => Ok(Command::Console { limit }),
        (false, Some(_)) => Err(String::from("--seconds only works with --console")),
        (false, None) => Ok(Command::Help),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(Command::Console { limit }) => console::run(limit),
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
    fn rejects_bad_input() {
        assert!(parse_args(&args(&["--seconds", "5"])).is_err());
        assert!(parse_args(&args(&["--console", "--seconds"])).is_err());
        assert!(parse_args(&args(&["--console", "--seconds", "-1"])).is_err());
        assert!(parse_args(&args(&["--bogus"])).is_err());
    }
}
