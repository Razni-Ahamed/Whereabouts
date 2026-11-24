//! Whereabouts background service.
//!
//! Running as a real Windows service comes later in v0.1 (design spec §5.1).
//! For now, `--console` shows live per-app network flows in the terminal and
//! saves finished flows to the encrypted store; `--history`, `--export` and
//! `--delete-all` work with what was saved.

#[macro_use]
mod log;

mod alerts;
mod apps;
mod blocking;
mod client;
mod clock;
mod console;
mod history;
mod install;
mod learning;
mod server;
mod service_mode;
mod storage;
mod updates;

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use crate::client::RuleAction;

const USAGE: &str = "\
Usage: whereabouts-service [OPTIONS]

Options:
  --console            Show live network flows per app in this terminal and
                       save finished flows (must run as administrator;
                       stop with Ctrl+C)
  --seconds <N>        With --console, stop after N seconds
  --status             Ask the running Whereabouts how it is doing, and show
                       the top flows and apps
  --json               With --status, print only the status as one line of JSON
  --history            Show what is saved: top apps of the last 24 hours
  --export <FILE>      Write all saved flows to a CSV file
  --delete-all --yes   Delete all saved flows and totals (cannot be undone)

Blocking (the service must be running; --rules as administrator or as the
user Whereabouts was installed for, every change as administrator, so that
other programs cannot lift your blocks; or use the Whereabouts app):
  --rules              List the blocking rules
  --block-app <PATH>   Block every connection of a program
  --block-domain <NAME>
                       Block a domain and its subdomains (by the addresses
                       Windows' DNS service confirms for it)
  --block-ip <IP>      Block one remote address
  --for <PATH>         With --block-domain or --block-ip: only for this
                       program (default: every program)
  --unblock <ID>       Delete a rule and lift its block
  --pause-blocking     Lift every block but keep the rules
  --resume-blocking    Apply the rules again
  --unblock-all        Emergency: remove every Whereabouts block from the
                       firewall now, even if the service is not running, and
                       pause blocking (as administrator)

Service:
  --install            Install and start Whereabouts as a Windows service that
                       runs at boot (as administrator)
  --uninstall          Stop and remove the service; saved data is kept
  --delete-data        With --uninstall or --unregister, also delete all
                       saved data
  --register           Register and start the service for this program where
                       it is (in %ProgramFiles%\\Whereabouts; used by the
                       installer)
  --unregister         Stop and remove the service but keep the program
                       files and the blocks (used by the installer)
  --remove-blocks      With --unregister, also remove every Whereabouts block
                       from the firewall (--uninstall always does)
  --version            Print the version
  --help               Print this help

Saved data is kept in %ProgramData%\\Whereabouts (readable by administrators
only), encrypted. Windows starts the installed service with --service.";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Console {
        limit: Option<Duration>,
    },
    Status {
        /// Print the status as one line of JSON (for scripts, e.g. the lab).
        json: bool,
    },
    History,
    Export(PathBuf),
    DeleteAll {
        confirmed: bool,
    },
    Install,
    Uninstall {
        delete_data: bool,
    },
    Register,
    Unregister {
        delete_data: bool,
        remove_blocks: bool,
    },
    Rules(RuleAction),
    UnblockAll,
    Service {
        client_user: String,
    },
    Version,
    Help,
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    let mut console = false;
    let mut seconds = None;
    let mut status = false;
    let mut json = false;
    let mut history = false;
    let mut export = None;
    let mut delete_all = false;
    let mut yes = false;
    let mut install = false;
    let mut uninstall = false;
    let mut register = false;
    let mut unregister = false;
    let mut delete_data = false;
    let mut service = false;
    let mut client_user = None;
    let mut remove_blocks = false;
    let mut rules: Option<RuleAction> = None;
    let mut target_for: Option<String> = None;
    let mut unblock_all = false;
    let set_rules = |rules: &mut Option<RuleAction>, action: RuleAction| -> Result<(), String> {
        if rules.replace(action).is_some() {
            return Err(String::from("choose only one blocking command"));
        }
        Ok(())
    };
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
            "--json" => json = true,
            "--history" => history = true,
            "--export" => {
                let value = iter.next().ok_or("--export needs a file name")?;
                export = Some(PathBuf::from(value));
            }
            "--delete-all" => delete_all = true,
            "--yes" => yes = true,
            "--install" => install = true,
            "--uninstall" => uninstall = true,
            "--register" => register = true,
            "--unregister" => unregister = true,
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
            "--remove-blocks" => remove_blocks = true,
            "--rules" => set_rules(&mut rules, RuleAction::List)?,
            "--block-app" => {
                let value = iter.next().ok_or("--block-app needs a program path")?;
                set_rules(&mut rules, RuleAction::BlockApp(PathBuf::from(value)))?;
            }
            "--block-domain" => {
                let value = iter.next().ok_or("--block-domain needs a domain name")?;
                set_rules(&mut rules, RuleAction::BlockDomain(value.clone(), None))?;
            }
            "--block-ip" => {
                let value = iter.next().ok_or("--block-ip needs an address")?;
                let ip: IpAddr = value
                    .parse()
                    .map_err(|_| format!("{value:?} is not an IP address"))?;
                set_rules(&mut rules, RuleAction::BlockIp(ip, None))?;
            }
            "--for" => {
                let value = iter.next().ok_or("--for needs a program path")?;
                target_for = Some(value.clone());
            }
            "--unblock" => {
                let value = iter
                    .next()
                    .ok_or("--unblock needs a rule ID (see --rules)")?;
                let id: i64 = value
                    .parse()
                    .map_err(|_| format!("--unblock expects a rule ID, got {value:?}"))?;
                set_rules(&mut rules, RuleAction::Unblock(id))?;
            }
            "--pause-blocking" => set_rules(&mut rules, RuleAction::Pause(true))?,
            "--resume-blocking" => set_rules(&mut rules, RuleAction::Pause(false))?,
            "--unblock-all" => unblock_all = true,
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
        register,
        unregister,
        service,
        rules.is_some(),
        unblock_all,
    ]
    .iter()
    .filter(|&&on| on)
    .count();
    if chosen > 1 {
        return Err(String::from(
            "choose only one of --console, --status, --history, --export, --delete-all, \
             --install, --uninstall, --register, --unregister, or a blocking command",
        ));
    }
    if json && !status {
        return Err(String::from("--json works only with --status"));
    }
    if seconds.is_some() && !console {
        return Err(String::from("--seconds only works with --console"));
    }
    if yes && !delete_all {
        return Err(String::from("--yes only works with --delete-all"));
    }
    if delete_data && !uninstall && !unregister {
        return Err(String::from(
            "--delete-data only works with --uninstall or --unregister",
        ));
    }
    if client_user.is_some() != service {
        return Err(String::from("--service and --client-user go together"));
    }
    if remove_blocks && !unregister {
        return Err(String::from("--remove-blocks only works with --unregister"));
    }
    if let Some(app) = target_for {
        rules = match rules {
            Some(RuleAction::BlockDomain(name, None)) => {
                Some(RuleAction::BlockDomain(name, Some(PathBuf::from(app))))
            }
            Some(RuleAction::BlockIp(ip, None)) => {
                Some(RuleAction::BlockIp(ip, Some(PathBuf::from(app))))
            }
            _ => {
                return Err(String::from(
                    "--for only works with --block-domain or --block-ip",
                ));
            }
        };
    }
    Ok(if console {
        Command::Console { limit: seconds }
    } else if status {
        Command::Status { json }
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
    } else if register {
        Command::Register
    } else if unregister {
        Command::Unregister {
            delete_data,
            // Without the saved rules, nothing could ever lift the blocks.
            remove_blocks: remove_blocks || delete_data,
        }
    } else if let Some(action) = rules {
        Command::Rules(action)
    } else if unblock_all {
        Command::UnblockAll
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
        Ok(Command::Status { json }) => client::status(json),
        Ok(Command::History) => storage::show_history(),
        Ok(Command::Export(path)) => storage::export(&path),
        Ok(Command::DeleteAll { confirmed }) => storage::delete_all(confirmed),
        Ok(Command::Install) => install::install(),
        Ok(Command::Uninstall { delete_data }) => install::uninstall(delete_data),
        Ok(Command::Register) => install::register(),
        Ok(Command::Unregister {
            delete_data,
            remove_blocks,
        }) => install::unregister(delete_data, remove_blocks),
        Ok(Command::Rules(action)) => client::rules(action),
        Ok(Command::UnblockAll) => blocking::unblock_all(),
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
        assert_eq!(
            parse_args(&args(&["--status"])),
            Ok(Command::Status { json: false })
        );
        assert_eq!(
            parse_args(&args(&["--status", "--json"])),
            Ok(Command::Status { json: true })
        );
        assert_eq!(
            parse_args(&args(&["--json"])),
            Err(String::from("--json works only with --status"))
        );
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
    fn parses_installer_commands() {
        assert_eq!(parse_args(&args(&["--register"])), Ok(Command::Register));
        assert_eq!(
            parse_args(&args(&["--unregister"])),
            Ok(Command::Unregister {
                delete_data: false,
                remove_blocks: false
            })
        );
        assert_eq!(
            parse_args(&args(&["--unregister", "--remove-blocks"])),
            Ok(Command::Unregister {
                delete_data: false,
                remove_blocks: true
            })
        );
        assert_eq!(
            parse_args(&args(&["--unregister", "--delete-data"])),
            Ok(Command::Unregister {
                delete_data: true,
                remove_blocks: true
            })
        );
    }

    #[test]
    fn parses_blocking_commands() {
        assert_eq!(
            parse_args(&args(&["--rules"])),
            Ok(Command::Rules(RuleAction::List))
        );
        assert_eq!(
            parse_args(&args(&["--block-app", r"C:\x.exe"])),
            Ok(Command::Rules(RuleAction::BlockApp(PathBuf::from(
                r"C:\x.exe"
            ))))
        );
        assert_eq!(
            parse_args(&args(&["--block-domain", "ads.example.com"])),
            Ok(Command::Rules(RuleAction::BlockDomain(
                String::from("ads.example.com"),
                None
            )))
        );
        assert_eq!(
            parse_args(&args(&["--block-ip", "203.0.113.5", "--for", r"C:\x.exe"])),
            Ok(Command::Rules(RuleAction::BlockIp(
                "203.0.113.5".parse().unwrap(),
                Some(PathBuf::from(r"C:\x.exe"))
            )))
        );
        assert_eq!(
            parse_args(&args(&["--unblock", "4"])),
            Ok(Command::Rules(RuleAction::Unblock(4)))
        );
        assert_eq!(
            parse_args(&args(&["--pause-blocking"])),
            Ok(Command::Rules(RuleAction::Pause(true)))
        );
        assert_eq!(
            parse_args(&args(&["--resume-blocking"])),
            Ok(Command::Rules(RuleAction::Pause(false)))
        );
        assert_eq!(
            parse_args(&args(&["--unblock-all"])),
            Ok(Command::UnblockAll)
        );
    }

    #[test]
    fn rejects_bad_blocking_input() {
        assert!(parse_args(&args(&["--block-ip", "example.com"])).is_err());
        assert!(parse_args(&args(&["--block-app"])).is_err());
        assert!(parse_args(&args(&["--unblock", "x"])).is_err());
        assert!(parse_args(&args(&["--for", r"C:\x.exe"])).is_err());
        assert!(parse_args(&args(&["--block-app", "a.exe", "--for", "b.exe"])).is_err());
        assert!(parse_args(&args(&["--rules", "--pause-blocking"])).is_err());
        assert!(parse_args(&args(&["--rules", "--status"])).is_err());
        assert!(parse_args(&args(&["--unblock-all", "--rules"])).is_err());
        assert!(parse_args(&args(&["--remove-blocks"])).is_err());
        assert!(parse_args(&args(&["--uninstall", "--remove-blocks"])).is_err());
    }

    #[test]
    fn rejects_bad_service_input() {
        assert!(parse_args(&args(&["--service"])).is_err());
        assert!(parse_args(&args(&["--client-user", "S-1-5-18"])).is_err());
        assert!(parse_args(&args(&["--service", "--client-user", "WD"])).is_err());
        assert!(parse_args(&args(&["--service", "--client-user", "S-1)(A;;GA;;;WD"])).is_err());
        assert!(parse_args(&args(&["--delete-data"])).is_err());
        assert!(parse_args(&args(&["--install", "--uninstall"])).is_err());
        assert!(parse_args(&args(&["--register", "--delete-data"])).is_err());
        assert!(parse_args(&args(&["--register", "--unregister"])).is_err());
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
