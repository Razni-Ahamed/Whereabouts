//! `--install` and `--uninstall`: set Whereabouts up as a Windows service.
//!
//! The program is copied to `%ProgramFiles%\Whereabouts`, which only
//! administrators can change, so the SYSTEM service never runs a file that
//! a normal user could replace. The user who installs it becomes the
//! account allowed to use the service's pipe.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use whereabouts_win_capture::identity::same_file;
use whereabouts_win_pipe::current_user_sid;
use whereabouts_win_secrets::{KnownFolder, known_folder};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::service_mode::{SERVICE_NAME, describe};

/// The installed program's file name.
const PROGRAM: &str = "whereabouts-service.exe";

/// Offline data files copied with the program (see `data/README.md`).
const DATA_EXTENSIONS: [&str; 4] = ["mmdb", "tsv", "txt", "md"];

/// Windows error: the service does not exist.
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

const DESCRIPTION: &str = "Shows which app connects where, without reading what is sent. \
                           Keeps its history encrypted on this computer.";

/// The installation folder, `%ProgramFiles%\Whereabouts`.
fn install_dir() -> Result<PathBuf, String> {
    known_folder(KnownFolder::ProgramFiles)
        .map(|dir| dir.join("Whereabouts"))
        .map_err(|e| format!("could not find the Program Files folder ({e})"))
}

/// The installed program, if Whereabouts is installed.
pub fn installed_exe() -> Option<PathBuf> {
    let exe = install_dir().ok()?.join(PROGRAM);
    exe.is_file().then_some(exe)
}

/// `--install`.
pub fn install() -> ExitCode {
    match try_install() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// `--uninstall`, optionally deleting all saved data too.
pub fn uninstall(delete_data: bool) -> ExitCode {
    match try_uninstall(delete_data) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn try_install() -> Result<(), String> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| {
        format!(
            "could not open the Windows service manager ({}); run as administrator",
            describe(&e)
        )
    })?;
    if manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .is_ok()
    {
        return Err(String::from(
            "Whereabouts is already installed. To update it, run --uninstall first (saved \
             data is kept), then --install.",
        ));
    }
    let client_sid =
        current_user_sid().map_err(|e| format!("could not read the current account ({e})"))?;

    // Prepare the saved data as this account, which may have created the
    // key of an older version: it is moved to machine scope now, so the
    // service (SYSTEM) can read it.
    drop(crate::storage::open()?);

    let folder = install_dir()?;
    std::fs::create_dir_all(&folder)
        .map_err(|e| format!("could not create {} ({e})", folder.display()))?;
    let exe = folder.join(PROGRAM);
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    if !same_file(&source, &exe) {
        std::fs::copy(&source, &exe)
            .map_err(|e| format!("could not copy the program to {} ({e})", exe.display()))?;
    }
    let data_files = copy_data(&crate::console::data_dir(), &folder.join("data"))?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Whereabouts"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.clone(),
        launch_arguments: vec![
            OsString::from("--service"),
            OsString::from("--client-user"),
            OsString::from(&client_sid),
        ],
        dependencies: vec![],
        // LocalSystem: needed to read the kernel's network events.
        account_name: None,
        account_password: None,
    };
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|e| format!("could not create the service ({})", describe(&e)))?;
    let configure = || -> windows_service::Result<()> {
        service.set_description(DESCRIPTION)?;
        // Restart after a crash or error: after 10 s, then 60 s, then stay
        // stopped; the count resets after a day without failures.
        service.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(10),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(60),
                },
                ServiceAction {
                    action_type: ServiceActionType::None,
                    delay: Duration::default(),
                },
            ]),
        })?;
        service.set_failure_actions_on_non_crash_failures(true)
    };
    configure().map_err(|e| format!("could not configure the service ({})", describe(&e)))?;
    service
        .start::<&OsStr>(&[])
        .map_err(|e| format!("could not start the service ({})", describe(&e)))?;
    wait_for(&service, ServiceState::Running, Duration::from_secs(30))?;

    println!("Whereabouts is installed and running as a Windows service.");
    println!("  Program:   {}", exe.display());
    println!("  Data:      {data_files} offline data files");
    println!(
        "  History:   {} (encrypted)",
        crate::storage::home_dir().display()
    );
    println!("  Starts automatically with Windows, whoever is logged in.");
    println!("Check on it with:  \"{}\" --status", exe.display());
    println!("Remove it with:    \"{}\" --uninstall", exe.display());
    Ok(())
}

/// Copies the offline data files from `from` to `to`. Returns how many.
fn copy_data(from: &Path, to: &Path) -> Result<usize, String> {
    std::fs::create_dir_all(to).map_err(|e| format!("could not create {} ({e})", to.display()))?;
    let Ok(entries) = std::fs::read_dir(from) else {
        eprintln!(
            "warning: no offline data found in {}; company and country columns will be \
             empty (run scripts/update-data.ps1, then install again)",
            from.display()
        );
        return Ok(0);
    };
    let mut copied = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let wanted = path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|ext| DATA_EXTENSIONS.contains(&ext));
        // Plain files only: not folders and not links.
        let plain = entry.file_type().is_ok_and(|kind| kind.is_file());
        if !(wanted && plain) {
            continue;
        }
        let target = to.join(entry.file_name());
        if same_file(&path, &target) {
            copied += 1;
            continue;
        }
        std::fs::copy(&path, &target)
            .map_err(|e| format!("could not copy {} ({e})", path.display()))?;
        copied += 1;
    }
    Ok(copied)
}

/// Waits until `service` is in `state`.
fn wait_for(service: &Service, state: ServiceState, limit: Duration) -> Result<(), String> {
    let deadline = Instant::now() + limit;
    loop {
        let current = service
            .query_status()
            .map_err(|e| format!("could not query the service ({})", describe(&e)))?;
        if current.current_state == state {
            return Ok(());
        }
        if current.current_state == ServiceState::Stopped && state != ServiceState::Stopped {
            return Err(format!(
                "the service stopped right after starting (exit code {:?}); see the log in {}",
                current.exit_code,
                crate::storage::home_dir().display()
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the service did not reach {state:?} within {} seconds",
                limit.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn try_uninstall(delete_data: bool) -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| {
            format!(
                "could not open the Windows service manager ({})",
                describe(&e)
            )
        })?;
    match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(service) => {
            let state = service
                .query_status()
                .map_err(|e| format!("could not query the service ({})", describe(&e)))?
                .current_state;
            if state != ServiceState::Stopped {
                println!("Stopping the service (it saves its last flows first)...");
                if state != ServiceState::StopPending {
                    service
                        .stop()
                        .map_err(|e| format!("could not stop the service ({})", describe(&e)))?;
                }
                wait_for(&service, ServiceState::Stopped, Duration::from_secs(60))?;
            }
            service
                .delete()
                .map_err(|e| format!("could not remove the service ({})", describe(&e)))?;
            println!("The Whereabouts service is removed.");
        }
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) =>
        {
            println!("Whereabouts is not installed as a service.");
        }
        Err(error) => {
            return Err(format!(
                "could not open the service ({}); run as administrator",
                describe(&error)
            ));
        }
    }

    remove_program_folder(&install_dir()?);

    let home = crate::storage::home_dir();
    if delete_data {
        crate::storage::delete_folder()?;
        println!("All saved data is deleted ({}).", home.display());
    } else if home.exists() {
        println!(
            "Your saved history is kept in {} (encrypted). To delete it too, run \
             --uninstall --delete-data.",
            home.display()
        );
    }
    Ok(())
}

/// Removes the installation folder. The running program cannot delete its
/// own file, so when uninstalling from the installed copy, that one file is
/// left and the user is told.
fn remove_program_folder(folder: &Path) {
    if !folder.exists() {
        return;
    }
    let running = std::env::current_exe().ok();
    let is_running_copy = |path: &Path| running.as_deref().is_some_and(|exe| same_file(exe, path));
    if !is_running_copy(&folder.join(PROGRAM)) {
        // The service may hold its file for a moment after stopping.
        for _ in 0..20 {
            if std::fs::remove_dir_all(folder).is_ok() || !folder.exists() {
                println!("Removed {}.", folder.display());
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        eprintln!("warning: could not remove {}", folder.display());
        return;
    }
    let _ = std::fs::remove_dir_all(folder.join("data"));
    println!(
        "Removed the program's data files. This program cannot delete itself while running: \
         delete the folder {} to finish.",
        folder.display()
    );
}
