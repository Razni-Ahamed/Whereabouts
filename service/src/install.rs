//! Setting Whereabouts up as a Windows service.
//!
//! - `--install` / `--uninstall`: copy the programs to
//!   `%ProgramFiles%\Whereabouts` and register the service (for builds from
//!   source).
//! - `--register` / `--unregister`: register or remove the service for the
//!   program where it already is, which must be that folder (used by the
//!   installer, which copies the files itself).
//!
//! Only administrators can change that folder, so the SYSTEM service never
//! runs a file that a normal user could replace. The user who installs it
//! becomes the account allowed to use the service's pipe.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use whereabouts_client::{APP_PROGRAM, SERVICE_PROGRAM};
use whereabouts_win_capture::identity::{same_file, same_folder};
use whereabouts_win_pipe::current_user_sid;
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::service_mode::{SERVICE_NAME, describe};

/// Offline data files copied with the program (see `data/README.md`).
const DATA_EXTENSIONS: [&str; 4] = ["mmdb", "tsv", "txt", "md"];

/// Windows error: the service does not exist.
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

const DESCRIPTION: &str = "Shows which app connects where, without reading what is sent. \
                           Keeps its history encrypted on this computer.";

/// The installation folder, `%ProgramFiles%\Whereabouts`.
fn install_dir() -> Result<PathBuf, String> {
    whereabouts_client::install_dir()
        .map_err(|e| format!("could not find the Program Files folder ({e})"))
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

/// `--register`: registers and starts the service for this program, which
/// must already be in the installation folder.
pub fn register() -> ExitCode {
    match try_register() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// `--unregister`: stops and removes the service, leaving the program files
/// (the installer removes those), optionally deleting all saved data too.
pub fn unregister(delete_data: bool) -> ExitCode {
    let result = remove_service().and_then(|()| finish_data(delete_data));
    match result {
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

/// Opens the Service Control Manager for creating a service, and checks
/// Whereabouts is not registered yet.
fn manager_for_create() -> Result<ServiceManager, String> {
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
    // Prepare the saved data as this account, which may have created the
    // key of an older version: it is moved to machine scope now, so the
    // service (SYSTEM) can read it.
    drop(crate::storage::open()?);
    Ok(manager)
}

fn try_register() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let folder = install_dir()?;
    let in_place = exe
        .parent()
        .is_some_and(|parent| same_folder(parent, &folder));
    if !in_place {
        return Err(format!(
            "--register only works for the program installed in {} (this one is {}); use \
             --install instead",
            folder.display(),
            exe.display()
        ));
    }
    let manager = manager_for_create()?;
    create_service(&manager, &exe)?;
    println!(
        "The Whereabouts service is registered and running ({}).",
        exe.display()
    );
    Ok(())
}

/// Registers the service for the program `exe` (LocalSystem, automatic
/// start, restart after failures, the current user as the pipe's client),
/// starts it and waits until it runs.
fn create_service(manager: &ServiceManager, exe: &Path) -> Result<(), String> {
    let client_sid =
        current_user_sid().map_err(|e| format!("could not read the current account ({e})"))?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Whereabouts"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
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
    wait_for(&service, ServiceState::Running, Duration::from_secs(30))
}

fn try_install() -> Result<(), String> {
    let manager = manager_for_create()?;
    let folder = install_dir()?;
    std::fs::create_dir_all(&folder)
        .map_err(|e| format!("could not create {} ({e})", folder.display()))?;
    let exe = folder.join(SERVICE_PROGRAM);
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    copy_program(&source, &exe)?;
    // The desktop app, when it was built next to this program.
    let app_source = source.with_file_name(APP_PROGRAM);
    let app = folder.join(APP_PROGRAM);
    let has_app = app_source.is_file();
    if has_app {
        copy_program(&app_source, &app)?;
    }
    let data_files = copy_data(&crate::console::data_dir(), &folder.join("data"))?;
    create_service(&manager, &exe)?;

    println!("Whereabouts is installed and running as a Windows service.");
    println!("  Program:   {}", exe.display());
    if has_app {
        println!("  App:       {}", app.display());
    } else {
        println!(
            "  App:       not installed ({APP_PROGRAM} was not found next to this program; \
             build it with `npm run tauri build` in ui/)"
        );
    }
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

/// Copies a program file, unless `from` already is `to`.
fn copy_program(from: &Path, to: &Path) -> Result<(), String> {
    if same_file(from, to) {
        return Ok(());
    }
    std::fs::copy(from, to).map(|_| ()).map_err(|e| {
        format!(
            "could not copy {} to {} ({e})",
            from.display(),
            to.display()
        )
    })
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
    remove_service()?;
    remove_program_folder(&install_dir()?);
    finish_data(delete_data)
}

/// Stops (letting it save its last flows) and removes the service, if it is
/// registered.
fn remove_service() -> Result<(), String> {
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
    Ok(())
}

/// Deletes all saved data if asked, otherwise says where it is kept.
fn finish_data(delete_data: bool) -> Result<(), String> {
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
    if !is_running_copy(&folder.join(SERVICE_PROGRAM)) {
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
    let _ = std::fs::remove_file(folder.join(APP_PROGRAM));
    println!(
        "Removed the program's data files. This program cannot delete itself while running: \
         delete the folder {} to finish.",
        folder.display()
    );
}
