//! Running as a Windows service (design spec §5.1): started by Windows at
//! boot as LocalSystem, independent of who is logged in.

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

/// The service's name in Windows.
pub const SERVICE_NAME: &str = "Whereabouts";

/// The account allowed to use the pipe, from the service's command line.
static CLIENT_USER: OnceLock<String> = OnceLock::new();
/// Set when Windows asks the service to stop.
static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();
/// For reporting progress while stopping.
static STATUS: OnceLock<ServiceStatusHandle> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Entry point when Windows starts the installed service. `client_user` is
/// the account (SID) of the user who installed it.
pub fn run(client_user: String) -> ExitCode {
    let _ = CLIENT_USER.set(client_user);
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "error: {}. --service is how Windows starts the installed service; use \
                 --install to install it, or --console to run in this terminal",
                describe(&error)
            );
            ExitCode::FAILURE
        }
    }
}

/// A readable reason for a service error (the crate's own text hides the
/// Windows error).
pub fn describe(error: &windows_service::Error) -> String {
    match error {
        windows_service::Error::Winapi(io) => io.to_string(),
        other => other.to_string(),
    }
}

/// Process ID of the running Whereabouts service, as the Service Control
/// Manager reports it. Any user may ask; only administrators can register
/// a service under this name.
pub fn process_id() -> Option<u32> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .ok()?;
    let status = service.query_status().ok()?;
    let running = matches!(
        status.current_state,
        ServiceState::Running | ServiceState::StopPending
    );
    status.process_id.filter(|&pid| running && pid != 0)
}

/// Whether the Whereabouts service is installed and not stopped.
pub fn is_running() -> bool {
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return false;
    };
    let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) else {
        return false;
    };
    service
        .query_status()
        .is_ok_and(|status| status.current_state != ServiceState::Stopped)
}

fn status(state: ServiceState, accept: ServiceControlAccept, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: if exit == 0 {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(exit)
        },
        checkpoint: 0,
        // Saving the last flows can take a few seconds.
        wait_hint: if state == ServiceState::StopPending {
            Duration::from_secs(30)
        } else {
            Duration::default()
        },
        process_id: None,
    }
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        report!("error: service: {}", describe(&error));
    }
}

fn run_service() -> windows_service::Result<()> {
    let stop = Arc::clone(STOP.get_or_init(|| Arc::new(AtomicBool::new(false))));
    let handle = service_control_handler::register(SERVICE_NAME, |control| match control {
        // Pre-shutdown gives time to save the last flows before Windows
        // shuts down.
        ServiceControl::Stop | ServiceControl::Preshutdown | ServiceControl::Shutdown => {
            if let Some(stop) = STOP.get() {
                stop.store(true, Ordering::Release);
            }
            if let Some(handle) = STATUS.get() {
                let _ = handle.set_service_status(status(
                    ServiceState::StopPending,
                    ServiceControlAccept::empty(),
                    0,
                ));
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let _ = STATUS.set(handle);

    // Without a terminal, warnings go to a log in the protected data folder.
    match crate::storage::open_log() {
        Ok(()) => {}
        Err(error) => eprintln!("warning: no log file: {error}"),
    }

    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
        0,
    ))?;
    report!("Whereabouts {} service started", env!("CARGO_PKG_VERSION"));

    let data_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("data")));
    let result = crate::console::run_engine(&crate::console::Options {
        limit: None,
        show_table: false,
        stop: Some(stop),
        client_sid: CLIENT_USER.get().cloned(),
        data_dir,
    });
    let exit = match result {
        Ok(()) => {
            report!("Whereabouts service stopped");
            0
        }
        Err(error) => {
            report!("error: {error}");
            1
        }
    };
    handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
    ))
}
