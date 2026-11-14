//! Who is on the other end of the pipe.
//!
//! Both ends learn the other's process ID from Windows. A process ID alone
//! proves little (IDs are reused), so each check opens the process first
//! and works only through that handle, rejects a process that started after
//! the connection was made (a reused ID), and locks the process's running
//! file, as for app identity, before looking at it.

use std::fs::File;
use std::path::Path;
use std::time::SystemTime;

use whereabouts_win_capture::identity::{is_same_file, lock_image_of, same_folder};
use whereabouts_win_capture::process::ProcessHandle;
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::{SERVICE_NAME, install_dir};

/// Opens process `pid` (which connected at or before `connected_by`) and
/// locks the file it runs. Returns its path and the locked file.
fn locked_image(pid: u32, connected_by: SystemTime) -> Option<(String, File)> {
    let process = ProcessHandle::open(pid)?;
    if process
        .start_time()
        .is_none_or(|started| started > connected_by)
    {
        return None;
    }
    lock_image_of(&process)
}

/// Whether `file` is directly inside the installation folder (compared by
/// folder ID, so spelling cannot fool it).
fn in_install_dir(file: &Path) -> bool {
    let (Some(parent), Ok(install)) = (file.parent(), install_dir()) else {
        return false;
    };
    same_folder(parent, &install)
}

/// Whether process `pid` runs the same program file as this process.
pub fn runs_same_file(pid: u32, connected_by: SystemTime) -> bool {
    let Some((_, file)) = locked_image(pid, connected_by) else {
        return false;
    };
    std::env::current_exe().is_ok_and(|own| is_same_file(&file, &own))
}

/// Whether the service may answer client `pid`: it runs the service's own
/// program file, or, when the service runs from the installation folder,
/// another program in that same folder (such as the desktop app). Only
/// administrators can put files there.
pub fn is_trusted_client(pid: u32, connected_by: SystemTime) -> bool {
    let Some((path, file)) = locked_image(pid, connected_by) else {
        return false;
    };
    let Ok(own) = std::env::current_exe() else {
        return false;
    };
    if is_same_file(&file, &own) {
        return true;
    }
    in_install_dir(&own) && in_install_dir(Path::new(&path))
}

/// Process ID of the running Whereabouts service, as the Service Control
/// Manager reports it. Any user may ask; only administrators can register
/// a service under this name.
pub fn service_process_id() -> Option<u32> {
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

/// Whether a client can trust the pipe server `pid`: it is the installed
/// Whereabouts service (its process ID per the Service Control Manager), or
/// it runs the same program file as this process (console mode).
///
/// The first check is needed because a normal user cannot open a SYSTEM
/// service's process to look at its file.
pub fn is_trusted_server(pid: u32, connected_by: SystemTime) -> bool {
    service_process_id() == Some(pid) || runs_same_file(pid, connected_by)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn this_process_is_recognised_and_others_are_not() {
        let now = SystemTime::now();
        assert!(runs_same_file(std::process::id(), now));
        assert!(is_trusted_client(std::process::id(), now));
        assert!(!runs_same_file(0, now));
        assert!(!runs_same_file(4, now));
    }

    #[test]
    fn a_process_that_started_after_the_connection_is_rejected() {
        // As if the connecting process had exited and its ID been reused by
        // this process: the connection predates our start.
        let long_ago = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        assert!(!runs_same_file(std::process::id(), long_ago));
        assert!(!is_trusted_client(std::process::id(), long_ago));
    }

    #[test]
    fn another_program_is_rejected() {
        let mut child = std::process::Command::new(r"C:\Windows\System32\cmd.exe")
            .args(["/c", "ping -n 3 127.0.0.1 > nul"])
            .spawn()
            .unwrap();
        let now = SystemTime::now();
        let rejected = !runs_same_file(child.id(), now) && !is_trusted_client(child.id(), now);
        let _ = child.kill();
        let _ = child.wait();
        assert!(rejected);
    }

    #[test]
    fn folders_compare_by_id() {
        let dir = std::env::temp_dir().join(format!("whereabouts-peer-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        assert!(same_folder(&dir, &dir.join("sub").join("..")));
        assert!(same_folder(&dir, &dir.join("SUB").join("..")));
        assert!(!same_folder(&dir, &dir.join("sub")));
        assert!(!same_folder(&dir, &dir.join("missing")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn programs_outside_the_install_folder_are_not_in_it() {
        assert!(!in_install_dir(&std::env::current_exe().unwrap()));
        assert!(!in_install_dir(Path::new(r"C:\Windows\System32\cmd.exe")));
    }
}
