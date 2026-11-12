//! Looks up which process hosts a Windows service.
//!
//! Used to trust only the DNS events that really come from the Windows DNS
//! Client service: any program can write events under the DNS Client ETW
//! provider's ID, but Windows stamps each event with the real writer's
//! process ID, which an ordinary program cannot fake.

#![allow(unsafe_code)]

use std::mem::size_of;

use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
};
use windows::core::{HSTRING, PCWSTR};

/// Name of the Windows DNS Client service.
pub const DNS_CLIENT_SERVICE: &str = "Dnscache";

/// Closes a service-control handle when dropped.
struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW or OpenServiceW and is
        // closed exactly once, here. A failure to close cannot be handled.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

/// Returns the ID of the process hosting service `name`, or `None` if the
/// service does not exist, is not running, or cannot be queried.
///
/// Needs no administrator rights.
pub fn service_process_id(name: &str) -> Option<u32> {
    // SAFETY: null names select the local service control manager; no
    // pointers are kept after the call.
    let manager =
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }.ok()?;
    let manager = ServiceHandle(manager);

    let name = HSTRING::from(name);
    // SAFETY: `name` is a valid null-terminated string that outlives the call.
    let service = unsafe { OpenServiceW(manager.0, &name, SERVICE_QUERY_STATUS) }.ok()?;
    let service = ServiceHandle(service);

    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0u32;
    // SAFETY: the byte slice covers exactly `status`, a plain-data struct
    // that lives for the whole call, and is not used through any other
    // reference while the slice exists.
    let result = unsafe {
        let buffer = std::slice::from_raw_parts_mut(
            (&raw mut status).cast::<u8>(),
            size_of::<SERVICE_STATUS_PROCESS>(),
        );
        QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, Some(buffer), &mut needed)
    };
    result.ok()?;
    (status.dwProcessId != 0).then_some(status.dwProcessId)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_dns_client_service() {
        let pid = service_process_id(DNS_CLIENT_SERVICE).expect("Dnscache is running");
        assert!(pid > 4, "unexpected PID {pid}");
    }

    #[test]
    fn unknown_service_returns_none() {
        assert_eq!(service_process_id("Whereabouts-NoSuchService"), None);
    }
}
