//! Looks up which executable a process ID belongs to.
//!
//! This is the first, simple step of app attribution (design spec §5.3).
//! Publisher signatures and file hashes come later.

#![allow(unsafe_code)]

use windows::Win32::Foundation::{CloseHandle, HMODULE};
use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetMappedFileNameW};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

/// Process ID of the Windows kernel ("System").
const SYSTEM_PID: u32 = 4;

/// Longest path accepted, in UTF-16 units (the Windows extended-path limit).
const MAX_PATH_UNITS: usize = 32_768;

/// Returns the full executable path of process `pid`, if it can be read.
///
/// Returns `None` for the idle process (PID 0), for processes that have
/// already exited, and for protected processes that deny access. PID 4 is
/// reported as `"System"`.
pub fn image_path(pid: u32) -> Option<String> {
    match pid {
        0 => return None,
        SYSTEM_PID => return Some(String::from("System")),
        _ => {}
    }

    // SAFETY: OpenProcess has no memory-safety preconditions. It returns an
    // error for invalid or inaccessible PIDs, which we turn into `None`.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;

    let mut buffer = vec![0u16; MAX_PATH_UNITS];
    let mut len = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
    // SAFETY: `buffer` is valid for writes of `len` UTF-16 units, and `len`
    // is a valid in/out pointer. On success Windows sets `len` to the number
    // of units written, excluding the terminating null.
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    };
    // SAFETY: `handle` came from OpenProcess above and is closed exactly once.
    // A failure to close cannot be handled usefully here, so it is ignored.
    let _ = unsafe { CloseHandle(handle) };

    result.ok()?;
    let len = usize::try_from(len).ok()?.min(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..len]))
}

/// Returns the device path (`\Device\HarddiskVolumeN\...`) of the file that
/// process `pid` is **actually running**, as mapped in its memory.
///
/// Unlike [`image_path`], which reports the path the program was started
/// from, this follows the file itself: if the program renamed its own file
/// after starting (and perhaps put a different file at the old path), this
/// returns the new name of the real file. Returns `None` if the process has
/// exited or cannot be opened (e.g. protected processes).
pub fn running_image_device_path(pid: u32) -> Option<String> {
    if pid == 0 || pid == SYSTEM_PID {
        return None;
    }
    // SAFETY: OpenProcess has no memory-safety preconditions.
    let handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }.ok()?;

    let mut module = HMODULE::default();
    let mut needed = 0u32;
    // SAFETY: `module` has room for exactly one module handle, which is the
    // size passed; the first module of a process is its main executable.
    let enumerated = unsafe {
        EnumProcessModules(
            handle,
            &mut module,
            u32::try_from(std::mem::size_of::<HMODULE>()).unwrap_or(0),
            &mut needed,
        )
    };
    let path = if enumerated.is_ok() && !module.is_invalid() {
        let mut buffer = vec![0u16; MAX_PATH_UNITS];
        // SAFETY: `buffer` is a writable slice; the function writes at most
        // its length. `module` is an address in the target process.
        let len = unsafe { GetMappedFileNameW(handle, module.0.cast_const(), &mut buffer) };
        let len = usize::try_from(len).unwrap_or(0).min(buffer.len());
        (len > 0).then(|| String::from_utf16_lossy(&buffer[..len]))
    } else {
        None
    };
    // SAFETY: `handle` came from OpenProcess above and is closed exactly once.
    let _ = unsafe { CloseHandle(handle) };
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_and_system_processes_are_special_cased() {
        assert_eq!(image_path(0), None);
        assert_eq!(image_path(SYSTEM_PID).as_deref(), Some("System"));
    }

    #[test]
    fn finds_the_current_process() {
        let path = image_path(std::process::id()).expect("own process is readable");
        let expected = std::env::current_exe().unwrap();
        assert!(
            path.eq_ignore_ascii_case(&expected.to_string_lossy()),
            "{path} vs {}",
            expected.display()
        );
    }

    #[test]
    fn finds_the_file_this_process_is_running() {
        let device = running_image_device_path(std::process::id()).expect("own process");
        let exe = std::env::current_exe().unwrap();
        let name = exe
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_ascii_lowercase();
        assert!(device.starts_with(r"\Device\"), "{device}");
        assert!(
            device.to_ascii_lowercase().ends_with(&name),
            "{device} vs {name}"
        );
    }

    #[test]
    fn unknown_pid_returns_none() {
        // PIDs are multiples of 4, so this one can never exist.
        assert_eq!(image_path(u32::MAX - 2), None);
    }
}
