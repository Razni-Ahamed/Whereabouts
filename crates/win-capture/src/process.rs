//! Looks up which executable a process ID belongs to.
//!
//! This is the first, simple step of app attribution (design spec §5.3).
//! Publisher signatures and file hashes come later.

#![allow(unsafe_code)]

use std::time::SystemTime;

use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use crate::events::filetime_to_system_time;

/// Process ID of the Windows kernel ("System").
const SYSTEM_PID: u32 = 4;

/// Longest path accepted, in UTF-16 units (the Windows extended-path limit).
const MAX_PATH_UNITS: usize = 32_768;

/// Returns the full executable path of process `pid`, if it can be read.
///
/// This is the kernel's own record of the process's image file, not
/// anything the process can edit in its memory. It follows the file: if
/// the program renamed its own file after starting, this returns the new
/// name (verified on Windows 11 by `tests/running_image.rs`).
///
/// Returns `None` for the idle process (PID 0), for processes that have
/// already exited, and for protected processes that deny access. PID 4 is
/// reported as `"System"`.
pub fn image_path(pid: u32) -> Option<String> {
    if pid == SYSTEM_PID {
        return Some(String::from("System"));
    }
    ProcessHandle::open(pid)?.image_path()
}

/// An open handle to a process. While it is open, Windows cannot give the
/// process's ID to another process, so checks made through it are about
/// one process, even if the ID is looked up again.
#[derive(Debug)]
pub struct ProcessHandle(HANDLE);

impl ProcessHandle {
    /// Opens process `pid` for limited queries. `None` for the idle and
    /// System processes, and for processes that cannot be opened.
    pub fn open(pid: u32) -> Option<Self> {
        if pid == 0 || pid == SYSTEM_PID {
            return None;
        }
        // SAFETY: OpenProcess has no memory-safety preconditions. It returns
        // an error for invalid or inaccessible PIDs, which become `None`.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        Some(Self(handle))
    }

    /// The process's executable path (the kernel's record, which follows
    /// renames; see [`image_path`]).
    pub fn image_path(&self) -> Option<String> {
        let mut buffer = vec![0u16; MAX_PATH_UNITS];
        let mut len = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: `buffer` is valid for writes of `len` UTF-16 units, and
        // `len` is a valid in/out pointer. On success Windows sets `len` to
        // the number of units written, excluding the terminating null.
        unsafe {
            QueryFullProcessImageNameW(
                self.0,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut len,
            )
        }
        .ok()?;
        let len = usize::try_from(len).ok()?.min(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..len]))
    }

    /// When the process started.
    pub fn start_time(&self) -> Option<SystemTime> {
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: all four out-pointers are valid FILETIMEs; the handle is
        // open.
        unsafe { GetProcessTimes(self.0, &mut created, &mut exited, &mut kernel, &mut user) }
            .ok()?;
        let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        Some(filetime_to_system_time(i64::try_from(ticks).ok()?))
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcess and is closed exactly
        // once. A failure to close cannot be handled usefully here.
        let _ = unsafe { CloseHandle(self.0) };
    }
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
    fn a_process_handle_reports_path_and_start_time() {
        let process = ProcessHandle::open(std::process::id()).unwrap();
        let start = process.start_time().unwrap();
        assert!(start <= SystemTime::now());
        let age = SystemTime::now().duration_since(start).unwrap();
        assert!(age.as_secs() < 3600, "started {age:?} ago");
        assert_eq!(process.image_path(), image_path(std::process::id()));
        assert!(ProcessHandle::open(0).is_none());
        assert!(ProcessHandle::open(4).is_none());
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
    fn unknown_pid_returns_none() {
        // PIDs are multiples of 4, so this one can never exist.
        assert_eq!(image_path(u32::MAX - 2), None);
    }
}
