//! Looks up which executable a process ID belongs to.
//!
//! This is the first, simple step of app attribution (design spec §5.3).
//! Publisher signatures and file hashes come later.

#![allow(unsafe_code)]

use std::time::SystemTime;

use std::collections::{HashMap, HashSet};

use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
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

    /// Whether the process runs with administrator rights (an elevated
    /// token). `false` if that cannot be read.
    pub fn is_elevated(&self) -> bool {
        let mut token = HANDLE::default();
        // SAFETY: the process handle is open; `token` is a valid out-pointer.
        if unsafe { OpenProcessToken(self.0, TOKEN_QUERY, &mut token) }.is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        // SAFETY: `elevation` is writable and its exact size is passed.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some((&raw mut elevation).cast()),
                u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(0),
                &mut len,
            )
        }
        .is_ok();
        // SAFETY: `token` was opened above and is closed once.
        let _ = unsafe { CloseHandle(token) };
        read && elevation.TokenIsElevated != 0
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcess and is closed exactly
        // once. A failure to close cannot be handled usefully here.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Every running process's ID and its parent's ID.
fn parents() -> Vec<(u32, u32)> {
    // SAFETY: no pointers are passed; the snapshot handle is closed below.
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return Vec::new();
    };
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(0),
        ..PROCESSENTRY32W::default()
    };
    let mut pairs = Vec::new();
    // SAFETY: `entry` is a writable PROCESSENTRY32W with `dwSize` set, as
    // the snapshot functions require; the snapshot handle is valid.
    let mut found = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();
    while found {
        pairs.push((entry.th32ProcessID, entry.th32ParentProcessID));
        // SAFETY: as above.
        found = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
    }
    // SAFETY: the snapshot handle is closed exactly once.
    let _ = unsafe { CloseHandle(snapshot) };
    pairs
}

/// The processes that process `root` started, directly or indirectly (for
/// example an app's WebView2 helper processes).
///
/// Windows reuses process IDs, so a process whose recorded parent ID is in
/// the tree but which started *before* that parent is someone else's child
/// and is left out. When a start time cannot be read, the process is kept:
/// for counting Whereabouts' own connections, counting a stranger is safer
/// than missing one of ours.
pub fn descendants(root: u32) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, parent) in parents() {
        if pid != parent {
            children.entry(parent).or_default().push(pid);
        }
    }
    let started = |pid: u32| ProcessHandle::open(pid).and_then(|p| p.start_time());
    let mut found = Vec::new();
    let mut seen = HashSet::from([root]);
    let mut queue = vec![(root, started(root))];
    while let Some((parent, parent_start)) = queue.pop() {
        for &child in children.get(&parent).into_iter().flatten() {
            if !seen.insert(child) {
                continue;
            }
            let child_start = started(child);
            if let (Some(parent_start), Some(child_start)) = (parent_start, child_start)
                && child_start < parent_start
            {
                continue;
            }
            found.push(child);
            queue.push((child, child_start));
        }
    }
    found
}

/// The nearest ancestor of process `pid` whose program file is not called
/// `name` (compared without regard to case), with its full path: for a
/// WebView2 process, the app that shows the web content.
///
/// Strict about reused process IDs: a recorded parent that started after
/// its child is someone else, and if a start time or path cannot be read
/// the answer is `None`. Crediting traffic to the wrong app is worse than
/// not crediting it.
pub fn ancestor_not_named(pid: u32, name: &str) -> Option<(u32, String)> {
    /// Deeper than any real WebView2 tree (app → browser → utility).
    const MAX_DEPTH: usize = 6;
    let parent_of: HashMap<u32, u32> = parents().into_iter().collect();
    let mut current = ProcessHandle::open(pid)?;
    let mut current_start = current.start_time()?;
    let mut current_pid = pid;
    for _ in 0..MAX_DEPTH {
        let parent_pid = *parent_of.get(&current_pid)?;
        if parent_pid == current_pid {
            return None;
        }
        let parent = ProcessHandle::open(parent_pid)?;
        let parent_start = parent.start_time()?;
        if parent_start > current_start {
            return None; // the ID was reused by a later process
        }
        let path = parent.image_path()?;
        let file = path.rsplit('\\').next().unwrap_or(&path);
        if !file.eq_ignore_ascii_case(name) {
            return Some((parent_pid, path));
        }
        (current, current_start, current_pid) = (parent, parent_start, parent_pid);
    }
    drop(current);
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_nearest_ancestor_with_another_name() {
        // This test process starts cmd, which starts another cmd: the
        // nearest ancestor of the inner cmd not called cmd.exe is this test.
        let mut child = std::process::Command::new(r"C:\Windows\System32\cmd.exe")
            .args([
                "/c",
                r"C:\Windows\System32\cmd.exe /c ping -n 4 127.0.0.1 > nul",
            ])
            .spawn()
            .unwrap();
        let mut inner = None;
        for _ in 0..40 {
            inner = descendants(child.id()).into_iter().next();
            if inner.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let inner = inner.expect("the inner cmd started");
        let found = ancestor_not_named(inner, "CMD.EXE");
        let _ = child.kill();
        let _ = child.wait();
        let (pid, path) = found.expect("an ancestor");
        assert_eq!(pid, std::process::id());
        let own = std::env::current_exe().unwrap();
        assert!(
            path.eq_ignore_ascii_case(&own.to_string_lossy()),
            "{path} vs {}",
            own.display()
        );
        assert_eq!(ancestor_not_named(0, "cmd.exe"), None);
    }

    #[test]
    fn finds_children_and_grandchildren() {
        // cmd starts another cmd, which waits a few seconds.
        let mut child = std::process::Command::new(r"C:\Windows\System32\cmd.exe")
            .args([
                "/c",
                r"C:\Windows\System32\cmd.exe /c ping -n 4 127.0.0.1 > nul",
            ])
            .spawn()
            .unwrap();
        let mut found = Vec::new();
        for _ in 0..40 {
            found = descendants(std::process::id());
            if found.len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let child_id = child.id();
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            found.contains(&child_id),
            "{found:?} should contain {child_id}"
        );
        assert!(
            found.len() >= 2,
            "the grandchild should be found too: {found:?}"
        );
        assert!(!found.contains(&std::process::id()));
    }

    #[test]
    fn a_process_with_no_children_has_no_descendants() {
        // The System process's children are kernel-started; an exited or
        // made-up ID has none.
        assert!(descendants(u32::MAX - 3).is_empty());
    }

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
