//! Locked-down local named pipes for the Whereabouts service and its
//! clients (design spec §5.8).
//!
//! - **Local only**: remote clients are rejected (`PIPE_REJECT_REMOTE_CLIENTS`)
//!   and network logons are denied in the pipe's permissions.
//! - **Only allowed accounts**: SYSTEM, Administrators and one named user
//!   (the user who runs Whereabouts) may connect.
//! - **No squatting**: the server creates the first instance with
//!   `FILE_FLAG_FIRST_PIPE_INSTANCE`, so it fails if another program already
//!   owns the pipe name, instead of silently sharing it.
//! - Both sides can learn the other's process ID, so the caller can check
//!   which program is on the other end before trusting it.
//!
//! `unsafe` is used only for these Windows API calls; every block has a
//! `// SAFETY:` comment.

#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::time::SystemTime;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS,
    TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenOwner, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, SECURITY_ANONYMOUS,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{HRESULT, HSTRING, PWSTR};

/// Access the account running Whereabouts gets on the pipe, and all a
/// client asks for: read (`FILE_GENERIC_READ`) and write data
/// (`FILE_WRITE_DATA`), plus `FILE_WRITE_EA` and `FILE_WRITE_ATTRIBUTES`.
///
/// Deliberately *not* generic write: for a pipe, `FILE_APPEND_DATA` means
/// `FILE_CREATE_PIPE_INSTANCE`, which would let any program running as
/// that account add its own instances of our pipe and receive our clients.
const USER_ACCESS: u32 = 0x0012_019B;

/// What a client opens the pipe with: `FILE_GENERIC_READ | FILE_WRITE_DATA`.
const CLIENT_ACCESS: u32 = 0x0012_008B;

/// Win32 error: all pipe instances are busy.
const ERROR_PIPE_BUSY: i32 = 231;

/// Pipe buffer size in bytes.
const BUFFER: u32 = 64 * 1024;

/// Returns the security identifier (e.g. `S-1-5-21-…`) of the account this
/// process runs as.
pub fn current_user_sid() -> io::Result<String> {
    token_sid(TokenUser, |buffer| {
        // SAFETY: the buffer holds a TOKEN_USER (read unaligned, since a
        // Vec<u8> has no alignment guarantee).
        let user: TOKEN_USER = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast()) };
        user.User.Sid
    })
}

/// Returns the security identifier that owns what this process creates:
/// Administrators for an elevated administrator, SYSTEM for a service, and
/// the user themself otherwise.
fn current_owner_sid() -> io::Result<String> {
    token_sid(TokenOwner, |buffer| {
        // SAFETY: the buffer holds a TOKEN_OWNER (read unaligned).
        let owner: TOKEN_OWNER = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast()) };
        owner.Owner
    })
}

/// Reads one SID-valued property of this process's token as text.
/// `sid_of` finds the SID in the returned buffer (it points into it).
fn token_sid(class: TOKEN_INFORMATION_CLASS, sid_of: impl Fn(&[u8]) -> PSID) -> io::Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; `token` is writable.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|e| io::Error::other(format!("OpenProcessToken failed: {e}")))?;
    let result = (|| {
        let mut needed = 0u32;
        // SAFETY: first call only asks for the size.
        let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut needed) };
        let mut buffer = vec![0u8; usize::try_from(needed).unwrap_or(0)];
        // SAFETY: `buffer` has room for `needed` bytes.
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(buffer.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        }
        .map_err(|e| io::Error::other(format!("GetTokenInformation failed: {e}")))?;
        let sid = sid_of(&buffer);
        let mut text = PWSTR::null();
        // SAFETY: the SID points into `buffer`, which is alive; `text`
        // receives a LocalAlloc'd string freed below.
        unsafe { ConvertSidToStringSidW(sid, &mut text) }
            .map_err(|e| io::Error::other(format!("ConvertSidToStringSidW failed: {e}")))?;
        // SAFETY: `text` is a valid null-terminated string from the call.
        let sid = unsafe { text.to_string() }.map_err(io::Error::other);
        // SAFETY: allocated by ConvertSidToStringSidW; freed once.
        let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
        sid
    })();
    // SAFETY: `token` was opened above and is closed once.
    let _ = unsafe { CloseHandle(token) };
    result
}

/// Refuses anything but a SID string ("S", digits and dashes), so it cannot
/// change the meaning of a security descriptor.
fn checked_sid(sid: &str) -> io::Result<&str> {
    let valid = sid.starts_with("S-") && sid[2..].bytes().all(|b| b.is_ascii_digit() || b == b'-');
    if valid {
        Ok(sid)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a valid account identifier",
        ))
    }
}

/// Pipe permissions: network logons denied; full access for SYSTEM,
/// Administrators and `server_sid` (the owner of what the server creates,
/// which needs to add the pipe's next instances); read and write, but not
/// creating instances (see [`USER_ACCESS`]), for `user_sid`.
///
/// When Whereabouts runs elevated or as a service, `server_sid` is
/// Administrators or SYSTEM, so other programs of the user cannot add
/// instances. Only an unelevated server (development and tests) gives its
/// own account that right, and there the server and the account's other
/// programs cannot be told apart anyway.
fn pipe_sddl(server_sid: &str, user_sid: &str) -> io::Result<String> {
    let server_sid = checked_sid(server_sid)?;
    let user_sid = checked_sid(user_sid)?;
    Ok(format!(
        "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{server_sid})\
         (A;;0x{USER_ACCESS:08x};;;{user_sid})"
    ))
}

/// A security descriptor freed when dropped.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `sddl` lives for the call; `descriptor` receives a
        // LocalAlloc'd descriptor freed in Drop.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &HSTRING::from(sddl),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|e| io::Error::other(format!("invalid pipe permissions: {e}")))?;
        Ok(Self(descriptor))
    }
}

// SAFETY: the descriptor is a heap block owned only by this value and never
// changed after creation, so moving it to another thread is fine.
unsafe impl Send for Descriptor {}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the conversion; freed exactly once.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

/// The server end: accepts one client at a time on a named pipe.
pub struct PipeListener {
    name: HSTRING,
    descriptor: Descriptor,
    /// The instance waiting for the next client.
    pending: Option<File>,
}

impl std::fmt::Debug for PipeListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeListener")
            .field("name", &self.name.to_string())
            .finish()
    }
}

impl PipeListener {
    /// Creates the pipe `name` (e.g. `\\.\pipe\Whereabouts`) that SYSTEM,
    /// Administrators and `user_sid` may open. Fails if the name is already
    /// taken by another program.
    pub fn bind(name: &str, user_sid: &str) -> io::Result<Self> {
        Self::bind_as(name, &current_owner_sid()?, user_sid)
    }

    fn bind_as(name: &str, server_sid: &str, user_sid: &str) -> io::Result<Self> {
        let descriptor = Descriptor::from_sddl(&pipe_sddl(server_sid, user_sid)?)?;
        let mut listener = Self {
            name: HSTRING::from(name),
            descriptor,
            pending: None,
        };
        listener.pending = Some(listener.create_instance(true)?);
        Ok(listener)
    }

    fn create_instance(&self, first: bool) -> io::Result<File> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: self.descriptor.0.0,
            bInheritHandle: false.into(),
        };
        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        // SAFETY: the name and `attributes` (pointing at `self.descriptor`)
        // live for the call.
        let handle = unsafe {
            CreateNamedPipeW(
                &self.name,
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER,
                BUFFER,
                0,
                Some(&attributes),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_invalid() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is a valid, owned pipe handle; the File takes
        // ownership and closes it when dropped.
        Ok(unsafe { File::from_raw_handle(handle.0 as RawHandle) })
    }

    /// Waits for the next client and returns the connection.
    pub fn accept(&mut self) -> io::Result<PipeConnection> {
        let file = match self.pending.take() {
            Some(file) => file,
            None => self.create_instance(false)?,
        };
        let handle = HANDLE(file.as_raw_handle());
        // SAFETY: `handle` is a valid pipe instance; no overlapped I/O.
        match unsafe { ConnectNamedPipe(handle, None) } {
            Ok(()) => {}
            // The client connected between creation and this call: fine.
            Err(error) if error.code() == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) => {}
            Err(error) => return Err(io::Error::other(format!("ConnectNamedPipe: {error}"))),
        }
        // The client connected at or before this moment.
        let connected_by = SystemTime::now();
        let mut client_pid = 0u32;
        // SAFETY: `handle` is a connected pipe; `client_pid` is writable.
        unsafe { GetNamedPipeClientProcessId(handle, &mut client_pid) }
            .map_err(|e| io::Error::other(format!("GetNamedPipeClientProcessId: {e}")))?;
        // Prepare the next instance now, so clients never find no instance.
        self.pending = Some(self.create_instance(false)?);
        Ok(PipeConnection {
            file,
            peer_pid: client_pid,
            connected_by,
        })
    }
}

/// One end of a connected pipe.
#[derive(Debug)]
pub struct PipeConnection {
    file: File,
    peer_pid: u32,
    connected_by: SystemTime,
}

impl PipeConnection {
    /// Process ID of the program on the other end.
    ///
    /// Windows may reuse a process ID once its process has exited, so check
    /// the peer through a process handle, and reject a process that started
    /// after [`Self::connected_by`]: it cannot be the one that connected.
    pub fn peer_pid(&self) -> u32 {
        self.peer_pid
    }

    /// A time at or after which the connection was made.
    pub fn connected_by(&self) -> SystemTime {
        self.connected_by
    }
}

impl Read for PipeConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for PipeConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Connects to the pipe `name` as a client. The returned connection's
/// [`PipeConnection::peer_pid`] is the server's process ID, so the caller
/// can check it is really Whereabouts before sending anything.
///
/// The connection is opened at the anonymous security level, so the server
/// cannot act as (impersonate) the client, even if it is an impostor.
pub fn connect(name: &str) -> io::Result<PipeConnection> {
    let mut attempts = 0;
    let file = loop {
        match OpenOptions::new()
            .access_mode(CLIENT_ACCESS)
            .security_qos_flags(SECURITY_ANONYMOUS.0)
            .open(name)
        {
            // All instances are busy for a moment (between one client being
            // accepted and the next instance being created): try again.
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 20 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            other => break other?,
        }
    };
    let connected_by = SystemTime::now();
    let mut server_pid = 0u32;
    // SAFETY: `file` is an open pipe client handle; `server_pid` is writable.
    unsafe { GetNamedPipeServerProcessId(HANDLE(file.as_raw_handle()), &mut server_pid) }
        .map_err(|e| io::Error::other(format!("GetNamedPipeServerProcessId: {e}")))?;
    Ok(PipeConnection {
        file,
        peer_pid: server_pid,
        connected_by,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn unique_name() -> String {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        format!(
            r"\\.\pipe\whereabouts-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[test]
    fn finds_the_current_user() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-"), "{sid}");
    }

    #[test]
    fn client_and_server_talk_and_see_each_other() {
        let name = unique_name();
        let sid = current_user_sid().unwrap();
        let mut listener = PipeListener::bind(&name, &sid).unwrap();
        let server = std::thread::spawn(move || {
            let mut connection = listener.accept().unwrap();
            let mut buffer = [0u8; 5];
            connection.read_exact(&mut buffer).unwrap();
            connection.write_all(b"world").unwrap();
            (buffer, connection.peer_pid())
        });

        let mut client = connect(&name).unwrap();
        assert_eq!(client.peer_pid(), std::process::id());
        client.write_all(b"hello").unwrap();
        let mut reply = [0u8; 5];
        client.read_exact(&mut reply).unwrap();

        let (received, client_pid) = server.join().unwrap();
        assert_eq!(&received, b"hello");
        assert_eq!(&reply, b"world");
        assert_eq!(client_pid, std::process::id());
    }

    #[test]
    fn a_taken_pipe_name_cannot_be_bound_again() {
        let name = unique_name();
        let sid = current_user_sid().unwrap();
        let _first = PipeListener::bind(&name, &sid).unwrap();
        assert!(
            PipeListener::bind(&name, &sid).is_err(),
            "pipe squatting must fail"
        );
    }

    #[test]
    fn serves_several_clients_in_turn() {
        let name = unique_name();
        let sid = current_user_sid().unwrap();
        let mut listener = PipeListener::bind(&name, &sid).unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..3 {
                let mut connection = listener.accept().unwrap();
                let mut byte = [0u8; 1];
                connection.read_exact(&mut byte).unwrap();
                connection.write_all(&byte).unwrap();
            }
        });
        for value in [1u8, 2, 3] {
            let mut client = connect(&name).unwrap();
            client.write_all(&[value]).unwrap();
            let mut echo = [0u8; 1];
            client.read_exact(&mut echo).unwrap();
            assert_eq!(echo[0], value);
        }
        server.join().unwrap();
    }

    /// Whether this process runs with administrator rights (which may add
    /// pipe instances by design).
    fn elevated() -> bool {
        use windows::Win32::Security::{TOKEN_ELEVATION, TokenElevation};
        let mut token = HANDLE::default();
        // SAFETY: pseudo-handle of this process; `token` is writable.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        // SAFETY: `elevation` is writable and its exact size is passed.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some((&raw mut elevation).cast()),
                u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>()).unwrap(),
                &mut len,
            )
        }
        .is_ok();
        // SAFETY: opened above, closed once.
        let _ = unsafe { CloseHandle(token) };
        ok && elevation.TokenIsElevated != 0
    }

    #[test]
    fn the_user_cannot_add_instances_to_the_pipe() {
        let name = unique_name();
        let sid = current_user_sid().unwrap();
        // A server running as SYSTEM, as the Whereabouts service does.
        let _listener = PipeListener::bind_as(&name, "S-1-5-18", &sid).unwrap();
        // Another program running as the same user tries to add its own
        // instance of our pipe, to receive our clients.
        let squatter = PipeListener {
            name: HSTRING::from(name.as_str()),
            descriptor: Descriptor::from_sddl("D:(A;;GA;;;WD)").unwrap(),
            pending: None,
        };
        let result = squatter.create_instance(false);
        if elevated() {
            eprintln!("skipped: administrators may add instances by design");
            return;
        }
        let error = result.expect_err("a normal user must not add pipe instances");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    }

    #[test]
    fn connections_know_when_they_were_made() {
        let name = unique_name();
        let sid = current_user_sid().unwrap();
        let before = SystemTime::now();
        let mut listener = PipeListener::bind(&name, &sid).unwrap();
        let server = std::thread::spawn(move || listener.accept().unwrap().connected_by());
        let client = connect(&name).unwrap();
        let server_side = server.join().unwrap();
        assert!(client.connected_by() >= before);
        assert!(server_side >= before);
        assert!(server_side <= SystemTime::now());
    }

    #[test]
    fn rejects_malformed_account_identifiers() {
        let sddl = pipe_sddl("S-1-5-32-544", "S-1-5-21-1-2-3-1001").unwrap();
        assert!(
            sddl.ends_with("(A;;GA;;;S-1-5-32-544)(A;;0x0012019b;;;S-1-5-21-1-2-3-1001)"),
            "{sddl}"
        );
        for bad in ["", "WD", "S-1-5)(A;;GA;;;WD", "S-1-5-21 x"] {
            assert!(pipe_sddl("S-1-5-18", bad).is_err(), "{bad}");
            assert!(pipe_sddl(bad, "S-1-5-18").is_err(), "{bad}");
        }
    }

    #[test]
    fn finds_the_owner_of_what_this_process_creates() {
        let owner = current_owner_sid().unwrap();
        if elevated() {
            assert_eq!(owner, "S-1-5-32-544", "Administrators");
        } else {
            assert_eq!(owner, current_user_sid().unwrap());
        }
    }
}
