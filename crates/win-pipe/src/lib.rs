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

use windows::Win32::Foundation::{
    CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
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

/// Win32 error: all pipe instances are busy.
const ERROR_PIPE_BUSY: i32 = 231;

/// Pipe buffer size in bytes.
const BUFFER: u32 = 64 * 1024;

/// Returns the security identifier (e.g. `S-1-5-21-…`) of the account this
/// process runs as.
pub fn current_user_sid() -> io::Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; `token` is writable.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|e| io::Error::other(format!("OpenProcessToken failed: {e}")))?;
    let result = (|| {
        let mut needed = 0u32;
        // SAFETY: first call only asks for the size.
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
        let mut buffer = vec![0u8; usize::try_from(needed).unwrap_or(0)];
        // SAFETY: `buffer` has room for `needed` bytes.
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        }
        .map_err(|e| io::Error::other(format!("GetTokenInformation failed: {e}")))?;
        // SAFETY: the buffer now holds a TOKEN_USER (read unaligned, since a
        // Vec<u8> has no alignment guarantee).
        let user: TOKEN_USER = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast()) };
        let mut text = PWSTR::null();
        // SAFETY: the SID points into `buffer`, which is alive; `text`
        // receives a LocalAlloc'd string freed below.
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }
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

/// Pipe permissions: full access for SYSTEM and Administrators, read and
/// write for `user_sid`, and network logons denied.
fn pipe_sddl(user_sid: &str) -> io::Result<String> {
    // A SID string only contains "S", digits and dashes; refuse anything else
    // so it cannot change the meaning of the descriptor.
    let valid = user_sid.starts_with("S-")
        && user_sid[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-');
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a valid account identifier",
        ));
    }
    Ok(format!(
        "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{user_sid})"
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
        let descriptor = Descriptor::from_sddl(&pipe_sddl(user_sid)?)?;
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
        let mut client_pid = 0u32;
        // SAFETY: `handle` is a connected pipe; `client_pid` is writable.
        unsafe { GetNamedPipeClientProcessId(handle, &mut client_pid) }
            .map_err(|e| io::Error::other(format!("GetNamedPipeClientProcessId: {e}")))?;
        // Prepare the next instance now, so clients never find no instance.
        self.pending = Some(self.create_instance(false)?);
        Ok(PipeConnection {
            file,
            peer_pid: client_pid,
        })
    }
}

/// One end of a connected pipe.
#[derive(Debug)]
pub struct PipeConnection {
    file: File,
    peer_pid: u32,
}

impl PipeConnection {
    /// Process ID of the program on the other end.
    pub fn peer_pid(&self) -> u32 {
        self.peer_pid
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
            .read(true)
            .write(true)
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
    let mut server_pid = 0u32;
    // SAFETY: `file` is an open pipe client handle; `server_pid` is writable.
    unsafe { GetNamedPipeServerProcessId(HANDLE(file.as_raw_handle()), &mut server_pid) }
        .map_err(|e| io::Error::other(format!("GetNamedPipeServerProcessId: {e}")))?;
    Ok(PipeConnection {
        file,
        peer_pid: server_pid,
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

    #[test]
    fn rejects_malformed_account_identifiers() {
        assert!(pipe_sddl("S-1-5-21-1-2-3-1001").is_ok());
        for bad in ["", "WD", "S-1-5)(A;;GA;;;WD", "S-1-5-21 x"] {
            assert!(pipe_sddl(bad).is_err(), "{bad}");
        }
    }
}
