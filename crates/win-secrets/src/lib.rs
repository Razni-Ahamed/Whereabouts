//! Windows key protection, secure random numbers and folder permissions for
//! Whereabouts' encrypted storage (design spec §5.7).
//!
//! - The database key is 32 random bytes from the system's secure random
//!   number generator.
//! - It is stored only after being encrypted with DPAPI for **this
//!   computer** (machine scope), so that the background service (SYSTEM)
//!   and administrators' commands (`--history`, `--export`) can both use
//!   it. Copying the key file and database to another computer gives
//!   nothing readable. On this computer, the key file is protected by the
//!   folder's permissions (SYSTEM and Administrators only).
//!   Machine-scope DPAPI keys can be recovered by someone holding an
//!   unencrypted disk, which is why BitLocker is recommended.
//! - The data folder is restricted to SYSTEM and Administrators and owned
//!   by Administrators. Ordinary users can create folders in
//!   `%ProgramData%`, so an existing folder (or file) is only trusted if it
//!   is not a link or junction and is owned by SYSTEM or Administrators;
//!   otherwise Whereabouts refuses to use it. Permissions are applied
//!   through a handle that was opened without following links, never by
//!   name, so the folder cannot be swapped for a link in between.
//!
//! `unsafe` is used only for these Windows API calls; every block has a
//! `// SAFETY:` comment.

#![allow(unsafe_code)]

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetSecurityInfo,
};
use windows::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom, CRYPT_INTEGER_BLOB,
    CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    IsWellKnownSid, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, KNOWN_FOLDER_FLAG, SHGetKnownFolderPath,
};
use windows::core::{BOOL, GUID, HRESULT, HSTRING, w};

/// Length of the database key in bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Extra input mixed into DPAPI, so that a DPAPI blob made by another
/// program for another purpose cannot be passed off as Whereabouts' key.
const ENTROPY: &[u8] = b"Whereabouts database key v1";

/// Folder security: owned by Administrators; full control for SYSTEM and
/// Administrators only, inherited by files and subfolders, nothing
/// inherited from the parent.
const FOLDER_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Fills a new buffer of `len` bytes from the system's secure random number
/// generator.
pub fn random_bytes(len: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; len];
    // SAFETY: `buffer` is a valid writable slice; the system-preferred RNG
    // needs no algorithm handle.
    let status = unsafe { BCryptGenRandom(None, &mut buffer, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.is_err() {
        return Err(io::Error::other(format!(
            "BCryptGenRandom failed: {status:?}"
        )));
    }
    Ok(buffer)
}

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).unwrap_or(u32::MAX),
        pbData: data.as_ptr().cast_mut(),
    }
}

/// Takes ownership of a DPAPI output blob: copies its bytes and frees it.
///
/// # Safety
///
/// `output` must have been filled by a successful DPAPI call.
unsafe fn take_output(output: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    let len = usize::try_from(output.cbData).unwrap_or(0);
    // SAFETY: DPAPI returned `cbData` valid bytes at `pbData`.
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, len) }.to_vec();
    // SAFETY: DPAPI allocated `pbData` with LocalAlloc; it is freed once.
    let _ = unsafe { LocalFree(Some(HLOCAL(output.pbData.cast()))) };
    bytes
}

/// Who can decrypt what [`protect`] encrypts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Only the account that encrypted it, on this computer.
    User,
    /// Any account on this computer (so protect the file itself).
    Machine,
}

/// Encrypts `data` with DPAPI for `scope`.
pub fn protect(data: &[u8], scope: Scope) -> io::Result<Vec<u8>> {
    let flags = match scope {
        Scope::User => CRYPTPROTECT_UI_FORBIDDEN,
        Scope::Machine => CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
    };
    let input = blob(data);
    let entropy = blob(ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input and entropy blobs point at live slices that DPAPI only
    // reads; `output` receives a LocalAlloc'd buffer freed by take_output.
    unsafe {
        CryptProtectData(
            &input,
            w!("Whereabouts database key"),
            Some(&entropy),
            None,
            None,
            flags,
            &mut output,
        )
    }
    .map_err(|e| io::Error::other(format!("DPAPI protect failed: {e}")))?;
    // SAFETY: the call succeeded, so `output` is a valid DPAPI blob.
    Ok(unsafe { take_output(output) })
}

/// Decrypts a DPAPI blob made by [`protect`] on this computer (and, for
/// [`Scope::User`], by this account).
pub fn unprotect(data: &[u8]) -> io::Result<Vec<u8>> {
    let input = blob(data);
    let entropy = blob(ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in `protect`; no description pointer is requested.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|e| io::Error::other(format!("DPAPI unprotect failed: {e}")))?;
    // SAFETY: the call succeeded, so `output` is a valid DPAPI blob.
    Ok(unsafe { take_output(output) })
}

/// Reads and decrypts a stored key.
fn read_key(path: &Path) -> io::Result<[u8; KEY_LEN]> {
    let key = unprotect(&std::fs::read(path)?)?;
    key.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "stored key has the wrong length",
        )
    })
}

/// Saves `key`, protected for this computer, to the new file `path`.
fn write_key(path: &Path, key: &[u8; KEY_LEN]) -> io::Result<()> {
    let protected = protect(key, Scope::Machine)?;
    // `create_new` never overwrites an existing key.
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&protected)?;
    file.sync_all()
}

/// Loads the database key from `path` (protected for this computer).
///
/// If there is none yet, a key from an older version at `legacy`
/// (protected for the account that made it) is moved to `path` and the
/// old file deleted; this works only for that same account. Otherwise a
/// new random key is created.
pub fn load_or_create_key(path: &Path, legacy: &Path) -> io::Result<[u8; KEY_LEN]> {
    match read_key(path) {
        Ok(key) => {
            // Finish a move that was interrupted after the new file was
            // written.
            if legacy.exists() {
                std::fs::remove_file(legacy)?;
            }
            return Ok(key);
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        Err(_) => {}
    }
    let key = match read_key(legacy) {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::NotFound => random_bytes(KEY_LEN)?
            .try_into()
            .map_err(|_| io::Error::other("wrong random length"))?,
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "the key from an older version can only be read by the administrator \
                     account that first ran Whereabouts; run any Whereabouts command once \
                     as that account ({error})"
                ),
            ));
        }
    };
    write_key(path, &key)?;
    if legacy.exists() {
        std::fs::remove_file(legacy)?;
    }
    Ok(key)
}

/// A folder Windows knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownFolder {
    /// `C:\Program Files` (the 64-bit one on 64-bit Windows).
    ProgramFiles,
    /// `C:\ProgramData`.
    ProgramData,
}

/// The real location of `folder`, asked from Windows rather than read from
/// an environment variable (which a user's own programs could change).
pub fn known_folder(folder: KnownFolder) -> io::Result<std::path::PathBuf> {
    let id: &GUID = match folder {
        KnownFolder::ProgramFiles => &FOLDERID_ProgramFiles,
        KnownFolder::ProgramData => &FOLDERID_ProgramData,
    };
    // SAFETY: `id` is a valid folder ID; the returned string is allocated
    // by the shell and freed below with CoTaskMemFree.
    let text = unsafe { SHGetKnownFolderPath(id, KNOWN_FOLDER_FLAG(0), None) }
        .map_err(|e| io::Error::other(format!("SHGetKnownFolderPath failed: {e}")))?;
    // SAFETY: `text` is a valid null-terminated string from the call.
    let path = unsafe { text.to_string() }.map_err(io::Error::other);
    // SAFETY: allocated by SHGetKnownFolderPath; freed exactly once.
    unsafe { CoTaskMemFree(Some(text.0.cast())) };
    Ok(std::path::PathBuf::from(path?))
}

/// A security descriptor made from [`FOLDER_SDDL`], freed when dropped.
struct FolderDescriptor(PSECURITY_DESCRIPTOR);

impl FolderDescriptor {
    fn new() -> io::Result<Self> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the SDDL string is a valid constant; `descriptor`
        // receives a LocalAlloc'd security descriptor freed in Drop.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &HSTRING::from(FOLDER_SDDL),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|e| io::Error::other(format!("invalid security descriptor: {e}")))?;
        Ok(Self(descriptor))
    }

    fn owner(&self) -> io::Result<PSID> {
        let mut owner = PSID::default();
        let mut defaulted = BOOL::default();
        // SAFETY: `self.0` is a valid descriptor; out-pointers are writable.
        unsafe { GetSecurityDescriptorOwner(self.0, &mut owner, &mut defaulted) }
            .map_err(|e| io::Error::other(format!("reading owner failed: {e}")))?;
        Ok(owner)
    }

    fn dacl(&self) -> io::Result<*mut ACL> {
        let mut present = BOOL::default();
        let mut defaulted = BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `self.0` is a valid descriptor; out-pointers are writable.
        unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) }
            .map_err(|e| io::Error::other(format!("reading permissions failed: {e}")))?;
        Ok(dacl)
    }
}

impl Drop for FolderDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the conversion in `new`; freed exactly once.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

/// A file or folder handle, closed when dropped.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateFileW and is closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Opens `path` (file or folder) **without following** links or junctions.
fn open_no_follow(path: &Path, access: u32) -> io::Result<OwnedHandle> {
    // SAFETY: the path string lives for the call; no security attributes or
    // template handle are passed.
    let handle = unsafe {
        CreateFileW(
            &HSTRING::from(path.as_os_str()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|e| io::Error::other(format!("could not open {}: {e}", path.display())))?;
    Ok(OwnedHandle(handle))
}

/// Returns `true` if the owner of the open object is SYSTEM or the
/// Administrators group.
fn owned_by_system_or_administrators(handle: &OwnedHandle) -> io::Result<bool> {
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `handle` is open with READ_CONTROL; `descriptor` receives a
    // LocalAlloc'd buffer that `owner` points into, freed below.
    let status = unsafe {
        GetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if status.is_err() {
        return Err(io::Error::other(format!(
            "reading the owner failed: {status:?}"
        )));
    }
    // SAFETY: `owner` points into `descriptor`, which is still alive.
    let trusted = unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid).as_bool()
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool()
    };
    // SAFETY: allocated by GetSecurityInfo above; freed exactly once.
    let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    Ok(trusted)
}

/// Refuses an object that is a link/junction, of the wrong kind, or not
/// owned by SYSTEM or Administrators.
fn check_trusted(handle: &OwnedHandle, path: &Path, directory: bool) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is open; `info` is writable.
    unsafe { GetFileInformationByHandle(handle.0, &mut info) }
        .map_err(|e| io::Error::other(format!("could not inspect {}: {e}", path.display())))?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is a link or junction; refusing to use it",
                path.display()
            ),
        ));
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) != directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a {}",
                path.display(),
                if directory { "folder" } else { "file" }
            ),
        ));
    }
    if !owned_by_system_or_administrators(handle)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by an account other than SYSTEM or Administrators; refusing to \
                 use it (if you did not create it, delete it and try again)",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Makes sure `path` is a private Whereabouts folder: creates it already
/// secured if it does not exist; otherwise refuses it unless it is a real
/// folder (not a link or junction) owned by SYSTEM or Administrators. Then
/// (re)applies the owner and permissions through a handle opened without
/// following links. Requires administrator rights.
pub fn secure_directory(path: &Path) -> io::Result<()> {
    let descriptor = FolderDescriptor::new()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: the path string and `attributes` (pointing at `descriptor`)
    // live for the call.
    match unsafe { CreateDirectoryW(&HSTRING::from(path.as_os_str()), Some(&attributes)) } {
        Ok(()) => {}
        Err(error) if error.code() == HRESULT::from_win32(ERROR_ALREADY_EXISTS.0) => {}
        Err(error) => {
            return Err(io::Error::other(format!(
                "could not create {}: {error}",
                path.display()
            )));
        }
    }

    let handle = open_no_follow(path, READ_CONTROL.0 | WRITE_DAC.0 | WRITE_OWNER.0)?;
    check_trusted(&handle, path, true)?;
    let owner = descriptor.owner()?;
    let dacl = descriptor.dacl()?;
    // SAFETY: `handle` is open with WRITE_DAC and WRITE_OWNER; `owner` and
    // `dacl` point into `descriptor`, which is still alive.
    let status = unsafe {
        SetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            Some(owner),
            None,
            Some(dacl.cast_const()),
            None,
        )
    };
    if status.is_err() {
        return Err(io::Error::other(format!(
            "setting folder permissions failed: {status:?}"
        )));
    }
    Ok(())
}

/// Before using an existing file in the data folder (the key or the
/// database), makes sure it is a real file, not a link or junction, and is
/// owned by SYSTEM or Administrators. A file that does not exist yet is
/// fine: it will be created inside the secured folder.
pub fn ensure_private_file(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let handle = open_no_follow(path, READ_CONTROL.0)?;
    check_trusted(&handle, path, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_are_random() {
        let a = random_bytes(32).unwrap();
        let b = random_bytes(32).unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert_ne!(a, vec![0u8; 32]);
    }

    #[test]
    fn dpapi_round_trip() {
        let secret = b"not really a secret";
        for scope in [Scope::User, Scope::Machine] {
            let protected = protect(secret, scope).unwrap();
            assert!(!protected.windows(secret.len()).any(|w| w == secret));
            assert_eq!(unprotect(&protected).unwrap(), secret);
        }
    }

    /// DPAPI blob flags (offset 40 of the blob layout), for tests only.
    fn blob_flags(blob: &[u8]) -> u32 {
        u32::from_le_bytes(blob[40..44].try_into().unwrap())
    }

    #[test]
    fn machine_scope_is_recorded_in_the_blob() {
        let user = protect(b"x", Scope::User).unwrap();
        let machine = protect(b"x", Scope::Machine).unwrap();
        assert_eq!(blob_flags(&user) & CRYPTPROTECT_LOCAL_MACHINE, 0);
        assert_ne!(blob_flags(&machine) & CRYPTPROTECT_LOCAL_MACHINE, 0);
    }

    #[test]
    fn tampered_blobs_are_rejected() {
        let mut protected = protect(b"secret", Scope::Machine).unwrap();
        let last = protected.len() - 1;
        protected[last] ^= 0xff;
        assert!(unprotect(&protected).is_err());
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("whereabouts-sec-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn junctions_are_refused() {
        let dir = temp("junction");
        let target = dir.join("target");
        let link = dir.join("link");
        std::fs::create_dir(&target).unwrap();
        // Creating a junction needs no administrator rights.
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink /J failed");

        let error = secure_directory(&link).unwrap_err();
        assert!(error.to_string().contains("link or junction"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_where_the_folder_should_be_is_refused() {
        let dir = temp("file");
        let path = dir.join("not-a-folder");
        std::fs::write(&path, b"x").unwrap();
        assert!(secure_directory(&path).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_folder_owned_by_a_normal_account_is_refused() {
        let dir = temp("owner");
        let planted = dir.join("planted");
        std::fs::create_dir(&planted).unwrap();
        let handle = open_no_follow(&planted, READ_CONTROL.0).unwrap();
        if owned_by_system_or_administrators(&handle).unwrap() {
            eprintln!("skipped: running elevated, so new folders are owned by Administrators");
            return;
        }
        drop(handle);
        let error = secure_directory(&planted).unwrap_err();
        assert!(error.to_string().contains("owned by an account"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_files_are_fine_and_planted_files_are_refused() {
        let dir = temp("files");
        assert!(ensure_private_file(&dir.join("missing.key")).is_ok());

        let planted = dir.join("planted.key");
        std::fs::write(&planted, b"not a real key").unwrap();
        let handle = open_no_follow(&planted, READ_CONTROL.0).unwrap();
        if owned_by_system_or_administrators(&handle).unwrap() {
            eprintln!("skipped: running elevated, so new files are owned by Administrators");
            return;
        }
        drop(handle);
        let error = ensure_private_file(&planted).unwrap_err();
        assert!(error.to_string().contains("owned by an account"), "{error}");

        // A folder where a file is expected is refused too.
        assert!(ensure_private_file(&dir).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn key_is_created_once_and_then_reloaded() {
        let dir = temp("key");
        let path = dir.join("database.key");
        let legacy = dir.join("store.key");

        let created = load_or_create_key(&path, &legacy).unwrap();
        let reloaded = load_or_create_key(&path, &legacy).unwrap();
        assert_eq!(created, reloaded);
        // The file holds the key protected for this computer, not the key.
        let on_disk = std::fs::read(&path).unwrap();
        assert!(!on_disk.windows(KEY_LEN).any(|w| w == created));
        assert_ne!(blob_flags(&on_disk) & CRYPTPROTECT_LOCAL_MACHINE, 0);
        assert!(!legacy.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_older_account_key_is_moved_to_machine_scope() {
        let dir = temp("legacy");
        let path = dir.join("database.key");
        let legacy = dir.join("store.key");
        let old_key = [7u8; KEY_LEN];
        std::fs::write(&legacy, protect(&old_key, Scope::User).unwrap()).unwrap();

        assert_eq!(load_or_create_key(&path, &legacy).unwrap(), old_key);
        assert!(!legacy.exists(), "the old file is deleted");
        let moved = std::fs::read(&path).unwrap();
        assert_ne!(blob_flags(&moved) & CRYPTPROTECT_LOCAL_MACHINE, 0);
        assert_eq!(load_or_create_key(&path, &legacy).unwrap(), old_key);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_unreadable_older_key_is_an_error_not_a_new_key() {
        let dir = temp("bad-legacy");
        let path = dir.join("database.key");
        let legacy = dir.join("store.key");
        std::fs::write(&legacy, b"not a DPAPI blob").unwrap();
        let error = load_or_create_key(&path, &legacy).unwrap_err();
        assert!(error.to_string().contains("older version"), "{error}");
        assert!(!path.exists(), "no new key may replace the old one");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn known_folders_are_found() {
        let program_files = known_folder(KnownFolder::ProgramFiles).unwrap();
        let program_data = known_folder(KnownFolder::ProgramData).unwrap();
        assert!(program_files.is_absolute() && program_files.is_dir());
        assert!(program_data.is_absolute() && program_data.is_dir());
        assert_ne!(program_files, program_data);
    }
}
