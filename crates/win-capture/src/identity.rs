//! Works out what a program really is (design spec §5.3): its file path,
//! code signature, file hash, and Microsoft Store package.
//!
//! # Privacy
//!
//! Checking a signature normally lets Windows contact certificate servers
//! on the internet (revocation lists, missing certificates). Whereabouts
//! turns that off: revocation is not checked and only certificates already
//! on this computer are used (`WTD_CACHE_ONLY_URL_RETRIEVAL`,
//! `WTD_REVOKE_NONE`). So checking an app never sends anything out.
//!
//! # Catalog signatures
//!
//! Many files that ship with Windows have no signature inside the file;
//! instead their hash is listed in a signed security catalog. If a file has
//! no embedded signature, its hash is looked up in the catalogs. Because the
//! lookup is by hash, a renamed copy of a Windows program is still
//! recognised, and a modified copy is not.
//!
//! # One locked handle
//!
//! Each check opens the file once, with sharing set so that nobody else can
//! write to, rename or delete it until the check is done, and does the
//! hash, the signature check and the catalog lookup through that same
//! handle. So the file cannot be swapped between the steps.

#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::mem::size_of;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use sha2::{Digest, Sha256};
use whereabouts_core::model::{AppIdentity, Signature};

use crate::process::ProcessHandle;
use windows::Win32::Foundation::{
    APPMODEL_ERROR_NO_PACKAGE, CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, HWND,
    TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN,
};
use windows::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ID_INFO, FILE_SHARE_READ, FileIdInfo, GetFileInformationByHandleEx, QueryDosDeviceW,
};
use windows::Win32::Storage::Packaging::Appx::GetPackageFamilyName;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::core::{HSTRING, PCWSTR, PWSTR, w};

/// Files larger than this are not hashed, to keep checks quick. Their
/// signature is still checked, but the result is not cached.
pub const MAX_HASH_SIZE: u64 = 512 * 1024 * 1024;

/// Opens `path` for reading and stops anyone else from writing to, renaming
/// or deleting it until the returned handle is closed.
pub fn open_locked(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
}

/// Opens and locks the file that process `pid` is running, and confirms it
/// is still that file. Returns its path and the locked handle.
///
/// The path comes from the kernel's record of the process image (which
/// follows renames), not from anything the process can edit. Between
/// asking for the path and opening the file, the program could rename its
/// file; once the file is locked it cannot be renamed any more, so the
/// kernel is asked again and the result is used only if:
///
/// - the path is **exactly** the same (not just ignoring case: Windows
///   allows case-sensitive folders, where `App.exe` and `app.exe` are
///   different files), and
/// - the file at that path **is** the locked file (same volume and file ID).
///
/// Returns `None` if the process has exited, cannot be queried, or its file
/// changed in between.
pub fn lock_running_image(pid: u32) -> Option<(String, File)> {
    lock_image_of(&ProcessHandle::open(pid)?)
}

/// Like [`lock_running_image`], for a process already opened (so its ID
/// cannot be reused in between).
pub fn lock_image_of(process: &ProcessHandle) -> Option<(String, File)> {
    let path = process.image_path()?;
    let file = open_locked(Path::new(&path)).ok()?;
    let again = process.image_path()?;
    if again != path {
        return None;
    }
    let at_path = File::open(Path::new(&again)).ok()?;
    let same_file = file_id(&file)? == file_id(&at_path)?;
    same_file.then_some((path, file))
}

/// Whether the open `file` is the file at `path`, compared by file ID.
pub fn is_same_file(file: &File, path: &Path) -> bool {
    match (
        file_id(file),
        File::open(path).ok().as_ref().and_then(file_id),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Whether `a` and `b` are the same file, compared by file ID rather than by
/// name (so case, `..`, short names or links cannot fool it). `false` if
/// either cannot be opened.
pub fn same_file(a: &Path, b: &Path) -> bool {
    match (File::open(a), File::open(b)) {
        (Ok(a), Ok(b)) => matches!((file_id(&a), file_id(&b)), (Some(x), Some(y)) if x == y),
        _ => false,
    }
}

/// Returns the volume serial number and 128-bit file ID of an open file:
/// what identifies the file itself, whatever its name.
fn file_id(file: &File) -> Option<(u64, [u8; 16])> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: `info` is a writable FILE_ID_INFO and its exact size is
    // passed; the handle stays open for the call.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            (&raw mut info).cast(),
            struct_size::<FILE_ID_INFO>(),
        )
    }
    .ok()?;
    Some((info.VolumeSerialNumber, info.FileId.Identifier))
}

/// Returns the SHA-256 hash of `file`'s whole content, hex-encoded. Reads
/// from the start, whatever the current position.
pub fn sha256_of(mut file: &File) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Maps Windows device paths (`\Device\HarddiskVolume3\...`), as used in
/// kernel events, to drive-letter paths (`C:\...`).
#[derive(Debug, Clone, Default)]
pub struct DevicePaths(Vec<(String, String)>);

impl DevicePaths {
    /// Reads the current drive-letter mappings from Windows.
    pub fn load() -> Self {
        let mut pairs = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", char::from(letter));
            let mut buffer = [0u16; 1024];
            // SAFETY: `drive` is a valid string for the call and `buffer` is
            // a writable slice; the function writes at most its length.
            let written = unsafe { QueryDosDeviceW(&HSTRING::from(&drive), Some(&mut buffer)) };
            let written = usize::try_from(written).unwrap_or(0).min(buffer.len());
            // The result is a list of null-terminated strings; use the first.
            let target: String = String::from_utf16_lossy(
                buffer[..written].split(|&c| c == 0).next().unwrap_or(&[]),
            );
            if !target.is_empty() {
                pairs.push((target, drive));
            }
        }
        Self(pairs)
    }

    /// Creates a mapping from `(device, drive)` pairs, for tests.
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(device, drive)| ((*device).to_owned(), (*drive).to_owned()))
                .collect(),
        )
    }

    /// Converts `path` to a drive-letter path if it starts with a known
    /// device. Drive-letter paths are returned unchanged; anything else gives
    /// `None`.
    pub fn to_dos(&self, path: &str) -> Option<String> {
        let path = path
            .strip_prefix(r"\??\")
            .or_else(|| path.strip_prefix(r"\\?\"))
            .unwrap_or(path);
        let bytes = path.as_bytes();
        if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":\\" {
            return Some(path.to_owned());
        }
        self.0.iter().find_map(|(device, drive)| {
            let prefix = path.get(..device.len())?;
            let rest = &path[device.len()..];
            (prefix.eq_ignore_ascii_case(device) && rest.starts_with('\\'))
                .then(|| format!("{drive}{rest}"))
        })
    }
}

/// Checks the code signature of the file at `path`, without network access.
pub fn verify_signature(path: &Path) -> Signature {
    match open_locked(path) {
        Ok(file) => verify_signature_of(&file, path),
        Err(_) => Signature::Unknown,
    }
}

/// Checks the code signature of an open `file` (opened from `path`), using
/// only that handle for reading.
pub fn verify_signature_of(file: &File, path: &Path) -> Signature {
    let path_w = HSTRING::from(path.as_os_str());
    let (status, publisher) = match rewind(file) {
        Ok(()) => verify_embedded(&path_w, file),
        Err(_) => return Signature::Unknown,
    };
    if status == 0 {
        return Signature::Signed {
            publisher: publisher.unwrap_or_else(|| String::from("(unknown publisher)")),
            via_catalog: false,
        };
    }
    let no_embedded_signature = [
        TRUST_E_NOSIGNATURE.0,
        TRUST_E_SUBJECT_FORM_UNKNOWN.0,
        TRUST_E_PROVIDER_UNKNOWN.0,
    ]
    .contains(&status);
    if !no_embedded_signature {
        return Signature::Invalid {
            code: u32::from_ne_bytes(status.to_ne_bytes()),
        };
    }
    match verify_catalog(file, &path_w) {
        Some((0, publisher)) => Signature::Signed {
            publisher: publisher.unwrap_or_else(|| String::from("(unknown publisher)")),
            via_catalog: true,
        },
        Some((code, _)) => Signature::Invalid {
            code: u32::from_ne_bytes(code.to_ne_bytes()),
        },
        None => Signature::Unsigned,
    }
}

fn rewind(mut file: &File) -> io::Result<()> {
    file.seek(SeekFrom::Start(0)).map(|_| ())
}

/// Settings shared by every check: no UI, no revocation, no network.
fn base_trust_data() -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: struct_size::<WINTRUST_DATA>(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4,
        ..Default::default()
    }
}

/// Runs `WinVerifyTrust` on prepared `data`, reads the signer's name on
/// success, and releases the verification state. Returns the status
/// (`0` = valid) and the signer's name.
///
/// # Safety
///
/// `data` must be fully initialised, and every pointer in it must stay
/// valid for the duration of the call.
unsafe fn run_trust_check(data: &mut WINTRUST_DATA) -> (i32, Option<String>) {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // INVALID_HANDLE_VALUE: there is no interactive user to ask.
    let no_window = HWND(-1isize as *mut core::ffi::c_void);
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    // SAFETY: guaranteed by the caller.
    let status =
        unsafe { WinVerifyTrust(no_window, &mut action, (data as *mut WINTRUST_DATA).cast()) };
    let publisher = if status == 0 {
        // SAFETY: after a successful verify, `hWVTStateData` holds valid
        // state until it is closed below.
        unsafe { signer_name(data.hWVTStateData) }
    } else {
        None
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closing the state opened by the verify call above.
    unsafe { WinVerifyTrust(no_window, &mut action, (data as *mut WINTRUST_DATA).cast()) };
    (status, publisher)
}

/// Reads the signer's display name from verification state.
///
/// # Safety
///
/// `state` must be valid verification state from a successful
/// `WinVerifyTrust` call that has not been closed yet.
unsafe fn signer_name(state: HANDLE) -> Option<String> {
    // SAFETY (whole block): every pointer is checked for null before use and
    // points into the verification state, which the caller keeps alive.
    unsafe {
        let provider = WTHelperProvDataFromStateData(state);
        if provider.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
        if signer.is_null() || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() {
            return None;
        }
        let certificate = (*(*signer).pasCertChain).pCert;
        if certificate.is_null() {
            return None;
        }
        let len = CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);
        if len <= 1 {
            return None;
        }
        let mut name = vec![0u16; usize::try_from(len).ok()?];
        let written = CertGetNameStringW(
            certificate,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name),
        );
        let written = usize::try_from(written)
            .ok()?
            .saturating_sub(1)
            .min(name.len());
        Some(String::from_utf16_lossy(&name[..written]))
    }
}

/// Checks a signature embedded in the file.
fn verify_embedded(path_w: &HSTRING, file: &File) -> (i32, Option<String>) {
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: struct_size::<WINTRUST_FILE_INFO>(),
        pcwszFilePath: PCWSTR(path_w.as_ptr()),
        hFile: HANDLE(file.as_raw_handle()),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        ..base_trust_data()
    };
    // SAFETY: `data` points at `file_info`, which points at `path_w` and
    // `file`; all of them outlive the call.
    unsafe { run_trust_check(&mut data) }
}

/// Looks the file's hash up in the Windows security catalogs and checks
/// the catalog's signature. Returns `None` if no catalog lists the file.
fn verify_catalog(file: &File, path_w: &HSTRING) -> Option<(i32, Option<String>)> {
    // Newer catalogs use SHA-256; older ones SHA-1 (the default).
    for algorithm in [w!("SHA256"), PCWSTR::null()] {
        let mut admin: isize = 0;
        // SAFETY: `admin` is a valid out-pointer; no other pointers passed.
        if unsafe { CryptCATAdminAcquireContext2(&mut admin, None, algorithm, None, None) }.is_err()
        {
            continue;
        }
        let result = catalog_lookup(admin, file, path_w);
        // SAFETY: `admin` was acquired above and is released exactly once.
        let _ = unsafe { CryptCATAdminReleaseContext(admin, 0) };
        if result.is_some() {
            return result;
        }
    }
    None
}

fn catalog_lookup(admin: isize, file: &File, path_w: &HSTRING) -> Option<(i32, Option<String>)> {
    let handle = HANDLE(file.as_raw_handle());
    rewind(file).ok()?;
    let mut size = 0u32;
    // SAFETY: first call only asks for the hash size; `handle` is open.
    let _ = unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, None, None) };
    if size == 0 || size > 64 {
        return None;
    }
    let mut hash = vec![0u8; usize::try_from(size).ok()?];
    rewind(file).ok()?;
    // SAFETY: `hash` has room for `size` bytes.
    unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin,
            handle,
            &mut size,
            Some(hash.as_mut_ptr()),
            None,
        )
    }
    .ok()?;

    // SAFETY: `hash` is a valid slice; no previous catalog is passed.
    let catalog = unsafe { CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None) };
    if catalog == 0 {
        return None;
    }
    let mut info = CATALOG_INFO {
        cbStruct: struct_size::<CATALOG_INFO>(),
        wszCatalogFile: [0; 260],
    };
    // SAFETY: `catalog` came from the enumeration above; `info` is writable.
    let result = if unsafe { CryptCATCatalogInfoFromContext(catalog, &mut info, 0) }.is_ok() {
        let tag: String = hash.iter().map(|byte| format!("{byte:02X}")).collect();
        let tag = HSTRING::from(tag);
        let mut catalog_info = WINTRUST_CATALOG_INFO {
            cbStruct: struct_size::<WINTRUST_CATALOG_INFO>(),
            dwCatalogVersion: 0,
            pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
            pcwszMemberTag: PCWSTR(tag.as_ptr()),
            pcwszMemberFilePath: PCWSTR(path_w.as_ptr()),
            hMemberFile: handle,
            pbCalculatedFileHash: hash.as_mut_ptr(),
            cbCalculatedFileHash: size,
            pcCatalogContext: std::ptr::null_mut(),
            hCatAdmin: admin,
        };
        let mut data = WINTRUST_DATA {
            dwUnionChoice: WTD_CHOICE_CATALOG,
            Anonymous: WINTRUST_DATA_0 {
                pCatalog: &mut catalog_info,
            },
            ..base_trust_data()
        };
        let _ = rewind(file);
        // SAFETY: `data` points at `catalog_info`, whose pointers refer to
        // `info`, `tag`, `path_w`, `file` and `hash`, all of which outlive
        // the call.
        Some(unsafe { run_trust_check(&mut data) })
    } else {
        None
    };
    // SAFETY: `catalog` was returned by the enumeration and is released once.
    let _ = unsafe { CryptCATAdminReleaseCatalogContext(admin, catalog, 0) };
    result
}

/// Returns the package family name if process `pid` is a Microsoft Store
/// (MSIX) app, e.g. `Microsoft.WindowsCalculator_8wekyb3d8bbwe`.
pub fn package_family_name(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess has no memory-safety preconditions.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut len = 0u32;
    // SAFETY: first call only asks for the length.
    let first = unsafe { GetPackageFamilyName(process, &mut len, None) };
    let name = if first == APPMODEL_ERROR_NO_PACKAGE || first != ERROR_INSUFFICIENT_BUFFER {
        None
    } else {
        let mut buffer = vec![0u16; usize::try_from(len).unwrap_or(0)];
        // SAFETY: `buffer` has room for `len` UTF-16 units.
        let status =
            unsafe { GetPackageFamilyName(process, &mut len, Some(PWSTR(buffer.as_mut_ptr()))) };
        let written = usize::try_from(len)
            .unwrap_or(0)
            .saturating_sub(1)
            .min(buffer.len());
        (status.0 == 0).then(|| String::from_utf16_lossy(&buffer[..written]))
    };
    // SAFETY: `process` was opened above and is closed exactly once.
    let _ = unsafe { CloseHandle(process) };
    name
}

/// Hashes an open `file` if it is small enough. Returns its size and hash.
pub fn size_and_hash(file: &File) -> (Option<u64>, Option<String>) {
    let size = file.metadata().ok().map(|m| m.len());
    let hash = match size {
        Some(size) if size <= MAX_HASH_SIZE => sha256_of(file).ok(),
        _ => None,
    };
    (size, hash)
}

/// Works out the full identity of the program at `path` (a drive-letter
/// path), reading the file through one locked handle. `pid` is used for the
/// Store package name, if the process is still running. The result is not
/// confirmed to be a running process's file; see [`lock_running_image`].
pub fn identify(path: &str, pid: Option<u32>) -> AppIdentity {
    let file_path = Path::new(path);
    let package_family_name = pid.and_then(package_family_name);
    let Ok(file) = open_locked(file_path) else {
        return AppIdentity {
            path: path.to_owned(),
            signature: Signature::Unknown,
            sha256: None,
            size: None,
            package_family_name,
            confirmed_running: false,
        };
    };
    let (size, sha256) = size_and_hash(&file);
    AppIdentity {
        path: path.to_owned(),
        signature: verify_signature_of(&file, file_path),
        sha256,
        size,
        package_family_name,
        confirmed_running: false,
    }
}

fn struct_size<T>() -> u32 {
    u32::try_from(size_of::<T>()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "whereabouts-identity-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn system32(file: &str) -> PathBuf {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
        Path::new(&root).join("System32").join(file)
    }

    /// A program with a signature embedded in the file (not a catalog), if
    /// one is installed. Edge and Git are present on GitHub's runners too.
    fn embedded_signed_program() -> Option<PathBuf> {
        let x86 = std::env::var("ProgramFiles(x86)").unwrap_or_default();
        let x64 = std::env::var("ProgramFiles").unwrap_or_default();
        [
            Path::new(&x86).join(r"Microsoft\Edge\Application\msedge.exe"),
            Path::new(&x64).join(r"Microsoft\Edge\Application\msedge.exe"),
            Path::new(&x64).join(r"Git\cmd\git.exe"),
        ]
        .into_iter()
        .find(|path| path.is_file())
    }

    #[test]
    fn hashes_files_with_sha256() {
        let dir = temp_dir("hash");
        let file = dir.join("abc.txt");
        std::fs::write(&file, b"abc").unwrap();
        let open = open_locked(&file).unwrap();
        // The position does not matter: hashing always starts at the start.
        let mut reader = &open;
        let mut first = [0u8; 1];
        reader.read_exact(&mut first).unwrap();
        assert_eq!(
            sha256_of(&open).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        drop(open);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_being_checked_cannot_be_changed_or_deleted() {
        let dir = temp_dir("locked");
        let file = dir.join("app.exe");
        std::fs::write(&file, b"original").unwrap();
        let locked = open_locked(&file).unwrap();

        assert!(
            std::fs::write(&file, b"swapped").is_err(),
            "write must fail"
        );
        assert!(std::fs::remove_file(&file).is_err(), "delete must fail");
        assert!(
            std::fs::rename(&file, dir.join("moved.exe")).is_err(),
            "rename must fail"
        );
        // Reading is still allowed.
        assert_eq!(std::fs::read(&file).unwrap(), b"original");

        drop(locked);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn same_file_compares_files_not_names() {
        let dir = temp_dir("same-file");
        let a = dir.join("a.exe");
        let b = dir.join("b.exe");
        std::fs::write(&a, b"one").unwrap();
        std::fs::write(&b, b"one").unwrap();
        assert!(same_file(&a, &a));
        // The same file by another spelling of its path.
        let folder = dir.file_name().unwrap();
        assert!(same_file(&a, &dir.join("..").join(folder).join("A.EXE")));
        assert!(!same_file(&a, &b), "same content, different files");
        assert!(!same_file(&a, &dir.join("missing.exe")));
    }

    #[test]
    fn file_ids_identify_files_not_names() {
        let dir = temp_dir("file-id");
        let a = dir.join("a.exe");
        let b = dir.join("b.exe");
        std::fs::write(&a, b"one").unwrap();
        std::fs::write(&b, b"one").unwrap();
        let id_a = file_id(&File::open(&a).unwrap()).unwrap();
        let id_b = file_id(&File::open(&b).unwrap()).unwrap();
        assert_ne!(id_a, id_b, "same content, different files");
        // A rename keeps the file's ID.
        let moved = dir.join("moved.exe");
        std::fs::rename(&a, &moved).unwrap();
        assert_eq!(file_id(&File::open(&moved).unwrap()).unwrap(), id_a);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn locks_and_confirms_this_process_image() {
        let (path, _file) = lock_running_image(std::process::id()).expect("own process");
        let me = std::env::current_exe().unwrap();
        assert!(
            path.eq_ignore_ascii_case(&me.to_string_lossy()),
            "{path} vs {}",
            me.display()
        );
    }

    #[test]
    fn converts_device_paths_to_drive_letters() {
        let map = DevicePaths::from_pairs(&[
            (r"\Device\HarddiskVolume3", "C:"),
            (r"\Device\HarddiskVolume13", "D:"),
        ]);
        assert_eq!(
            map.to_dos(r"\Device\HarddiskVolume3\Windows\System32\curl.exe")
                .as_deref(),
            Some(r"C:\Windows\System32\curl.exe")
        );
        // Volume3 must not match Volume13.
        assert_eq!(
            map.to_dos(r"\Device\HarddiskVolume13\Games\x.exe")
                .as_deref(),
            Some(r"D:\Games\x.exe")
        );
        assert_eq!(
            map.to_dos(r"\device\harddiskvolume3\a.exe").as_deref(),
            Some(r"C:\a.exe")
        );
        assert_eq!(
            map.to_dos(r"C:\already\dos.exe").as_deref(),
            Some(r"C:\already\dos.exe")
        );
        assert_eq!(map.to_dos(r"\??\C:\x.exe").as_deref(), Some(r"C:\x.exe"));
        assert_eq!(map.to_dos(r"\Device\Mup\server\share\x.exe"), None);
    }

    #[test]
    fn loads_the_system_drive_mapping() {
        let map = DevicePaths::load();
        let windows = std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
        let drive = &windows[..2];
        assert!(
            map.0.iter().any(|(_, d)| d.eq_ignore_ascii_case(drive)),
            "no device mapping for {drive}: {map:?}"
        );
    }

    #[test]
    fn windows_programs_are_signed_by_microsoft() {
        let curl = system32("curl.exe");
        match verify_signature(&curl) {
            Signature::Signed { publisher, .. } => {
                assert!(publisher.contains("Microsoft"), "publisher {publisher:?}");
            }
            other => panic!("curl.exe: {other:?}"),
        }
    }

    #[test]
    fn a_renamed_copy_is_still_recognised() {
        let dir = temp_dir("renamed");
        let copy = dir.join("definitely-not-curl.exe");
        std::fs::copy(system32("curl.exe"), &copy).unwrap();
        let original = verify_signature(&system32("curl.exe"));
        assert_eq!(verify_signature(&copy), original);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_modified_copy_is_not_signed() {
        let dir = temp_dir("modified");
        let copy = dir.join("curl.exe");
        let mut bytes = std::fs::read(system32("curl.exe")).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        std::fs::write(&copy, &bytes).unwrap();
        let result = verify_signature(&copy);
        assert!(
            !matches!(result, Signature::Signed { .. }),
            "a modified file must not count as signed: {result:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn embedded_signatures_are_checked() {
        let Some(program) = embedded_signed_program() else {
            eprintln!("skipped: no program with an embedded signature found");
            return;
        };
        match verify_signature(&program) {
            Signature::Signed {
                publisher,
                via_catalog,
            } => {
                assert!(!publisher.is_empty());
                assert!(
                    !via_catalog,
                    "{} should have an embedded signature",
                    program.display()
                );
            }
            other => panic!("{}: {other:?}", program.display()),
        }
    }

    #[test]
    fn a_modified_copy_with_an_embedded_signature_is_invalid() {
        let Some(program) = embedded_signed_program() else {
            eprintln!("skipped: no program with an embedded signature found");
            return;
        };
        let dir = temp_dir("tampered");
        let copy = dir.join("tampered.exe");
        let mut bytes = std::fs::read(&program).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        std::fs::write(&copy, &bytes).unwrap();
        let result = verify_signature(&copy);
        assert!(
            matches!(result, Signature::Invalid { .. }),
            "tampered copy of {}: {result:?}",
            program.display()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn this_test_program_is_unsigned() {
        let me = std::env::current_exe().unwrap();
        assert_eq!(verify_signature(&me), Signature::Unsigned);
    }

    #[test]
    fn identifies_a_program_fully() {
        let curl = system32("curl.exe");
        let identity = identify(&curl.to_string_lossy(), Some(std::process::id()));
        assert!(matches!(identity.signature, Signature::Signed { .. }));
        assert_eq!(identity.sha256.as_ref().map(String::len), Some(64));
        assert!(identity.size.is_some_and(|s| s > 0));
        // This test process is not a Store app.
        assert_eq!(identity.package_family_name, None);
    }

    #[test]
    fn missing_files_are_unknown() {
        assert_eq!(
            verify_signature(Path::new(r"C:\no\such\file.exe")),
            Signature::Unknown
        );
    }
}
