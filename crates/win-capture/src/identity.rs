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

#![allow(unsafe_code)]

use std::fs::File;
use std::io::{self, Read};
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use sha2::{Digest, Sha256};
use whereabouts_core::model::{AppIdentity, Signature};
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
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::Storage::Packaging::Appx::GetPackageFamilyName;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::core::{HSTRING, PCWSTR, PWSTR, w};

/// Files larger than this are not hashed, to keep checks quick.
pub const MAX_HASH_SIZE: u64 = 512 * 1024 * 1024;

/// Returns the SHA-256 hash of the file at `path`, hex-encoded.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
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
    let Ok(file) = File::open(path) else {
        return Signature::Unknown;
    };
    let path_w = HSTRING::from(path.as_os_str());
    let (status, publisher) = verify_embedded(&path_w, &file);
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
    match verify_catalog(path, &path_w) {
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
fn verify_catalog(path: &Path, path_w: &HSTRING) -> Option<(i32, Option<String>)> {
    // Newer catalogs use SHA-256; older ones SHA-1 (the default).
    for algorithm in [w!("SHA256"), PCWSTR::null()] {
        let mut admin: isize = 0;
        // SAFETY: `admin` is a valid out-pointer; no other pointers passed.
        if unsafe { CryptCATAdminAcquireContext2(&mut admin, None, algorithm, None, None) }.is_err()
        {
            continue;
        }
        let result = catalog_lookup(admin, path, path_w);
        // SAFETY: `admin` was acquired above and is released exactly once.
        let _ = unsafe { CryptCATAdminReleaseContext(admin, 0) };
        if result.is_some() {
            return result;
        }
    }
    None
}

fn catalog_lookup(admin: isize, path: &Path, path_w: &HSTRING) -> Option<(i32, Option<String>)> {
    let file = File::open(path).ok()?;
    let handle = HANDLE(file.as_raw_handle());
    let mut size = 0u32;
    // SAFETY: first call only asks for the hash size; `handle` is open.
    let _ = unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, None, None) };
    if size == 0 || size > 64 {
        return None;
    }
    let mut hash = vec![0u8; usize::try_from(size).ok()?];
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
        let member = File::open(path).ok();
        let mut catalog_info = WINTRUST_CATALOG_INFO {
            cbStruct: struct_size::<WINTRUST_CATALOG_INFO>(),
            dwCatalogVersion: 0,
            pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
            pcwszMemberTag: PCWSTR(tag.as_ptr()),
            pcwszMemberFilePath: PCWSTR(path_w.as_ptr()),
            hMemberFile: member
                .as_ref()
                .map_or(HANDLE::default(), |f| HANDLE(f.as_raw_handle())),
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
        // SAFETY: `data` points at `catalog_info`, whose pointers refer to
        // `info`, `tag`, `path_w`, `member` and `hash`, all of which outlive
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

/// Works out the full identity of the program at `path` (a drive-letter
/// path). `pid` is used for the Store package name, if the process is still
/// running.
pub fn identify(path: &str, pid: Option<u32>) -> AppIdentity {
    let file = Path::new(path);
    let size = std::fs::metadata(file).ok().map(|m| m.len());
    let sha256 = match size {
        Some(size) if size <= MAX_HASH_SIZE => sha256_file(file).ok(),
        _ => None,
    };
    AppIdentity {
        path: path.to_owned(),
        signature: verify_signature(file),
        sha256,
        size,
        package_family_name: pid.and_then(package_family_name),
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

    #[test]
    fn hashes_files_with_sha256() {
        let dir = temp_dir("hash");
        let file = dir.join("abc.txt");
        std::fs::write(&file, b"abc").unwrap();
        assert_eq!(
            sha256_file(&file).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_dir_all(dir);
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
