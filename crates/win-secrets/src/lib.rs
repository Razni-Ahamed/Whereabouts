//! Windows key protection, secure random numbers and folder permissions for
//! Whereabouts' encrypted storage (design spec §5.7).
//!
//! - The database key is 32 random bytes from the system's secure random
//!   number generator.
//! - It is stored only after being encrypted with DPAPI for the **current
//!   account** (for the background service, that is SYSTEM). Only the same
//!   account on the same computer can decrypt it, so copying the key file
//!   and database elsewhere gives nothing readable.
//! - The data folder is restricted to SYSTEM and Administrators.
//!
//! `unsafe` is used only for these Windows API calls; every block has a
//! `// SAFETY:` comment.

#![allow(unsafe_code)]

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom, CRYPT_INTEGER_BLOB,
    CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::core::{BOOL, HSTRING, PCWSTR, w};

/// Length of the database key in bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Extra input mixed into DPAPI, so that a DPAPI blob made by another
/// program for another purpose cannot be passed off as Whereabouts' key.
const ENTROPY: &[u8] = b"Whereabouts database key v1";

/// Folder permissions: full control for SYSTEM and Administrators only,
/// inherited by files and subfolders, nothing inherited from the parent.
const FOLDER_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

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

/// Encrypts `data` with DPAPI for the current account.
pub fn protect(data: &[u8]) -> io::Result<Vec<u8>> {
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
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|e| io::Error::other(format!("DPAPI protect failed: {e}")))?;
    // SAFETY: the call succeeded, so `output` is a valid DPAPI blob.
    Ok(unsafe { take_output(output) })
}

/// Decrypts a DPAPI blob made by [`protect`] on this computer and account.
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

/// Loads the database key from `path`, or creates a new random one and
/// saves it there (DPAPI-protected) if the file does not exist yet.
pub fn load_or_create_key(path: &Path) -> io::Result<[u8; KEY_LEN]> {
    match std::fs::read(path) {
        Ok(protected) => {
            let key = unprotect(&protected)?;
            key.try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stored key has the wrong length",
                )
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let key: [u8; KEY_LEN] = random_bytes(KEY_LEN)?
                .try_into()
                .map_err(|_| io::Error::other("wrong random length"))?;
            let protected = protect(&key)?;
            // `create_new` never overwrites an existing key.
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            file.write_all(&protected)?;
            file.sync_all()?;
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

/// Creates `path` if needed and restricts it to SYSTEM and Administrators,
/// replacing any inherited permissions. Requires administrator rights.
pub fn secure_directory(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the SDDL string is a valid constant; `descriptor` receives a
    // LocalAlloc'd security descriptor freed below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(FOLDER_SDDL),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|e| io::Error::other(format!("invalid security descriptor: {e}")))?;

    let result = (|| {
        let mut present = BOOL::default();
        let mut defaulted = BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `descriptor` is valid; the out-pointers are writable.
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            .map_err(|e| io::Error::other(format!("reading permissions failed: {e}")))?;
        let path_w = HSTRING::from(path.as_os_str());
        // SAFETY: `path_w` is a valid string; `dacl` points into
        // `descriptor`, which is still alive.
        let status = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(path_w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
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
    })();
    // SAFETY: `descriptor` was allocated by the conversion above; freed once.
    let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    result
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
        let protected = protect(secret).unwrap();
        assert!(!protected.windows(secret.len()).any(|w| w == secret));
        assert_eq!(unprotect(&protected).unwrap(), secret);
    }

    #[test]
    fn tampered_blobs_are_rejected() {
        let mut protected = protect(b"secret").unwrap();
        let last = protected.len() - 1;
        protected[last] ^= 0xff;
        assert!(unprotect(&protected).is_err());
    }

    #[test]
    fn key_is_created_once_and_then_reloaded() {
        let dir = std::env::temp_dir().join(format!("whereabouts-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.key");
        let _ = std::fs::remove_file(&path);

        let created = load_or_create_key(&path).unwrap();
        let reloaded = load_or_create_key(&path).unwrap();
        assert_eq!(created, reloaded);
        // The file holds the protected key, not the key itself.
        let on_disk = std::fs::read(&path).unwrap();
        assert!(!on_disk.windows(KEY_LEN).any(|w| w == created));

        let _ = std::fs::remove_dir_all(dir);
    }
}
