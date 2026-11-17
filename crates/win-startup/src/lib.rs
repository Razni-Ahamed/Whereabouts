//! Starting the Whereabouts app at sign-in (v0.2, N4).
//!
//! Windows starts programs listed under the current user's
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` key when that user
//! signs in. Whereabouts adds one value there, named `Whereabouts`, only
//! when the user chooses to, and removes it when they turn it off (the
//! installer removes it when uninstalling).
//!
//! Windows' own "Startup apps" settings can turn a listed program off
//! without removing it; that choice is kept under
//! `...\Explorer\StartupApproved\Run`. A program counts as starting at
//! sign-in only if it is listed **and** not turned off there. Turning it
//! on from Whereabouts clears an earlier "off" there.
//!
//! Nothing else is read or written. `unsafe` is used only for the registry
//! calls; every block has a `// SAFETY:` comment.

#![allow(unsafe_code)]

use std::io;
use std::path::Path;

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, WIN32_ERROR};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, REG_ROUTINE_FLAGS, REG_SZ, RRF_RT_REG_BINARY, RRF_RT_REG_SZ,
    RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW,
};
use windows::core::HSTRING;

/// Where Windows lists the current user's sign-in programs.
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Where Windows records programs the user turned off in "Startup apps".
const APPROVED_KEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

/// The name of Whereabouts' value under both keys.
pub const VALUE_NAME: &str = "Whereabouts";

/// The argument the app gets when Windows starts it at sign-in: start in
/// the tray, without opening a window.
pub const BACKGROUND_ARG: &str = "--background";

/// The command Windows runs at sign-in for the app at `exe`.
pub fn command_for(exe: &Path) -> String {
    format!("\"{}\" {BACKGROUND_ARG}", exe.display())
}

/// The registry place used (the real one, or a test key).
#[derive(Debug, Clone, Copy)]
struct Place<'a> {
    run: &'a str,
    approved: &'a str,
    value: &'a str,
}

const REAL: Place<'static> = Place {
    run: RUN_KEY,
    approved: APPROVED_KEY,
    value: VALUE_NAME,
};

/// Whether Windows starts the app at `exe` at sign-in for this user.
pub fn is_enabled(exe: &Path) -> io::Result<bool> {
    is_enabled_at(REAL, exe)
}

/// Starts the app at `exe` at sign-in for this user, in the background.
pub fn enable(exe: &Path) -> io::Result<()> {
    enable_at(REAL, exe)
}

/// Stops starting the app at sign-in for this user.
pub fn disable() -> io::Result<()> {
    disable_at(REAL)
}

fn is_enabled_at(place: Place<'_>, exe: &Path) -> io::Result<bool> {
    let Some(command) = read_string(place.run, place.value)? else {
        return Ok(false);
    };
    if !command.eq_ignore_ascii_case(&command_for(exe)) {
        return Ok(false);
    }
    // In "Startup apps", the first byte is even when on (2, 6) and odd when
    // turned off (3, 7). No value means on.
    Ok(read_binary(place.approved, place.value)?
        .and_then(|data| data.first().copied())
        .is_none_or(|first| first % 2 == 0))
}

fn enable_at(place: Place<'_>, exe: &Path) -> io::Result<()> {
    let command = command_for(exe);
    let wide: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = u32::try_from(wide.len() * 2).map_err(io::Error::other)?;
    // SAFETY: the key and value names are valid wide strings that outlive
    // the call; `wide` holds `bytes` bytes and outlives it.
    let code = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            &HSTRING::from(place.run),
            &HSTRING::from(place.value),
            REG_SZ.0,
            Some(wide.as_ptr().cast()),
            bytes,
        )
    };
    check(code)?;
    // The user asked for it here, so an earlier "off" in Startup apps no
    // longer applies.
    delete_value(place.approved, place.value)
}

fn disable_at(place: Place<'_>) -> io::Result<()> {
    delete_value(place.run, place.value)
}

fn delete_value(key: &str, value: &str) -> io::Result<()> {
    // SAFETY: the key and value names are valid wide strings that outlive
    // the call.
    let code = unsafe {
        RegDeleteKeyValueW(
            HKEY_CURRENT_USER,
            &HSTRING::from(key),
            &HSTRING::from(value),
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    check(code)
}

fn check(code: WIN32_ERROR) -> io::Result<()> {
    if code.is_ok() {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code.0 as i32))
    }
}

/// Reads a value's bytes; `None` if the key or value does not exist.
fn read_raw(key: &str, value: &str, kind: REG_ROUTINE_FLAGS) -> io::Result<Option<Vec<u8>>> {
    let (key, value) = (HSTRING::from(key), HSTRING::from(value));
    let hkey: HKEY = HKEY_CURRENT_USER;
    let mut size = 0u32;
    // SAFETY: asks for the size only (no data buffer); `size` outlives the
    // call.
    let code = unsafe { RegGetValueW(hkey, &key, &value, kind, None, None, Some(&mut size)) };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    check(code)?;
    // The value can grow between the two calls; try a few times.
    for _ in 0..4 {
        let mut data = vec![0u8; size as usize];
        let mut len = size;
        // SAFETY: `data` has `len` writable bytes; both outlive the call.
        let code = unsafe {
            RegGetValueW(
                hkey,
                &key,
                &value,
                kind,
                None,
                Some(data.as_mut_ptr().cast()),
                Some(&mut len),
            )
        };
        if code == ERROR_MORE_DATA {
            size = len;
            continue;
        }
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        check(code)?;
        data.truncate(len as usize);
        return Ok(Some(data));
    }
    Err(io::Error::other("the registry value kept changing"))
}

fn read_string(key: &str, value: &str) -> io::Result<Option<String>> {
    Ok(read_raw(key, value, RRF_RT_REG_SZ)?.map(|bytes| {
        let wide: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16_lossy(&wide)
    }))
}

fn read_binary(key: &str, value: &str) -> io::Result<Option<Vec<u8>>> {
    read_raw(key, value, RRF_RT_REG_BINARY)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private test key, never the real Run key.
    fn test_place(name: &str) -> (String, String) {
        let base = format!(r"Software\Whereabouts-test-{}-{name}", std::process::id());
        (format!(r"{base}\Run"), format!(r"{base}\Approved"))
    }

    fn remove_tree(name: &str) {
        let base = format!(r"Software\Whereabouts-test-{}-{name}", std::process::id());
        // SAFETY: a valid wide string that outlives the call.
        let _ = unsafe {
            windows::Win32::System::Registry::RegDeleteTreeW(
                HKEY_CURRENT_USER,
                &HSTRING::from(base.as_str()),
            )
        };
        // SAFETY: as above; removes the now empty key itself.
        let _ = unsafe {
            windows::Win32::System::Registry::RegDeleteKeyW(
                HKEY_CURRENT_USER,
                &HSTRING::from(base.as_str()),
            )
        };
    }

    #[test]
    fn the_command_starts_the_app_in_the_background() {
        assert_eq!(
            command_for(Path::new(r"C:\Program Files\Whereabouts\whereabouts.exe")),
            r#""C:\Program Files\Whereabouts\whereabouts.exe" --background"#
        );
    }

    #[test]
    fn enabling_and_disabling_round_trips() {
        let (run, approved) = test_place("toggle");
        let place = Place {
            run: &run,
            approved: &approved,
            value: VALUE_NAME,
        };
        let exe = Path::new(r"C:\Program Files\Whereabouts\whereabouts.exe");
        assert!(!is_enabled_at(place, exe).unwrap());
        enable_at(place, exe).unwrap();
        assert!(is_enabled_at(place, exe).unwrap());
        // Another program's path does not count.
        assert!(!is_enabled_at(place, Path::new(r"C:\Other\whereabouts.exe")).unwrap());
        disable_at(place).unwrap();
        assert!(!is_enabled_at(place, exe).unwrap());
        disable_at(place).unwrap();
        remove_tree("toggle");
    }

    #[test]
    fn turned_off_in_startup_apps_counts_as_off_until_enabled_again() {
        let (run, approved) = test_place("approved");
        let place = Place {
            run: &run,
            approved: &approved,
            value: VALUE_NAME,
        };
        let exe = Path::new(r"C:\Program Files\Whereabouts\whereabouts.exe");
        enable_at(place, exe).unwrap();
        let off = [3u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // SAFETY: valid wide strings and a 12-byte buffer that outlive the call.
        let code = unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                &HSTRING::from(approved.as_str()),
                &HSTRING::from(VALUE_NAME),
                windows::Win32::System::Registry::REG_BINARY.0,
                Some(off.as_ptr().cast()),
                12,
            )
        };
        check(code).unwrap();
        assert!(!is_enabled_at(place, exe).unwrap());
        enable_at(place, exe).unwrap();
        assert!(is_enabled_at(place, exe).unwrap());
        disable_at(place).unwrap();
        remove_tree("approved");
    }
}
