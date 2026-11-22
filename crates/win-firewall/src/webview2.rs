//! Keeps the web pages of a blocked app offline when the app shows them
//! through Microsoft Edge WebView2.
//!
//! Such pages (ads included) are fetched by `msedgewebview2.exe`, one file
//! shared by every WebView2 app, so a WFP filter on the app does not cover
//! them and WFP cannot tell one app's WebView2 from another's. WebView2
//! itself has a per-app setting, the `AdditionalBrowserArguments` policy,
//! keyed by the app's file name: for each blocked app Whereabouts sends that
//! app's WebView2 to a proxy on this computer where nothing listens, so
//! nothing outside this computer loads, and an app's own pages served over
//! loopback (uTorrent Web's) keep working. WebView2 reads the setting when
//! the app starts, so it applies from the app's next start.
//!
//! Only values whose data is exactly [`ARGUMENTS`] are ever changed or
//! removed: a setting someone else made for an app is left alone. The
//! policy is keyed by file name, so it also covers other programs with the
//! same file name (they lose only pages shown through WebView2).

#![allow(unsafe_code)]

use std::collections::BTreeSet;
use std::io;

use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, WIN32_ERROR,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, KEY_WRITE, REG_OPTION_NON_VOLATILE,
    REG_SZ, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteValueW,
    RegEnumValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

/// The browser arguments Whereabouts sets: every request goes to a closed
/// port on this computer (Chromium never sends loopback through a proxy).
pub const ARGUMENTS: &str = "--proxy-server=http://127.0.0.1:9";

/// Where WebView2 reads the setting, under `HKEY_LOCAL_MACHINE`.
pub const POLICY_KEY: &str =
    r"SOFTWARE\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments";

/// What to change so that exactly the `wanted` file names (lower case) carry
/// our arguments: `(set, delete)`. `existing` holds every value of the key,
/// with its data when it is text.
pub fn plan(
    existing: &[(String, Option<String>)],
    wanted: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    let ours = |data: &Option<String>| data.as_deref() == Some(ARGUMENTS);
    let delete = existing
        .iter()
        .filter(|(name, data)| ours(data) && !wanted.contains(&name.to_lowercase()))
        .map(|(name, _)| name.clone())
        .collect();
    let set = wanted
        .iter()
        .filter(|name| {
            !existing
                .iter()
                .any(|(other, _)| other.to_lowercase() == **name)
        })
        .cloned()
        .collect();
    (set, delete)
}

/// An open registry key, closed when dropped.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key was opened by us and is closed once.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

fn check(code: WIN32_ERROR) -> io::Result<()> {
    if code.is_ok() {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code.0 as i32))
    }
}

/// Makes the values under `HKEY_LOCAL_MACHINE\{key}` match `wanted` (lower
/// case file names). The key is made only when something is wanted, and
/// removed when it ends up empty.
pub fn sync(key: &str, wanted: &BTreeSet<String>) -> io::Result<()> {
    let path = HSTRING::from(key);
    let mut handle = HKEY::default();
    let access = KEY_READ | KEY_WRITE | KEY_WOW64_64KEY;
    let code = if wanted.is_empty() {
        // SAFETY: `path` outlives the call; `handle` receives the key.
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, &path, None, access, &mut handle) }
    } else {
        // SAFETY: as above; no class, default security, no disposition.
        unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                &path,
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                access,
                None,
                &mut handle,
                None,
            )
        }
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(()); // nothing wanted and nothing there
    }
    check(code)?;
    let opened = Key(handle);
    let existing = values(&opened)?;
    let (set, delete) = plan(&existing, wanted);
    for name in &delete {
        // SAFETY: the key is open; the name outlives the call.
        check(unsafe { RegDeleteValueW(opened.0, &HSTRING::from(name.as_str())) })?;
    }
    for name in &set {
        let wide: Vec<u16> = ARGUMENTS.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes: Vec<u8> = wide.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        // SAFETY: the key is open; the name and data outlive the call.
        check(unsafe {
            RegSetValueExW(
                opened.0,
                &HSTRING::from(name.as_str()),
                None,
                REG_SZ,
                Some(&bytes),
            )
        })?;
    }
    let left = existing.len() + set.len() - delete.len();
    drop(opened);
    if left == 0 {
        // Leave nothing behind (it holds no values and no subkeys here).
        // SAFETY: `path` outlives the call. Fails harmlessly if the key
        // has subkeys.
        let _ = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, &path) };
    }
    Ok(())
}

/// The text data of the value `name` under `HKEY_LOCAL_MACHINE\{key}`, or
/// `None` if the key or the value is missing.
#[cfg(test)]
pub fn value(key: &str, name: &str) -> io::Result<Option<String>> {
    let mut handle = HKEY::default();
    // SAFETY: the path outlives the call; `handle` receives the key.
    let code = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            &HSTRING::from(key),
            None,
            KEY_READ | KEY_WOW64_64KEY,
            &mut handle,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    check(code)?;
    read_text(&Key(handle), name)
}

/// Every value of `key`: its name, and its data when it is text.
fn values(key: &Key) -> io::Result<Vec<(String, Option<String>)>> {
    let mut found = Vec::new();
    // Value names are at most 16,383 characters.
    let mut name = vec![0u16; 16_384];
    for index in 0.. {
        let mut len = u32::try_from(name.len()).map_err(io::Error::other)?;
        // SAFETY: `name` has `len` writable characters; both outlive the call.
        let code = unsafe {
            RegEnumValueW(
                key.0,
                index,
                Some(PWSTR(name.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            )
        };
        if code == ERROR_NO_MORE_ITEMS {
            break;
        }
        check(code)?;
        let text = String::from_utf16_lossy(&name[..len as usize]);
        let data = read_text(key, &text)?;
        found.push((text, data));
    }
    Ok(found)
}

/// A text value's data, or `None` if it is not text.
fn read_text(key: &Key, value: &str) -> io::Result<Option<String>> {
    let value = HSTRING::from(value);
    let mut size = 0u32;
    for _ in 0..4 {
        let mut data = vec![0u16; (size as usize).div_ceil(2)];
        let mut len = size;
        // SAFETY: `data` has at least `len` writable bytes (none when
        // asking for the size); everything outlives the call.
        let code = unsafe {
            RegGetValueW(
                key.0,
                PCWSTR::null(),
                &value,
                RRF_RT_REG_SZ,
                None,
                (size > 0).then_some(data.as_mut_ptr().cast()),
                Some(&mut len),
            )
        };
        if code == ERROR_MORE_DATA || (code.is_ok() && size == 0) {
            size = len;
            continue;
        }
        if code.is_ok() {
            let chars = (len as usize / 2).min(data.len());
            let text = String::from_utf16_lossy(&data[..chars]);
            return Ok(Some(text.trim_end_matches('\0').to_owned()));
        }
        // Not text (or gone meanwhile): never ours.
        return Ok(None);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wanted(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    fn value(name: &str, data: &str) -> (String, Option<String>) {
        (name.to_owned(), Some(data.to_owned()))
    }

    #[test]
    fn sets_what_is_wanted_and_removes_only_its_own() {
        let existing = vec![
            value("Old.exe", ARGUMENTS),
            value("theirs.exe", "--remote-debugging-port=9222"),
            ("binary.exe".to_owned(), None),
        ];
        let (set, delete) = plan(&existing, &wanted(&["utweb.exe"]));
        assert_eq!(set, vec!["utweb.exe"]);
        assert_eq!(delete, vec!["Old.exe"], "someone else's values stay");
    }

    #[test]
    fn never_overwrites_someone_elses_setting_for_a_blocked_app() {
        let existing = vec![value("UTWEB.EXE", "--their-own-flag")];
        let (set, delete) = plan(&existing, &wanted(&["utweb.exe"]));
        assert!(set.is_empty() && delete.is_empty());
    }

    #[test]
    fn a_value_already_in_place_is_kept_whatever_its_case() {
        let existing = vec![value("uTorrent.EXE", ARGUMENTS)];
        let (set, delete) = plan(&existing, &wanted(&["utorrent.exe"]));
        assert!(set.is_empty() && delete.is_empty());
    }

    #[test]
    fn nothing_wanted_removes_all_of_ours() {
        let existing = vec![value("a.exe", ARGUMENTS), value("b.exe", ARGUMENTS)];
        let (set, delete) = plan(&existing, &BTreeSet::new());
        assert!(set.is_empty());
        assert_eq!(delete, vec!["a.exe", "b.exe"]);
    }
}
