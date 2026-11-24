//! Which programs count as a web browser that "goes anywhere" (design spec
//! v0.3): a browser legitimately contacts any site, so its profile does not
//! flag new domains, but only if the program is really that browser.

/// `(file name, expected publisher)` for browsers whose signing certificate's
/// publisher is well known.
///
/// Browsers in `whereabouts_core::privacy` that are not listed here (for
/// example `chromium.exe`, `librewolf.exe`, `arc.exe`) are not recognised
/// automatically: the user can still switch "goes anywhere" on for them. To
/// add one, confirm the publisher string the service reports for a real,
/// signed install and add a row; names are lower case.
const BROWSER_PUBLISHERS: [(&str, &str); 7] = [
    ("chrome.exe", "Google LLC"),
    ("msedge.exe", "Microsoft Corporation"),
    ("iexplore.exe", "Microsoft Corporation"),
    ("firefox.exe", "Mozilla Corporation"),
    ("brave.exe", "Brave Software, Inc."),
    ("opera.exe", "Opera Norway AS"),
    ("vivaldi.exe", "Vivaldi Technologies AS"),
];

/// Returns `true` if `app_name` is a listed browser, its signature is valid
/// the publisher is the one expected for that browser, and the file is
/// installed by administrators (`installed_by_admins`, worked out by the
/// caller). A program that only has a browser's file name, or that another
/// program of the same publisher was copied over (a Microsoft-signed
/// `curl.exe` renamed `msedge.exe`), does not qualify. Comparison ignores
/// ASCII case.
///
/// Per-user browser installs (for example in `LocalAppData`) are not
/// recognised automatically, because a normal program could plant a file
/// there; the user can switch "goes anywhere" on for such a browser.
pub fn auto_goes_anywhere(
    app_name: &str,
    publisher: Option<&str>,
    signature_valid: bool,
    installed_by_admins: bool,
) -> bool {
    if !signature_valid || !installed_by_admins {
        return false;
    }
    let Some(publisher) = publisher else {
        return false;
    };
    BROWSER_PUBLISHERS.iter().any(|(name, expected)| {
        name.eq_ignore_ascii_case(app_name) && expected.eq_ignore_ascii_case(publisher)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_browser_does_not_go_anywhere() {
        assert!(!auto_goes_anywhere(
            "chrome.exe",
            Some("Evil Ltd"),
            true,
            true
        ));
        assert!(!auto_goes_anywhere(
            "chrome.exe",
            Some("Google LLC"),
            false,
            true
        ));
        assert!(!auto_goes_anywhere("chrome.exe", None, true, true));
    }

    #[test]
    fn real_browser_goes_anywhere() {
        assert!(auto_goes_anywhere(
            "CHROME.EXE",
            Some("google llc"),
            true,
            true
        ));
        assert!(auto_goes_anywhere(
            "msedge.exe",
            Some("Microsoft Corporation"),
            true,
            true
        ));
    }

    #[test]
    fn browser_not_installed_by_admins_does_not_go_anywhere() {
        assert!(!auto_goes_anywhere(
            "chrome.exe",
            Some("Google LLC"),
            true,
            false
        ));
        assert!(auto_goes_anywhere(
            "chrome.exe",
            Some("Google LLC"),
            true,
            true
        ));
    }

    #[test]
    fn other_programs_do_not_go_anywhere() {
        assert!(!auto_goes_anywhere(
            "notepad.exe",
            Some("Google LLC"),
            true,
            true
        ));
    }

    #[test]
    fn every_listed_name_is_a_known_browser() {
        for (name, _) in BROWSER_PUBLISHERS {
            assert!(whereabouts_core::privacy::is_web_browser(name), "{name}");
        }
    }
}
