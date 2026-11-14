//! Privacy rules applied before anything is stored (design spec §3, D5).

/// Executable names of common web browsers (lowercase).
///
/// For a browser, the list of domains it connects to is the user's browsing
/// history, so only the registrable domain (`example.com`, not
/// `mail.example.com`) is stored by default. Embedded web views inside
/// other apps (`msedgewebview2.exe`) are not browsing and are not listed.
const WEB_BROWSERS: [&str; 12] = [
    "chrome.exe",
    "chromium.exe",
    "msedge.exe",
    "firefox.exe",
    "librewolf.exe",
    "waterfox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "arc.exe",
    "thorium.exe",
    "iexplore.exe",
];

/// Returns `true` if `executable` (a file name like `chrome.exe`) is a
/// known web browser.
pub fn is_web_browser(executable: &str) -> bool {
    let name = executable.to_ascii_lowercase();
    WEB_BROWSERS.contains(&name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_browsers_case_insensitively() {
        assert!(is_web_browser("chrome.exe"));
        assert!(is_web_browser("MSEdge.EXE"));
        assert!(is_web_browser("firefox.exe"));
    }

    #[test]
    fn web_views_and_other_apps_are_not_browsers() {
        assert!(!is_web_browser("msedgewebview2.exe"));
        assert!(!is_web_browser("claude.exe"));
        assert!(!is_web_browser("curl.exe"));
    }
}
