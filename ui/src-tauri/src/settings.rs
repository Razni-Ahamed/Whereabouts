//! The app's own settings, per Windows user (v0.2, N4).
//!
//! Kept as a small JSON file in the user's app configuration folder
//! (`%APPDATA%\org.whereabouts.app\settings.json`). It holds only on/off
//! choices, never captured data. Whether the app starts at sign-in is not
//! stored here: Windows' own list of sign-in programs is the source of
//! truth (see `whereabouts-win-startup`).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// The settings file's name.
const FILE: &str = "settings.json";

/// Largest settings file read; anything bigger is ignored.
const MAX_FILE: u64 = 64 * 1024;

/// The app's settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Whether the first-run question (start at sign-in?) was answered.
    pub first_run_done: bool,
    /// Whether to show Windows notifications at all.
    pub notifications: bool,
    /// Whether notifications may name apps and sites. Off by default:
    /// Windows keeps a history of notifications and may show them on the
    /// lock screen.
    pub show_names: bool,
    /// Whether the "still running in the tray" hint was shown.
    pub tray_hint_shown: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            first_run_done: false,
            notifications: true,
            show_names: false,
            tray_hint_shown: false,
        }
    }
}

/// The app's settings while it runs.
#[derive(Debug)]
pub struct AppState {
    /// Where they are saved.
    pub file: SettingsFile,
    /// The current settings.
    pub settings: Mutex<Settings>,
    /// Whether the app was started at sign-in, in the tray.
    pub background: bool,
}

/// Where the settings live.
#[derive(Debug, Clone)]
pub struct SettingsFile(PathBuf);

impl SettingsFile {
    /// The settings file in `config_dir`.
    pub fn in_dir(config_dir: &Path) -> Self {
        Self(config_dir.join(FILE))
    }

    /// The saved settings, or the defaults if there are none (or they
    /// cannot be read).
    pub fn load(&self) -> Settings {
        let Ok(meta) = std::fs::metadata(&self.0) else {
            return Settings::default();
        };
        if meta.len() > MAX_FILE {
            return Settings::default();
        }
        std::fs::read(&self.0)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Saves `settings` (written to a temporary file, then moved in place).
    pub fn save(&self, settings: &Settings) -> std::io::Result<()> {
        if let Some(dir) = self.0.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let temporary = self.0.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(settings).map_err(std::io::Error::other)?;
        std::fs::write(&temporary, json)?;
        std::fs::rename(&temporary, &self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip_and_default_when_missing_or_broken() {
        let dir = std::env::temp_dir().join(format!("wa-app-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = SettingsFile::in_dir(&dir);
        assert_eq!(file.load(), Settings::default());
        assert!(file.load().notifications && !file.load().show_names);
        let chosen = Settings {
            first_run_done: true,
            notifications: false,
            show_names: true,
            tray_hint_shown: true,
        };
        file.save(&chosen).unwrap();
        assert_eq!(file.load(), chosen);
        std::fs::write(dir.join(FILE), b"not json").unwrap();
        assert_eq!(file.load(), Settings::default());
        // Unknown or missing fields keep the defaults.
        std::fs::write(dir.join(FILE), br#"{"first_run_done":true,"future":1}"#).unwrap();
        assert!(file.load().first_run_done && file.load().notifications);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
