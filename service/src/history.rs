//! The user's choice whether connection history is saved.
//!
//! History is saved until the user turns it off (on the Privacy screen, or
//! when the app first asks). When it is off, finished connections are shown
//! live and then forgotten; alerts, blocking rules, known apps and settings
//! are still saved, because those features need them.

use whereabouts_store::Store;

/// The saved setting: `"true"` or `"false"`, missing until the user chose.
const SAVE_HISTORY: &str = "save_history";

/// Whether finished connections are saved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HistorySwitch {
    /// The user's choice; `None` until they chose.
    choice: Option<bool>,
}

impl HistorySwitch {
    /// Reads the user's choice. Without a database nothing is saved anyway.
    /// If the choice cannot be read, history is treated as off for this
    /// run, so a choice to stop saving is never overridden by an error.
    pub fn load(store: Option<&Store>) -> Self {
        let Some(store) = store else {
            return Self::default();
        };
        let choice = match store.setting(SAVE_HISTORY) {
            Ok(Some(value)) => match value.as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            Ok(None) => None,
            Err(error) => {
                report!("warning: could not read whether to save history ({error}); not saving");
                Some(false)
            }
        };
        Self { choice }
    }

    /// The user's choice; `None` until they chose.
    pub fn choice(self) -> Option<bool> {
        self.choice
    }

    /// Whether finished connections are saved (on until the user turns it
    /// off).
    pub fn on(self) -> bool {
        self.choice != Some(false)
    }

    /// Saves the user's choice and applies it. When turning saving off with
    /// `delete_saved`, also deletes the connections and hourly totals saved
    /// so far (alerts, rules, known apps and settings are kept).
    pub fn set(&mut self, store: &mut Store, save: bool, delete_saved: bool) -> Result<(), String> {
        store
            .set_setting(SAVE_HISTORY, if save { "true" } else { "false" })
            .map_err(|e| format!("could not save the choice: {e}"))?;
        self.choice = Some(save);
        if save {
            report!("Saving connection history at the user's request");
        } else {
            report!("Stopped saving connection history at the user's request");
            if delete_saved {
                store
                    .delete_history()
                    .map_err(|e| format!("could not delete the saved history: {e}"))?;
                report!("Saved connection history was deleted at the user's request");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use whereabouts_store::Key;

    fn temp_store(name: &str) -> (Store, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("whereabouts-history-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("t.db"), &Key::from_bytes([9; 32])).unwrap();
        (store, dir)
    }

    #[test]
    fn history_is_on_until_the_user_turns_it_off() {
        let (mut store, dir) = temp_store("switch");
        let mut switch = HistorySwitch::load(Some(&store));
        assert_eq!(switch.choice(), None);
        assert!(switch.on());

        switch.set(&mut store, false, false).unwrap();
        assert!(!switch.on());
        // The choice is kept across restarts.
        assert_eq!(HistorySwitch::load(Some(&store)).choice(), Some(false));

        switch.set(&mut store, true, true).unwrap();
        assert!(switch.on());
        assert_eq!(HistorySwitch::load(Some(&store)).choice(), Some(true));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_unknown_saved_value_counts_as_not_chosen() {
        let (mut store, dir) = temp_store("unknown");
        store.set_setting(SAVE_HISTORY, "maybe").unwrap();
        assert_eq!(HistorySwitch::load(Some(&store)).choice(), None);
        assert_eq!(HistorySwitch::load(None).choice(), None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
