//! New apps on the network (v0.2, N4).
//!
//! Whereabouts remembers which programs have used the network (in the
//! encrypted store) and announces the first use of a new one as a notice
//! that the desktop app turns into a Windows notification.
//!
//! So that people are not flooded when they start using Whereabouts, every
//! program seen in the first 24 hours (and every program in the saved
//! history when upgrading) is learned quietly. The same happens after the
//! history is deleted. Without a store nothing can be remembered across
//! restarts, so nothing is announced.

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use whereabouts_store::{Store, known_app_key};

/// How long programs are learned quietly.
const LEARNING: Duration = Duration::from_secs(24 * 60 * 60);

/// Saved setting: until when programs are learned quietly (seconds since
/// 1970).
const LEARNING_UNTIL: &str = "apps_learning_until";

/// Most programs remembered in memory (the store keeps them all).
const MAX_KNOWN: usize = 100_000;

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The programs known to have used the network.
#[derive(Debug)]
pub struct NewApps {
    known: HashSet<String>,
    learning_until: SystemTime,
    /// `false` without a store: nothing is announced.
    enabled: bool,
}

impl NewApps {
    /// Loads the known programs. Problems are reported, not fatal.
    pub fn load(store: Option<&mut Store>, now: SystemTime) -> Self {
        let Some(store) = store else {
            return Self {
                known: HashSet::new(),
                learning_until: now,
                enabled: false,
            };
        };
        let known = match store.known_app_keys() {
            Ok(keys) => keys.into_iter().collect(),
            Err(error) => {
                report!("warning: could not read the known apps: {error}");
                return Self {
                    known: HashSet::new(),
                    learning_until: now,
                    enabled: false,
                };
            }
        };
        let saved = store
            .setting(LEARNING_UNTIL)
            .ok()
            .flatten()
            .and_then(|value| value.parse::<u64>().ok())
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
        let mut apps = Self {
            known,
            learning_until: now,
            enabled: true,
        };
        match saved {
            Some(until) => apps.learning_until = until,
            None => apps.start_learning(store, now),
        }
        apps
    }

    fn start_learning(&mut self, store: &mut Store, now: SystemTime) {
        self.learning_until = now + LEARNING;
        if let Err(error) =
            store.set_setting(LEARNING_UNTIL, &unix_secs(self.learning_until).to_string())
        {
            report!("warning: could not save the learning period: {error}");
        }
    }

    /// Called the first time each process instance uses the network.
    /// Returns `true` if `path` is a program never seen before that should
    /// be announced.
    pub fn seen(&mut self, store: Option<&mut Store>, path: &str, now: SystemTime) -> bool {
        if !self.enabled {
            return false;
        }
        let key = known_app_key(path);
        if self.known.contains(&key) {
            return false;
        }
        if self.known.len() < MAX_KNOWN {
            self.known.insert(key);
        }
        let saved = store.is_some_and(|store| match store.add_known_app(path, now) {
            Ok(_) => true,
            Err(error) => {
                report!("warning: could not save a known app: {error}");
                false
            }
        });
        saved && now >= self.learning_until
    }

    /// Called after all saved data was deleted: forget the programs and
    /// learn quietly again.
    pub fn reset(&mut self, store: Option<&mut Store>, now: SystemTime) {
        self.known.clear();
        if let Some(store) = store {
            self.start_learning(store, now);
            self.enabled = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use whereabouts_store::Key;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    const T0: u64 = 1_800_000_000;

    fn store(name: &str) -> (Store, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("whereabouts-apps-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("t.db"), &Key::from_bytes([4; 32])).unwrap();
        (store, dir)
    }

    #[test]
    fn new_apps_are_announced_once_after_the_learning_day() {
        let (mut store, dir) = store("announce");
        let mut apps = NewApps::load(Some(&mut store), at(T0));
        // Learned quietly on the first day.
        assert!(!apps.seen(Some(&mut store), r"C:\Apps\Early.exe", at(T0 + 60)));
        assert!(!apps.seen(Some(&mut store), r"C:\Apps\Early.exe", at(T0 + 2 * 86_400)));
        // Afterwards a new program is announced, once.
        assert!(apps.seen(Some(&mut store), r"C:\Apps\Late.exe", at(T0 + 2 * 86_400)));
        assert!(!apps.seen(Some(&mut store), r"c:\apps\LATE.exe", at(T0 + 2 * 86_400)));
        // A restart remembers both programs and the learning period.
        let mut apps = NewApps::load(Some(&mut store), at(T0 + 3 * 86_400));
        assert!(!apps.seen(Some(&mut store), r"C:\Apps\Late.exe", at(T0 + 3 * 86_400)));
        assert!(apps.seen(Some(&mut store), r"C:\Apps\Other.exe", at(T0 + 3 * 86_400)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn deleting_the_history_starts_learning_again() {
        let (mut store, dir) = store("reset");
        let mut apps = NewApps::load(Some(&mut store), at(T0));
        let later = at(T0 + 2 * 86_400);
        assert!(apps.seen(Some(&mut store), r"C:\Apps\A.exe", later));
        store.wipe().unwrap();
        apps.reset(Some(&mut store), later);
        assert!(!apps.seen(Some(&mut store), r"C:\Apps\B.exe", later));
        assert!(!apps.seen(Some(&mut store), r"C:\Apps\A.exe", later));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn nothing_is_announced_without_a_store() {
        let mut apps = NewApps::load(None, at(T0));
        assert!(!apps.seen(None, r"C:\Apps\A.exe", at(T0 + 9 * 86_400)));
    }
}
