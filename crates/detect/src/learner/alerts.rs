//! The Learner's behaviour alerts: combining signals into one open alert per
//! app, raising each app, signal and value at most once a local day, "this
//! is fine" allows, and the links from pending destinations to the alert
//! that named them.

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use whereabouts_store::{
    AlertKind, ItemKind, NewAlert, Reason, Severity, Signal, Store, StoreError, cap_reasons,
};

use super::AppFacts;
use crate::signals::severity_of;
use crate::{Raised, unix_secs};

/// Signals for the same app within this many seconds of an alert's first
/// one update that alert instead of raising another.
pub const COMBINE_WINDOW: u64 = 600;

/// An app's open behaviour alert, which later signals update.
#[derive(Debug)]
struct Window {
    /// When the window opened, in Unix seconds.
    start: u64,
    /// The saved alert's ID.
    id: i64,
    /// The alert as it stands (all its reasons, current severity).
    alert: NewAlert,
}

/// What a pending destination's next sighting does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Link {
    /// Counts as "seen again" on this open alert.
    Open(i64),
    /// The user dismissed the alert ("remind me"): raises a new alert.
    Closed,
}

/// The outcome of saving reasons.
#[derive(Debug, Default)]
pub(super) struct Saved {
    /// The alert the reasons are on, if they were saved.
    pub(super) id: Option<i64>,
    /// The alert to notify about, if it is new (above info) or its severity
    /// went up.
    pub(super) raised: Option<Raised>,
}

/// The state behind behaviour alerts, kept in memory.
#[derive(Debug, Default)]
pub(super) struct Alerts {
    /// The open alert of each app.
    windows: HashMap<String, Window>,
    /// Pending destinations by app key, kind and value.
    links: HashMap<(String, ItemKind, String), Link>,
    /// How many times each alert's pending destinations were seen again.
    seen_again: HashMap<i64, u32>,
    /// Reasons saved today, by app key, signal and value.
    raised_today: HashSet<(String, Signal, String)>,
    /// The local day `raised_today` is for.
    day: Option<i64>,
}

impl Alerts {
    /// Starts a new day of reasons when `local_day` changes.
    pub(super) fn new_day(&mut self, local_day: i64) {
        if self.day != Some(local_day) {
            self.day = Some(local_day);
            self.raised_today.clear();
        }
    }

    /// What links a pending destination to its alert, if this run knows.
    pub(super) fn link(&self, key: &str, kind: ItemKind, value: &str) -> Option<Link> {
        self.links
            .get(&(key.to_owned(), kind, value.to_owned()))
            .copied()
    }

    /// Links a pending destination to the open alert `id`.
    pub(super) fn set_link(&mut self, key: &str, kind: ItemKind, value: &str, id: i64) {
        self.links
            .insert((key.to_owned(), kind, value.to_owned()), Link::Open(id));
    }

    /// The reasons not yet saved today for this app and not allowed by the
    /// user ("this is fine" on beaconing, a random-looking name or an
    /// unusual hour). An allow that cannot be read fails the whole batch.
    pub(super) fn fresh(
        &self,
        key: &str,
        reasons: Vec<Reason>,
        store: &Store,
    ) -> Result<Vec<Reason>, StoreError> {
        let mut fresh = Vec::new();
        for reason in reasons {
            if self.raised_today.contains(&today(key, &reason)) {
                continue;
            }
            if let Some(allow) = allow_key(key, &reason)
                && store.is_allowed(&allow)?
            {
                continue;
            }
            fresh.push(reason);
        }
        Ok(fresh)
    }

    /// Saves reasons as a behaviour alert: they update the app's open alert
    /// if its window is still open, otherwise they open a new one. Only
    /// saved reasons count as raised today.
    pub(super) fn save(
        &mut self,
        key: &str,
        app: &AppFacts<'_>,
        reasons: Vec<Reason>,
        store: &mut Store,
        now: SystemTime,
    ) -> Result<Saved, StoreError> {
        let Some(first) = reasons.first() else {
            return Ok(Saved::default());
        };
        let secs = unix_secs(now);

        if let Some(window) = self.windows.get_mut(key)
            && secs.saturating_sub(window.start) < COMBINE_WINDOW
        {
            let mut merged = window.alert.reasons.clone();
            for reason in &reasons {
                if !merged
                    .iter()
                    .any(|r| r.signal == reason.signal && r.value == reason.value)
                {
                    merged.push(reason.clone());
                }
            }
            let severity = combined(&merged).max(window.alert.severity);
            // Bounded like the saved alert (the store keeps the count).
            cap_reasons(&mut merged);
            let seen_again = self.seen_again.get(&window.id).copied().unwrap_or(0);
            // `false`: the alert is gone (all data deleted), so a new one opens.
            if store.update_alert(window.id, &reasons, severity, seen_again, now)? {
                let raised = severity > window.alert.severity;
                // A signal that can be allowed may join an alert that began
                // without one: the alert gains its "this is fine", if the
                // reason was kept (one the cap dropped is never shown).
                if window.alert.allow_key.is_none()
                    && let Some(allow) = reasons
                        .iter()
                        .filter(|r| {
                            merged
                                .iter()
                                .any(|m| m.signal == r.signal && m.value == r.value)
                        })
                        .find_map(|r| allow_key(key, r))
                    && store.set_allow_key(window.id, &allow)?
                {
                    window.alert.allow_key = Some(allow);
                }
                window.alert.reasons = merged;
                window.alert.severity = severity;
                let saved = Saved {
                    id: Some(window.id),
                    raised: raised.then(|| Raised {
                        id: window.id,
                        alert: window.alert.clone(),
                    }),
                };
                self.mark_today(key, &reasons);
                return Ok(saved);
            }
        }

        // The store keeps the same reasons and counts the rest; only a kept
        // reason, one the user sees, can give the alert its "this is fine".
        let mut kept = reasons.clone();
        cap_reasons(&mut kept);
        let mut alert = NewAlert {
            key: format!("behaviour|{key}|{secs}"),
            allow_key: kept.iter().find_map(|r| allow_key(key, r)),
            kind: AlertKind::Behaviour,
            severity: combined(&reasons),
            app_name: Some(app.app_name.to_owned()),
            app_path: Some(app.path.to_owned()),
            target: first.value.clone(),
            detail: None,
            reasons,
        };
        let Some(id) = store.add_alert(&alert, now)? else {
            return Ok(Saved::default());
        };
        self.mark_today(key, &alert.reasons);
        alert.reasons = kept;
        self.windows.insert(
            key.to_owned(),
            Window {
                start: secs,
                id,
                alert: alert.clone(),
            },
        );
        Ok(Saved {
            id: Some(id),
            raised: (alert.severity > Severity::Info).then_some(Raised { id, alert }),
        })
    }

    /// Counts a sighting of pending destinations on the open alerts that
    /// named them (once per alert). Returns the first error.
    pub(super) fn count_seen_again(
        &mut self,
        key: &str,
        seen: &[(ItemKind, String)],
        store: &mut Store,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let mut ids: Vec<i64> = seen
            .iter()
            .filter_map(|(kind, value)| match self.link(key, *kind, value) {
                Some(Link::Open(id)) => Some(id),
                _ => None,
            })
            .collect();
        ids.sort_unstable();
        ids.dedup();
        let mut result = Ok(());
        for id in ids {
            let count = self.seen_again.entry(id).or_insert(0);
            *count = count.saturating_add(1);
            // Info never lowers a severity: only the count changes.
            match store.update_alert(id, &[], Severity::Info, *count, now) {
                Ok(true) => {}
                Ok(false) => {
                    self.links.retain(|_, link| *link != Link::Open(id));
                    self.seen_again.remove(&id);
                }
                Err(error) => {
                    if result.is_ok() {
                        result = Err(error);
                    }
                }
            }
        }
        result
    }

    /// The pending destinations linked to alert `id`. Their links stay until
    /// the caller says what happens to each ([`Alerts::remind`] or
    /// [`Alerts::unlink`]).
    pub(super) fn linked(&self, id: i64) -> Vec<(String, ItemKind, String)> {
        self.links
            .iter()
            .filter(|(_, link)| **link == Link::Open(id))
            .map(|(named, _)| named.clone())
            .collect()
    }

    /// The user closed alert `id`: its window ends and its "seen again"
    /// count is forgotten.
    pub(super) fn close(&mut self, id: i64) {
        self.windows.retain(|_, window| window.id != id);
        self.seen_again.remove(&id);
    }

    /// "Remind me": the next sighting of this pending destination raises a
    /// new alert, even today.
    pub(super) fn remind(&mut self, key: &str, kind: ItemKind, value: &str) {
        self.links
            .insert((key.to_owned(), kind, value.to_owned()), Link::Closed);
        self.raised_today.retain(|(app, signal, raised)| {
            !(app == key && raised == value && item_kind(*signal) == Some(kind))
        });
    }

    /// Forgets the link of a destination that is no longer pending.
    pub(super) fn unlink(&mut self, key: &str, kind: ItemKind, value: &str) {
        self.links.remove(&(key.to_owned(), kind, value.to_owned()));
    }

    /// Restores a pending destination's link read back from the store (after
    /// a restart), with the alert's saved "seen again" count. A link this
    /// run already holds is more recent and is kept.
    pub(super) fn restore(
        &mut self,
        key: &str,
        kind: ItemKind,
        value: &str,
        link: Link,
        seen_again: u32,
    ) {
        self.links
            .entry((key.to_owned(), kind, value.to_owned()))
            .or_insert(link);
        if let Link::Open(id) = link {
            self.seen_again.entry(id).or_insert(seen_again);
        }
    }

    /// Forgets everything about an app.
    pub(super) fn forget(&mut self, key: &str) {
        if let Some(window) = self.windows.remove(key) {
            self.seen_again.remove(&window.id);
        }
        self.links.retain(|(app, _, _), link| {
            let keep = app != key;
            if !keep && let Link::Open(id) = link {
                self.seen_again.remove(id);
            }
            keep
        });
        self.raised_today.retain(|(app, _, _)| app != key);
    }

    fn mark_today(&mut self, key: &str, reasons: &[Reason]) {
        for reason in reasons {
            self.raised_today.insert(today(key, reason));
        }
    }
}

/// The profile item a destination signal is about.
pub(super) fn item_kind(signal: Signal) -> Option<ItemKind> {
    match signal {
        Signal::NewSite | Signal::RandomName => Some(ItemKind::Domain),
        Signal::NewCompany => Some(ItemKind::Company),
        Signal::NewCountry => Some(ItemKind::Country),
        _ => None,
    }
}

fn today(key: &str, reason: &Reason) -> (String, Signal, String) {
    (
        key.to_owned(),
        reason.signal,
        reason.value.clone().unwrap_or_default(),
    )
}

/// The lasting "this is fine" key for a reason, for the signals that have
/// one (beaconing, random-looking name, unusual time, impostor).
pub(super) fn allow_key(key: &str, reason: &Reason) -> Option<String> {
    let allowable = matches!(
        reason.signal,
        Signal::Beaconing | Signal::RandomName | Signal::UnusualTime | Signal::Impostor
    );
    let value = reason.value.as_deref().filter(|_| allowable)?;
    Some(format!(
        "behaviour|{key}|{}|{value}",
        reason.signal.as_str()
    ))
}

/// The severity of reasons together: the highest, raised to high when two
/// or more are medium.
fn combined(reasons: &[Reason]) -> Severity {
    let highest = reasons
        .iter()
        .map(|r| severity_of(r.signal))
        .max()
        .unwrap_or(Severity::Info);
    let mediums = reasons
        .iter()
        .filter(|r| severity_of(r.signal) == Severity::Medium)
        .count();
    if mediums >= 2 {
        highest.max(Severity::High)
    } else {
        highest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use whereabouts_store::MAX_REASONS;

    fn reason(signal: Signal, value: Option<&str>) -> Reason {
        Reason {
            signal,
            value: value.map(str::to_owned),
            observed: None,
            usual: None,
            count: None,
        }
    }

    #[test]
    fn two_mediums_make_high() {
        let beacon = reason(Signal::Beaconing, Some("c2.example"));
        let name = reason(Signal::RandomName, Some("xk3j9q2m7z.example"));
        let site = reason(Signal::NewSite, Some("a.example"));
        let country = reason(Signal::NewCountry, Some("RU"));
        assert_eq!(combined(std::slice::from_ref(&site)), Severity::Info);
        assert_eq!(combined(&[site, country]), Severity::Info);
        assert_eq!(
            combined(&[reason(Signal::NewSite, None), beacon.clone()]),
            Severity::Medium
        );
        assert_eq!(combined(&[beacon, name]), Severity::High);
        assert_eq!(combined(&[]), Severity::Info);
    }

    #[test]
    fn an_impostor_warning_can_be_allowed_lastingly() {
        let impostor = reason(Signal::Impostor, Some(r"C:\Apps\chrome.exe"));
        assert_eq!(
            allow_key("k", &impostor).as_deref(),
            Some(r"behaviour|k|impostor|C:\Apps\chrome.exe")
        );
    }

    #[test]
    fn only_lasting_signals_have_allow_keys() {
        let beacon = reason(Signal::Beaconing, Some("c2.example"));
        assert_eq!(
            allow_key("k", &beacon).as_deref(),
            Some("behaviour|k|beaconing|c2.example")
        );
        assert_eq!(
            allow_key("k", &reason(Signal::NewCountry, Some("RU"))),
            None
        );
        assert_eq!(allow_key("k", &reason(Signal::UnusualTime, None)), None);
    }

    #[test]
    fn dismissing_reopens_the_day_for_its_values() {
        let mut alerts = Alerts::default();
        alerts.set_link("k", ItemKind::Country, "RU", 7);
        alerts.set_link("k", ItemKind::Company, "Acme", 8);
        alerts.mark_today("k", &[reason(Signal::NewCountry, Some("RU"))]);
        alerts.mark_today("k", &[reason(Signal::NewCompany, Some("Acme"))]);
        let named = alerts.linked(7);
        alerts.close(7);
        assert_eq!(
            named,
            [("k".to_owned(), ItemKind::Country, "RU".to_owned())]
        );
        // Closing alone keeps the link; the caller decides.
        assert_eq!(
            alerts.link("k", ItemKind::Country, "RU"),
            Some(Link::Open(7))
        );
        alerts.remind("k", ItemKind::Country, "RU");
        assert_eq!(
            alerts.link("k", ItemKind::Country, "RU"),
            Some(Link::Closed)
        );
        assert!(
            !alerts
                .raised_today
                .contains(&today("k", &reason(Signal::NewCountry, Some("RU"))))
        );
        // Other alerts' values are untouched.
        assert_eq!(
            alerts.link("k", ItemKind::Company, "Acme"),
            Some(Link::Open(8))
        );
        assert_eq!(alerts.raised_today.len(), 1);
        // Allowing drops the link.
        alerts.close(8);
        alerts.unlink("k", ItemKind::Company, "Acme");
        assert_eq!(alerts.link("k", ItemKind::Company, "Acme"), None);
    }

    /// A temporary store and its folder (removed by the caller).
    fn store(name: &str) -> (Store, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("whereabouts-alerts-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = whereabouts_store::Key::from_bytes([3; 32]);
        (Store::open(&dir.join("t.db"), &key).unwrap(), dir)
    }

    fn app() -> AppFacts<'static> {
        AppFacts {
            app_name: "Chat.exe",
            path: r"C:\Apps\Chat.exe",
            sha256: None,
            publisher: None,
            signature_valid: false,
            installed_by_admins: false,
        }
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs)
    }

    /// `count` new companies (info, nothing to allow).
    fn companies(count: usize) -> Vec<Reason> {
        (0..count)
            .map(|n| reason(Signal::NewCompany, Some(&format!("Company {n}"))))
            .collect()
    }

    #[test]
    fn a_reason_the_cap_dropped_gives_no_allow_key() {
        let (mut store, dir) = store("dropped-allow");
        let mut alerts = Alerts::default();
        let hour = reason(Signal::UnusualTime, Some("03"));

        // A new alert whose allowable reason is cut by the cap.
        let mut first = companies(MAX_REASONS);
        first.push(hour.clone());
        let saved = alerts
            .save("k", &app(), first, &mut store, at(1_000))
            .unwrap();
        let id = saved.id.unwrap();
        assert_eq!(alerts.windows["k"].alert.allow_key, None);
        assert!(!store.alert(id).unwrap().unwrap().can_allow);

        // An alert already full: an allowable reason joining it is dropped
        // and gives it no "this is fine".
        let later = vec![reason(Signal::UnusualTime, Some("04"))];
        let saved = alerts
            .save("k", &app(), later, &mut store, at(1_060))
            .unwrap();
        assert_eq!(saved.id, Some(id));
        assert_eq!(alerts.windows["k"].alert.allow_key, None);
        let stored = store.alert(id).unwrap().unwrap();
        assert!(!stored.can_allow, "the user never saw the reason");
        assert_eq!(stored.dropped_reasons, 2);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn restored_links_do_not_replace_newer_ones() {
        let mut alerts = Alerts::default();
        alerts.remind("k", ItemKind::Domain, "a.example");
        alerts.restore("k", ItemKind::Domain, "a.example", Link::Open(3), 2);
        assert_eq!(
            alerts.link("k", ItemKind::Domain, "a.example"),
            Some(Link::Closed)
        );
        alerts.restore("k", ItemKind::Domain, "b.example", Link::Open(4), 5);
        assert_eq!(
            alerts.link("k", ItemKind::Domain, "b.example"),
            Some(Link::Open(4))
        );
        assert_eq!(alerts.seen_again.get(&4), Some(&5));
    }
}
