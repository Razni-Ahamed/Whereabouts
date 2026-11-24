//! Whereabouts' detection: Layer 1 alerts (v0.2, N5; design spec §6.1 and
//! §6.4), shared by the service and the lab's replay tool (v0.3, L0).
//!
//! Checks what the engine sees against known lists and its own health
//! counters, and saves alerts in the encrypted store:
//!
//! - **Tracker contacts** (EasyPrivacy): *info*, one per app, tracker and
//!   day. Never notified on their own (the app sends a daily digest).
//! - **Networks on Spamhaus' DROP list**: *high*, one per app, address and
//!   day. DROP may not be redistributed, so it is used only if this computer
//!   downloaded it into `lists\` in Whereabouts' data folder.
//! - **Faked DNS events** and **unattributed traffic** (signs that something
//!   is hiding from Whereabouts): *medium*, at most one of each per hour.
//!
//! Only names confirmed by the Windows DNS service (or seen for the same
//! address in its answers) count, never what an app reports about itself.
//! "This is fine" (stored by the store as an allow key) stops alerts for the
//! same app and tracker, or the same app and listed range.

pub mod beacon;
pub mod browsers;
pub mod learner;
pub mod meter;
pub mod profile;
pub mod signals;

pub use profile::{LEARNING, Profile};

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use whereabouts_core::flow::FlowKey;
use whereabouts_enrich::{DropList, Enricher};
use whereabouts_store::{AlertKind, NewAlert, Severity, Store, known_app_key};

/// Most flows remembered as checked (cleared each day).
const MAX_CHECKED: usize = 50_000;

/// What the detector needs to know about one flow.
#[derive(Debug, Clone, Copy)]
pub struct FlowFacts<'a> {
    pub key: FlowKey,
    /// Executable file name.
    pub app: &'a str,
    /// The program's full path, if known.
    pub path: Option<&'a str>,
    /// The domain, only if confirmed by the Windows DNS service (or seen
    /// for the same address in its answers).
    pub domain: Option<&'a str>,
    /// The names the domain points to (confirmed CNAME aliases).
    pub aliases: &'a [Arc<str>],
}

/// A saved alert worth telling the user about now.
#[derive(Debug, Clone, PartialEq)]
pub struct Raised {
    pub id: i64,
    pub alert: NewAlert,
}

/// Windows' own core network programs, which contact certificate
/// authorities and Microsoft to check certificates and update Windows (for
/// example `lsass.exe` reaching `geotrust.com`): no tracker alerts for them.
/// Blocklisted networks are still reported.
const WINDOWS_CORE: [&str; 5] = [
    "lsass.exe",
    "svchost.exe",
    "services.exe",
    "wininit.exe",
    "winlogon.exe",
];

/// Whether `path` is one of [`WINDOWS_CORE`] in System32 itself (a program
/// elsewhere with the same name does not count).
fn is_windows_core(path: Option<&str>) -> bool {
    let Some(path) = path.map(Path::new) else {
        return false;
    };
    let system32 = std::env::var_os("SystemRoot")
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
        .join("System32");
    let in_system32 = path.parent().is_some_and(|parent| {
        parent
            .to_string_lossy()
            .eq_ignore_ascii_case(&system32.to_string_lossy())
    });
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase());
    in_system32 && name.is_some_and(|name| WINDOWS_CORE.contains(&name.as_str()))
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Finds alerts in what the engine sees.
#[derive(Debug, Default)]
pub struct Detector {
    drop: Option<DropList>,
    /// Flows already checked today (with or without a domain).
    checked: HashSet<(FlowKey, bool)>,
    day: u64,
    rejected: u64,
    unattributed: u64,
    /// Problems saving alerts, for the caller to report ([`Detector::take_errors`]).
    errors: Vec<String>,
}

impl Detector {
    /// Loads Spamhaus DROP from `lists_dir`, if this computer downloaded it.
    /// The second value is a warning to report when the list could not be
    /// read (the detector then works without it).
    pub fn load(lists_dir: &Path) -> (Self, Option<String>) {
        match DropList::load(lists_dir) {
            Ok(drop) => (
                Self {
                    drop,
                    ..Self::default()
                },
                None,
            ),
            Err(error) => (
                Self::default(),
                Some(format!("could not read the Spamhaus DROP list: {error}")),
            ),
        }
    }

    /// A detector using this DROP list (tests and the lab's replay tool).
    pub fn with_drop(drop: DropList) -> Self {
        Self {
            drop: Some(drop),
            ..Self::default()
        }
    }

    /// Checks one flow; returns an alert to notify about, if any. Each
    /// flow is checked once a day (again once its domain is known).
    pub fn check_flow(
        &mut self,
        flow: &FlowFacts<'_>,
        enricher: &Enricher,
        store: &mut Store,
        now: SystemTime,
    ) -> Option<Raised> {
        let day = unix_secs(now) / 86_400;
        if day != self.day || self.checked.len() >= MAX_CHECKED {
            self.day = day;
            self.checked.clear();
        }
        if !self.checked.insert((flow.key, flow.domain.is_some())) {
            return None;
        }
        let app_key = flow
            .path
            .map_or_else(|| flow.app.to_ascii_lowercase(), known_app_key);
        let ip = flow.key.remote.ip().to_canonical();

        if let Some(entry) = self.drop.as_ref().and_then(|drop| drop.lookup(ip)) {
            let alert = NewAlert {
                key: format!("bad_network|{app_key}|{ip}|{day}"),
                // Only a known program path can be trusted again: a file name
                // alone could be any program.
                allow_key: flow
                    .path
                    .map(|_| format!("bad_network|{app_key}|{}", entry.cidr)),
                kind: AlertKind::BadNetwork,
                severity: Severity::High,
                app_name: Some(flow.app.to_owned()),
                app_path: flow.path.map(str::to_owned),
                target: Some(ip.to_string()),
                reasons: Vec::new(),
                detail: Some(format!("{} ({})", entry.cidr, entry.sblid)),
            };
            if let Some(raised) = save(&mut self.errors, store, alert, now) {
                return Some(raised);
            }
        }

        if let Some(domain) = flow.domain.filter(|_| !is_windows_core(flow.path)) {
            // The domain itself, or a tracker hidden behind it (a CNAME
            // alias of a site's own name).
            let direct = enricher.domain(domain);
            let (info, hidden_behind) = if direct.tracker {
                (direct, None)
            } else {
                flow.aliases
                    .iter()
                    .map(|alias| enricher.domain(alias))
                    .find(|info| info.tracker)
                    .map_or((direct, None), |info| (info, Some(domain)))
            };
            if info.tracker {
                let tracker = info.registrable.unwrap_or_else(|| domain.to_owned());
                let who = info
                    .company
                    .map_or_else(|| tracker.clone(), |company| company.name);
                let alert = NewAlert {
                    key: format!("tracker|{app_key}|{tracker}|{day}"),
                    allow_key: flow.path.map(|_| format!("tracker|{app_key}|{tracker}")),
                    kind: AlertKind::Tracker,
                    severity: Severity::Info,
                    app_name: Some(flow.app.to_owned()),
                    app_path: flow.path.map(str::to_owned),
                    reasons: Vec::new(),
                    detail: Some(match hidden_behind {
                        Some(name) => format!("{who}, hidden behind {name}"),
                        None => who,
                    }),
                    target: Some(tracker),
                };
                // Info: saved for the Alerts screen and the daily digest only.
                let _ = save(&mut self.errors, store, alert, now);
            }
        }
        None
    }

    /// Checks the engine's evasion counters (they only grow while it runs).
    pub fn check_counters(
        &mut self,
        rejected: u64,
        unattributed: u64,
        store: &mut Store,
        now: SystemTime,
    ) -> Vec<Raised> {
        let hour = unix_secs(now) / 3600;
        let mut raised = Vec::new();
        if rejected > self.rejected {
            let new = rejected - self.rejected;
            self.rejected = rejected;
            let alert = NewAlert {
                key: format!("faked_dns|{hour}"),
                allow_key: None,
                kind: AlertKind::FakedDns,
                severity: Severity::Medium,
                app_name: None,
                app_path: None,
                target: None,
                reasons: Vec::new(),
                detail: Some(format!("{new} events")),
            };
            raised.extend(save(&mut self.errors, store, alert, now));
        }
        if unattributed > self.unattributed {
            let new = unattributed - self.unattributed;
            self.unattributed = unattributed;
            let alert = NewAlert {
                key: format!("unattributed|{hour}"),
                allow_key: None,
                kind: AlertKind::Unattributed,
                severity: Severity::Medium,
                app_name: None,
                app_path: None,
                target: None,
                reasons: Vec::new(),
                detail: Some(format!("{new} events")),
            };
            raised.extend(save(&mut self.errors, store, alert, now));
        }
        raised
    }

    /// Whether the DROP list is in use.
    pub fn has_drop(&self) -> bool {
        self.drop.is_some()
    }

    /// How many network ranges the DROP list holds, if it is in use.
    pub fn drop_ranges(&self) -> Option<usize> {
        self.drop.as_ref().map(DropList::len)
    }

    /// Problems saving alerts since the last call, for the caller to report.
    pub fn take_errors(&mut self) -> Vec<String> {
        std::mem::take(&mut self.errors)
    }
}

fn save(
    errors: &mut Vec<String>,
    store: &mut Store,
    alert: NewAlert,
    now: SystemTime,
) -> Option<Raised> {
    match store.add_alert(&alert, now) {
        Ok(Some(id)) => Some(Raised { id, alert }),
        Ok(None) => None,
        Err(error) => {
            errors.push(format!("could not save an alert: {error}"));
            None
        }
    }
}

/// The address of a flow, for tests.
#[cfg(test)]
fn key(remote: &str) -> FlowKey {
    FlowKey {
        pid: 7,
        protocol: whereabouts_core::model::Protocol::Tcp,
        remote: remote.parse().unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use whereabouts_enrich::{CompanyList, GeoDatabases, TrackerList};
    use whereabouts_store::Key;

    const T0: u64 = 1_800_000_000;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn store(name: &str) -> (Store, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("whereabouts-detect-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("t.db"), &Key::from_bytes([5; 32])).unwrap();
        (store, dir)
    }

    fn enricher() -> Enricher {
        Enricher::from_parts(
            TrackerList::parse("||ads.example^\n"),
            CompanyList::default(),
            GeoDatabases::default(),
        )
    }

    fn drop() -> DropList {
        DropList::parse(r#"{"cidr":"203.0.113.0/24","sblid":"SBL1"}"#, "")
    }

    fn flow<'a>(remote: &str, domain: Option<&'a str>) -> FlowFacts<'a> {
        FlowFacts {
            key: key(remote),
            app: "chat.exe",
            path: Some(r"C:\Apps\Chat.exe"),
            domain,
            aliases: &[],
        }
    }

    #[test]
    fn drop_networks_raise_a_high_alert_once_a_day() {
        let (mut store, dir) = store("drop");
        let mut detector = Detector::with_drop(drop());
        let raised = detector
            .check_flow(
                &flow("203.0.113.9:443", None),
                &enricher(),
                &mut store,
                at(T0),
            )
            .unwrap();
        assert_eq!(raised.alert.severity, Severity::High);
        assert_eq!(
            raised.alert.detail.as_deref(),
            Some("203.0.113.0/24 (SBL1)")
        );
        // The same flow, another flow to the same address: not again today.
        assert!(
            detector
                .check_flow(
                    &flow("203.0.113.9:443", None),
                    &enricher(),
                    &mut store,
                    at(T0 + 5)
                )
                .is_none()
        );
        assert!(
            detector
                .check_flow(
                    &flow("203.0.113.9:80", None),
                    &enricher(),
                    &mut store,
                    at(T0 + 6)
                )
                .is_none()
        );
        // Another address in the range is another alert; elsewhere, none.
        assert!(
            detector
                .check_flow(
                    &flow("203.0.113.10:443", None),
                    &enricher(),
                    &mut store,
                    at(T0 + 7)
                )
                .is_some()
        );
        assert!(
            detector
                .check_flow(
                    &flow("198.51.100.1:443", None),
                    &enricher(),
                    &mut store,
                    at(T0 + 8)
                )
                .is_none()
        );
        // "This is fine" for the range stops it for this app.
        assert!(store.dismiss_alert(raised.id, true, at(T0 + 9)).unwrap());
        assert!(
            detector
                .check_flow(
                    &flow("203.0.113.11:443", None),
                    &enricher(),
                    &mut store,
                    at(T0 + 10)
                )
                .is_none()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn without_a_program_path_alerts_cannot_be_allowed() {
        let (mut store, dir) = store("nopath");
        let mut detector = Detector::with_drop(drop());
        let mut facts = flow("203.0.113.9:443", None);
        facts.path = None;
        let raised = detector
            .check_flow(&facts, &enricher(), &mut store, at(T0))
            .unwrap();
        assert_eq!(raised.alert.allow_key, None);
        assert!(!store.alerts(at(0), 10).unwrap()[0].can_allow);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn windows_certificate_checks_are_not_tracker_alerts() {
        let (mut store, dir) = store("core");
        let mut detector = Detector::default();
        let lsass = PathBuf::from(std::env::var("SystemRoot").unwrap())
            .join(r"System32\lsass.exe")
            .to_string_lossy()
            .into_owned();
        let core = FlowFacts {
            key: key("198.51.100.1:443"),
            app: "lsass.exe",
            path: Some(&lsass),
            domain: Some("cdn.ads.example"),
            aliases: &[],
        };
        detector.check_flow(&core, &enricher(), &mut store, at(T0));
        assert!(store.alerts(at(0), 10).unwrap().is_empty());
        // The same name anywhere else is just a program.
        let impostor = FlowFacts {
            key: key("198.51.100.2:443"),
            path: Some(r"C:\Users\x\lsass.exe"),
            ..core
        };
        detector.check_flow(&impostor, &enricher(), &mut store, at(T0));
        assert_eq!(store.alerts(at(0), 10).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tracker_contacts_are_saved_but_not_notified() {
        let (mut store, dir) = store("tracker");
        let mut detector = Detector::default();
        assert!(!detector.has_drop());
        let none = detector.check_flow(
            &flow("198.51.100.1:443", Some("cdn.ads.example")),
            &enricher(),
            &mut store,
            at(T0),
        );
        assert!(none.is_none());
        let saved = store.alerts(at(0), 10).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].kind, AlertKind::Tracker);
        assert_eq!(saved[0].target.as_deref(), Some("ads.example"));
        // Unknown domains and flows without a confirmed domain: nothing.
        detector.check_flow(
            &flow("198.51.100.2:443", Some("example.org")),
            &enricher(),
            &mut store,
            at(T0),
        );
        detector.check_flow(
            &flow("198.51.100.3:443", None),
            &enricher(),
            &mut store,
            at(T0),
        );
        assert_eq!(store.alerts(at(0), 10).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn trackers_hidden_behind_a_sites_own_name_are_found() {
        let (mut store, dir) = store("cloaked");
        let mut detector = Detector::default();
        let aliases: Vec<Arc<str>> = vec![Arc::from("eu.ads.example")];
        let mut facts = flow("198.51.100.9:443", Some("metrics.shop.example"));
        facts.aliases = &aliases;
        detector.check_flow(&facts, &enricher(), &mut store, at(T0));
        let saved = store.alerts(at(0), 10).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].target.as_deref(), Some("ads.example"));
        assert_eq!(
            saved[0].detail.as_deref(),
            Some("ads.example, hidden behind metrics.shop.example")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn evasion_counters_raise_at_most_one_alert_an_hour() {
        let (mut store, dir) = store("evasion");
        let mut detector = Detector::default();
        assert!(detector.check_counters(0, 0, &mut store, at(T0)).is_empty());
        let raised = detector.check_counters(3, 0, &mut store, at(T0 + 1));
        assert_eq!(raised.len(), 1);
        assert_eq!(raised[0].alert.kind, AlertKind::FakedDns);
        assert_eq!(raised[0].alert.detail.as_deref(), Some("3 events"));
        assert!(
            detector
                .check_counters(5, 0, &mut store, at(T0 + 60))
                .is_empty(),
            "same hour"
        );
        assert_eq!(
            detector.check_counters(5, 2, &mut store, at(T0 + 61)).len(),
            1
        );
        assert_eq!(
            detector
                .check_counters(6, 2, &mut store, at(T0 + 3700))
                .len(),
            1
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_reports_unreadable_drop_as_warning() {
        let dir =
            std::env::temp_dir().join(format!("whereabouts-detect-badlist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A folder where the list file should be cannot be read as a file.
        std::fs::create_dir_all(dir.join("drop_v4.json")).unwrap();
        let (detector, warning) = Detector::load(&dir);
        assert!(!detector.has_drop());
        assert!(warning.is_some_and(|w| w.contains("Spamhaus DROP")));
        let (detector, warning) = Detector::load(&dir.join("missing"));
        assert!(!detector.has_drop());
        assert_eq!(warning, None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
