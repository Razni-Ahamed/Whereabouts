//! The Learner turns traffic into profiles and explained behaviour alerts.

use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use whereabouts_detect::learner::{AppFacts, BINARY_CHANGE_WINDOW, Finished, Learner};
use whereabouts_detect::meter::Delta;
use whereabouts_detect::signals::Toggles;
use whereabouts_enrich::{CompanyList, Enricher, GeoDatabases, TrackerList};
use whereabouts_store::{
    AlertKind, GoesAnywhere, HourRow, ItemKind, ItemState, Key, MAX_ITEMS_PER_KIND, MAX_REASONS,
    NewAlert, ProfileItem, ProfileRow, Reason, Severity, Signal, Store, StoredAlert, known_app_key,
};

/// 2027-01-15 08:00 UTC, on the hour.
const T0: u64 = 1_800_000_000;
const HOUR: u64 = 3_600;
const DAY: u64 = 86_400;
const MB: u64 = 1_000_000;
const PATH: &str = r"C:\Apps\Chat.exe";

/// A temporary encrypted store, deleted (after closing it) when dropped.
struct TestStore {
    store: Option<Store>,
    dir: PathBuf,
}

impl TestStore {
    fn open(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("whereabouts-learner-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("t.db"), &Key::from_bytes([9; 32])).unwrap();
        Self {
            store: Some(store),
            dir,
        }
    }
}

impl Deref for TestStore {
    type Target = Store;
    fn deref(&self) -> &Store {
        self.store.as_ref().unwrap()
    }
}

impl DerefMut for TestStore {
    fn deref_mut(&mut self) -> &mut Store {
        self.store.as_mut().unwrap()
    }
}

impl Drop for TestStore {
    fn drop(&mut self) {
        drop(self.store.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn key() -> String {
    known_app_key(PATH)
}

fn enricher() -> Enricher {
    Enricher::from_parts(
        TrackerList::parse(""),
        CompanyList::default(),
        GeoDatabases::default(),
    )
}

fn app() -> AppFacts<'static> {
    AppFacts {
        app_name: "Chat.exe",
        path: PATH,
        sha256: Some("aaaa"),
        publisher: Some("Chat Inc"),
        signature_valid: true,
        installed_by_admins: true,
    }
}

/// A finished flow to `domain` (owned by `company`, in `country`) on port 443.
fn flow<'a>(
    domain: Option<&'a str>,
    company: Option<&'a str>,
    country: Option<&'a str>,
    secs: u64,
) -> Finished<'a> {
    Finished {
        app: app(),
        domain,
        company,
        country,
        port: 443,
        first_seen: at(secs.saturating_sub(30)),
        last_seen: at(secs),
    }
}

/// A random-looking domain: unknown to the profile, so it raises a medium
/// signal (random name), unlike a new company or country, which are info.
const RANDOM_DOMAIN: &str = "q7x9k2m4zt8w.example";

/// A flow to [`RANDOM_DOMAIN`], otherwise to the usual places.
fn random_flow(secs: u64) -> Finished<'static> {
    flow(Some(RANDOM_DOMAIN), Some("Chat Inc"), Some("DE"), secs)
}

/// The usual destinations of the seeded app.
fn usual(secs: u64) -> Finished<'static> {
    flow(Some("chat.example"), Some("Chat Inc"), Some("DE"), secs)
}

fn item(kind: ItemKind, value: &str) -> ProfileItem {
    ProfileItem {
        kind,
        value: value.to_owned(),
        first_seen: at(T0 - 8 * DAY),
        last_seen: at(T0 - DAY),
        seen_on_day: 8,
        state: ItemState::Learned,
    }
}

/// Saves a profile that finished learning (first data 8 days before
/// `T0`), knowing chat.example, Chat Inc, DE and port 443, with `hours`.
fn seed(store: &mut Store, goes_anywhere: GoesAnywhere, hours: &[HourRow]) {
    let row = ProfileRow {
        key: key(),
        path: PATH.to_owned(),
        app_name: "Chat.exe".to_owned(),
        first_data: at(T0 - 8 * DAY),
        learned_since: at(T0 - 8 * DAY),
        last_data: at(T0 - DAY),
        active_days: 8,
        last_active_day: Some(((T0 - DAY) / DAY) as i64),
        last_sha256: Some("aaaa".to_owned()),
        last_publisher: Some("Chat Inc".to_owned()),
        goes_anywhere,
        reset_at: None,
    };
    store.save_profile_row(&row).unwrap();
    store
        .save_items(
            &key(),
            &[
                item(ItemKind::Domain, "chat.example"),
                item(ItemKind::Company, "Chat Inc"),
                item(ItemKind::Country, "DE"),
                item(ItemKind::Port, "443"),
            ],
        )
        .unwrap();
    store.add_hours(&key(), hours).unwrap();
}

/// `count` hours of `sent` bytes each, the last ending where `T0`'s hour begins.
fn history(count: u64, sent: u64) -> Vec<HourRow> {
    let last = (T0 / HOUR) as i64 - 1;
    (0..count as i64)
        .map(|i| HourRow {
            hour: last - i,
            bytes_sent: sent,
            bytes_received: 0,
            connections: 1,
        })
        .collect()
}

fn behaviour(store: &Store) -> Vec<StoredAlert> {
    store
        .alerts(UNIX_EPOCH, 100)
        .unwrap()
        .into_iter()
        .filter(|a| a.kind == AlertKind::Behaviour)
        .collect()
}

fn state(store: &Store, kind: ItemKind, value: &str) -> Option<ItemState> {
    store
        .profile(&key())
        .unwrap()
        .unwrap()
        .items
        .into_iter()
        .find(|i| i.kind == kind && i.value == value)
        .map(|i| i.state)
}

fn delta(secs: u64, destination: &str, sent: u64, connections: u32) -> Delta {
    Delta {
        app_key: key(),
        destination: Some(destination.to_owned()),
        hour: (secs / HOUR) as i64,
        sent,
        received: 0,
        new_connections: connections,
    }
}

#[test]
fn nothing_raised_while_learning() {
    let mut db = TestStore::open("learning");
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    assert!(learner.finished(&usual(T0), &e, &mut db, at(T0)).is_empty());
    let day2 = flow(
        Some("other.example"),
        Some("Other Co"),
        Some("FR"),
        T0 + DAY,
    );
    assert!(
        learner
            .finished(&day2, &e, &mut db, at(T0 + DAY))
            .is_empty()
    );
    assert!(learner.take_errors().is_empty());
    assert!(behaviour(&db).is_empty());

    let profile = db.profile(&key()).unwrap().unwrap();
    assert_eq!(profile.row.first_data, at(T0));
    assert_eq!(profile.row.learned_since, at(T0));
    assert_eq!(profile.row.active_days, 2);
    assert_eq!(profile.row.last_sha256.as_deref(), Some("aaaa"));
    assert_eq!(
        state(&db, ItemKind::Country, "FR"),
        Some(ItemState::Learned)
    );
    assert_eq!(
        state(&db, ItemKind::Company, "Other Co"),
        Some(ItemState::Learned)
    );
    assert_eq!(state(&db, ItemKind::Port, "443"), Some(ItemState::Learned));
}

#[test]
fn new_country_is_listed_not_notified_and_learned() {
    let mut db = TestStore::open("country-info");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let raised = learner.finished(&russia(T0), &enricher(), &mut db, at(T0));
    assert!(learner.take_errors().is_empty());
    assert!(raised.is_empty(), "info is listed, never notified");

    let saved = behaviour(&db);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].severity, Severity::Info);
    assert_eq!(signals_of_stored(&saved[0]), [Signal::NewCountry]);
    assert_eq!(
        state(&db, ItemKind::Country, "RU"),
        Some(ItemState::Learned)
    );
}

#[test]
fn new_company_is_listed_not_notified_and_learned() {
    let mut db = TestStore::open("company-info");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let company = flow(Some("chat.example"), Some("Evil Corp"), Some("DE"), T0);
    assert!(
        learner
            .finished(&company, &enricher(), &mut db, at(T0))
            .is_empty()
    );
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].severity, Severity::Info);
    assert_eq!(signals_of_stored(&saved[0]), [Signal::NewCompany]);
    assert_eq!(
        state(&db, ItemKind::Company, "Evil Corp"),
        Some(ItemState::Learned)
    );
}

#[test]
fn random_name_after_learning_is_pending() {
    let mut db = TestStore::open("pending");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let raised = learner.finished(&random_flow(T0), &enricher(), &mut db, at(T0));
    assert!(learner.take_errors().is_empty());

    assert_eq!(raised.len(), 1);
    let alert = &raised[0].alert;
    assert_eq!(alert.kind, AlertKind::Behaviour);
    assert_eq!(alert.severity, Severity::Medium);
    assert_eq!(alert.key, format!("behaviour|{}|{T0}", key()));
    let allow = format!("behaviour|{}|random_name|{RANDOM_DOMAIN}", key());
    assert_eq!(alert.allow_key.as_deref(), Some(allow.as_str()));
    assert_eq!(alert.target.as_deref(), Some(RANDOM_DOMAIN));
    assert_eq!(alert.detail, None);
    assert_eq!(alert.app_path.as_deref(), Some(PATH));

    let saved = behaviour(&db);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].id, raised[0].id);
    assert!(saved[0].can_allow, "\"This is fine\" is offered");
    assert_eq!(saved[0].severity, Severity::Medium);
    assert_eq!(
        signals_of_stored(&saved[0]),
        [Signal::NewSite, Signal::RandomName]
    );
    assert_eq!(saved[0].reasons[1].value.as_deref(), Some(RANDOM_DOMAIN));
    assert_eq!(
        state(&db, ItemKind::Domain, RANDOM_DOMAIN),
        Some(ItemState::Pending)
    );
    assert_eq!(
        state(&db, ItemKind::Country, "DE"),
        Some(ItemState::Learned)
    );
}

#[test]
fn info_alert_raised_to_medium_notifies_and_gains_its_allow_key() {
    let mut db = TestStore::open("info-to-medium");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    // A plain new site: listed only, and nothing in it can be allowed.
    let plain = flow(Some("chat2.example"), Some("Chat Inc"), Some("DE"), T0);
    assert!(learner.finished(&plain, &e, &mut db, at(T0)).is_empty());
    let first = newest(&db);
    assert_eq!(first.severity, Severity::Info);
    assert!(!first.can_allow);

    // Two minutes later a random-looking name joins it: now medium, notified.
    let raised = learner.finished(&random_flow(T0 + 120), &e, &mut db, at(T0 + 120));
    assert_eq!(raised.len(), 1, "a severity raise is notified");
    assert_eq!(raised[0].id, first.id);
    assert_eq!(raised[0].alert.severity, Severity::Medium);
    let allow = format!("behaviour|{}|random_name|{RANDOM_DOMAIN}", key());
    assert_eq!(raised[0].alert.allow_key.as_deref(), Some(allow.as_str()));
    let saved = newest(&db);
    assert_eq!(saved.id, first.id);
    assert!(saved.can_allow);

    // "This is fine" now sticks.
    assert!(db.dismiss_alert(saved.id, true, at(T0 + 180)).unwrap());
    assert!(db.is_allowed(&allow).unwrap());
    assert!(learner.take_errors().is_empty());
}

#[test]
fn pending_seen_again_updates_alert() {
    let mut db = TestStore::open("seen-again");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    assert_eq!(
        learner
            .finished(&random_flow(T0), &e, &mut db, at(T0))
            .len(),
        1
    );
    for i in 1..=3 {
        let secs = T0 + i * HOUR;
        assert!(
            learner
                .finished(&random_flow(secs), &e, &mut db, at(secs))
                .is_empty()
        );
    }
    assert!(learner.take_errors().is_empty());
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].seen_again, 3);
    assert_eq!(saved[0].severity, Severity::Medium);
    assert_eq!(
        state(&db, ItemKind::Domain, RANDOM_DOMAIN),
        Some(ItemState::Pending)
    );
}

#[test]
fn signals_in_ten_minutes_combine() {
    let mut db = TestStore::open("combine");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    let first = learner.finished(&random_flow(T0), &e, &mut db, at(T0));
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].alert.severity, Severity::Medium);

    // Five minutes later, another random name: two mediums make it high.
    let other = flow(
        Some("m3v8r1y6pd5c.example"),
        Some("Chat Inc"),
        Some("DE"),
        T0 + 300,
    );
    let second = learner.finished(&other, &e, &mut db, at(T0 + 300));
    assert_eq!(second.len(), 1, "a severity raise is notified");
    assert_eq!(second[0].id, first[0].id);
    assert_eq!(second[0].alert.severity, Severity::High);
    assert_eq!(second[0].alert.reasons.len(), 4);

    let saved = behaviour(&db);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].severity, Severity::High);
    let signals: Vec<Signal> = saved[0].reasons.iter().map(|r| r.signal).collect();
    assert_eq!(
        signals,
        [
            Signal::NewSite,
            Signal::RandomName,
            Signal::NewSite,
            Signal::RandomName
        ]
    );

    // After the window closes, a new signal is a new alert.
    let later = flow(
        Some("h2n7b4w9tj6s.example"),
        Some("Chat Inc"),
        Some("DE"),
        T0 + 700,
    );
    assert_eq!(learner.finished(&later, &e, &mut db, at(T0 + 700)).len(), 1);
    assert_eq!(behaviour(&db).len(), 2);
    assert!(learner.take_errors().is_empty());
}

#[test]
fn thousands_of_new_companies_in_one_window_keep_the_alert_small() {
    let mut db = TestStore::open("many-companies");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    const COMPANIES: u64 = 1_500;
    for i in 0..COMPANIES {
        // All within one combine window.
        let secs = T0 + i * 300 / COMPANIES;
        let company = format!("Company {i}");
        let new = flow(Some("chat.example"), Some(&company), Some("DE"), secs);
        learner.finished(&new, &e, &mut db, at(secs));
    }
    assert!(learner.take_errors().is_empty());
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 1, "one window, one alert");
    assert_eq!(saved[0].reasons.len(), MAX_REASONS);
    assert_eq!(
        u64::from(saved[0].dropped_reasons),
        COMPANIES - MAX_REASONS as u64
    );
    // The earliest are kept.
    assert_eq!(saved[0].reasons[0].value.as_deref(), Some("Company 0"));

    // A medium signal still joins (and the alert in memory is as small).
    let raised = learner.finished(&random_flow(T0 + 400), &e, &mut db, at(T0 + 400));
    assert_eq!(raised.len(), 1);
    assert_eq!(raised[0].alert.severity, Severity::Medium);
    assert_eq!(raised[0].alert.reasons.len(), MAX_REASONS);
    assert!(signals_of(&raised[0].alert).contains(&Signal::RandomName));
    let saved = newest(&db);
    assert!(signals_of_stored(&saved).contains(&Signal::RandomName));
    assert_eq!(saved.reasons.len(), MAX_REASONS);
    assert!(learner.take_errors().is_empty());
}

#[test]
fn cache_and_store_drop_the_same_items_beyond_the_limit() {
    let mut db = TestStore::open("item-limit");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    // The profile is full of sites, the oldest first.
    let sites: Vec<ProfileItem> = (0..MAX_ITEMS_PER_KIND as u64 - 1)
        .map(|n| ProfileItem {
            last_seen: at(T0 - 2 * DAY + n),
            ..item(ItemKind::Domain, &format!("d{n}.example"))
        })
        .collect();
    db.save_items(&key(), &sites).unwrap();
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    assert!(learner.finished(&usual(T0), &e, &mut db, at(T0)).is_empty());

    // One more site: the oldest goes, in the store and in the Learner.
    let new = flow(Some("new.example"), Some("Chat Inc"), Some("DE"), T0 + 60);
    learner.finished(&new, &e, &mut db, at(T0 + 60));
    assert_eq!(state(&db, ItemKind::Domain, "d0.example"), None);
    assert_eq!(
        state(&db, ItemKind::Domain, "d1.example"),
        Some(ItemState::Learned)
    );
    let old = flow(Some("d0.example"), Some("Chat Inc"), Some("DE"), T0 + 120);
    learner.finished(&old, &e, &mut db, at(T0 + 120));
    let reasons = newest(&db).reasons;
    assert!(
        reasons
            .iter()
            .any(|r| r.signal == Signal::NewSite && r.value.as_deref() == Some("d0.example")),
        "a dropped site is new again: {reasons:?}"
    );
    assert!(learner.take_errors().is_empty());
}

#[test]
fn upload_spike_raised_while_upload_runs() {
    let mut db = TestStore::open("upload");
    seed(&mut db, GoesAnywhere::Auto, &history(24, MB));
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    let mut raised = Vec::new();
    for i in 0..10 {
        let secs = T0 + i * 60;
        let deltas = [delta(secs, "upload.example", 50 * MB, 0)];
        raised.extend(learner.traffic(&app(), &deltas, &e, &mut db, at(secs)));
    }
    assert!(learner.take_errors().is_empty());
    assert_eq!(raised.len(), 1, "raised once, on the first big tick");
    assert_eq!(raised[0].alert.severity, Severity::High);
    assert_eq!(raised[0].alert.reasons[0].signal, Signal::UploadSpike);
    assert_eq!(raised[0].alert.reasons[0].observed, Some(5e7));
    assert_eq!(behaviour(&db).len(), 1);
    // Nothing was flushed yet: the running hour is not in the store.
    let hours = db.profile(&key()).unwrap().unwrap().hours;
    assert!(hours.iter().all(|h| h.hour < (T0 / HOUR) as i64));
}

#[test]
fn flush_then_restart_adds_to_same_hour() {
    let mut db = TestStore::open("flush");
    let e = enricher();
    let hour = (T0 / HOUR) as i64;
    let mut learner = Learner::new(Toggles::default(), 0);
    let deltas = [delta(T0 + 60, "chat.example", 5 * MB, 1)];
    assert!(
        learner
            .traffic(&app(), &deltas, &e, &mut db, at(T0 + 60))
            .is_empty()
    );
    // Shutting down: the service flushes an hour ahead to write the open hour.
    learner.flush(&mut db, at(T0 + 60 + HOUR)).unwrap();
    assert!(learner.take_errors().is_empty());
    let stored = db.profile(&key()).unwrap().unwrap();
    assert_eq!(stored.row.first_data, at(T0 + 60));
    assert_eq!(stored.hours.len(), 1);
    assert_eq!(stored.hours[0].bytes_sent, 5 * MB);

    let mut restarted = Learner::new(Toggles::default(), 0);
    let deltas = [delta(T0 + 120, "chat.example", 5 * MB, 1)];
    restarted.traffic(&app(), &deltas, &e, &mut db, at(T0 + 120));
    // Still inside the hour: nothing is written yet.
    restarted.flush(&mut db, at(T0 + 180)).unwrap();
    assert_eq!(
        db.profile(&key()).unwrap().unwrap().hours[0].bytes_sent,
        5 * MB
    );
    restarted.flush(&mut db, at(T0 + HOUR)).unwrap();
    assert!(restarted.take_errors().is_empty());
    let hours = db.profile(&key()).unwrap().unwrap().hours;
    assert_eq!(hours.len(), 1);
    assert_eq!(hours[0].hour, hour);
    assert_eq!(hours[0].bytes_sent, 10 * MB);
    assert_eq!(hours[0].connections, 2);
}

#[test]
fn dropped_profiles_are_read_again_and_held_traffic_is_kept() {
    let mut db = TestStore::open("drop");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let e = enricher();
    let mut learner = Learner::new(Toggles::default(), 0);
    assert!(learner.finished(&usual(T0), &e, &mut db, at(T0)).is_empty());
    let deltas = [delta(T0 + 60, "chat.example", 5 * MB, 1)];
    learner.traffic(&app(), &deltas, &e, &mut db, at(T0 + 60));

    // The stored profile changes behind the Learner's back (as when the
    // store ages items out); without dropping its copy, it would still
    // raise "new site" here.
    assert!(db.set_goes_anywhere(&key(), GoesAnywhere::UserOn).unwrap());
    learner.drop_profiles();
    let new = flow(
        Some("other.example"),
        Some("Other Co"),
        Some("RU"),
        T0 + 120,
    );
    assert!(
        learner.finished(&new, &e, &mut db, at(T0 + 120)).is_empty(),
        "read again from the store"
    );

    // The traffic held before is still written.
    learner.flush(&mut db, at(T0 + HOUR + 60)).unwrap();
    assert!(learner.take_errors().is_empty());
    let hours = db.profile(&key()).unwrap().unwrap().hours;
    assert_eq!(hours.iter().map(|h| h.bytes_sent).sum::<u64>(), 5 * MB);
}

#[test]
fn goes_anywhere_app_gets_no_destination_alerts() {
    let mut db = TestStore::open("anywhere");
    seed(&mut db, GoesAnywhere::UserOn, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let new = flow(Some("other.example"), Some("Other Co"), Some("RU"), T0);
    assert!(
        learner
            .finished(&new, &enricher(), &mut db, at(T0))
            .is_empty()
    );
    assert!(learner.take_errors().is_empty());
    assert!(behaviour(&db).is_empty());
    assert_eq!(
        state(&db, ItemKind::Country, "RU"),
        Some(ItemState::Learned)
    );
    assert_eq!(
        state(&db, ItemKind::Company, "Other Co"),
        Some(ItemState::Learned)
    );
    assert_eq!(
        state(&db, ItemKind::Domain, "other.example"),
        Some(ItemState::Learned)
    );
}

#[test]
fn allowed_beacon_not_raised_again() {
    let mut db = TestStore::open("beacon");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::all_on(), 0);
    let e = enricher();
    let beacon = |learner: &mut Learner, db: &mut TestStore, start: u64| {
        let mut raised = Vec::new();
        for i in 0..8 {
            let secs = start + i * 60;
            let deltas = [delta(secs, "c2.example", 500, 1)];
            raised.extend(learner.traffic(&app(), &deltas, &e, db, at(secs)));
        }
        raised
    };

    let raised = beacon(&mut learner, &mut db, T0);
    assert_eq!(raised.len(), 1);
    let alert = &raised[0].alert;
    assert_eq!(alert.severity, Severity::Medium);
    assert_eq!(alert.reasons[0].signal, Signal::Beaconing);
    assert_eq!(alert.target.as_deref(), Some("c2.example"));
    let allow = format!("behaviour|{}|beaconing|c2.example", key());
    assert_eq!(alert.allow_key.as_deref(), Some(allow.as_str()));

    // "This is fine" saves the allow key.
    assert!(db.dismiss_alert(raised[0].id, true, at(T0 + 600)).unwrap());
    assert!(db.is_allowed(&allow).unwrap());

    // The next day: a new company (listed, not notified) opens a window, and
    // the beacon, though inside that window, is not added to it.
    let day2 = T0 + DAY;
    let company = flow(Some("chat.example"), Some("Evil Corp"), Some("DE"), day2);
    assert!(learner.finished(&company, &e, &mut db, at(day2)).is_empty());
    assert!(beacon(&mut learner, &mut db, day2 + 10).is_empty());
    assert!(learner.take_errors().is_empty());
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 2);
    let newest = saved.iter().find(|a| a.id != raised[0].id).unwrap();
    let signals: Vec<Signal> = newest.reasons.iter().map(|r| r.signal).collect();
    assert_eq!(signals, [Signal::NewCompany]);
}

#[test]
fn reset_profile_learns_again() {
    let mut db = TestStore::open("reset");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    // The learner caches the finished profile.
    assert!(learner.finished(&usual(T0), &e, &mut db, at(T0)).is_empty());

    assert!(learner.reset(&mut db, &key(), at(T0 + 60)).unwrap());

    let ru = flow(Some("chat.example"), Some("Chat Inc"), Some("RU"), T0 + 120);
    assert!(learner.finished(&ru, &e, &mut db, at(T0 + 120)).is_empty());
    let day6 = T0 + 6 * DAY;
    let company = flow(Some("chat.example"), Some("Evil Corp"), Some("RU"), day6);
    assert!(learner.finished(&company, &e, &mut db, at(day6)).is_empty());
    assert!(behaviour(&db).is_empty());
    assert_eq!(
        state(&db, ItemKind::Country, "RU"),
        Some(ItemState::Learned)
    );

    // Once the new learning period is over, something new alerts again.
    let day8 = T0 + 8 * DAY;
    assert_eq!(
        learner
            .finished(&random_flow(day8), &e, &mut db, at(day8))
            .len(),
        1
    );
    assert!(learner.take_errors().is_empty());
}

/// The app after its file was swapped for an unsigned one.
fn unsigned() -> AppFacts<'static> {
    AppFacts {
        sha256: Some("bbbb"),
        publisher: None,
        signature_valid: false,
        ..app()
    }
}

fn russia(secs: u64) -> Finished<'static> {
    flow(Some("chat.example"), Some("Chat Inc"), Some("RU"), secs)
}

fn signals_of(alert: &whereabouts_store::NewAlert) -> Vec<Signal> {
    alert.reasons.iter().map(|r| r.signal).collect()
}

fn signals_of_stored(alert: &StoredAlert) -> Vec<Signal> {
    alert.reasons.iter().map(|r| r.signal).collect()
}

/// The most recently saved behaviour alert.
fn newest(store: &Store) -> StoredAlert {
    behaviour(store).into_iter().max_by_key(|a| a.id).unwrap()
}

#[test]
fn swapped_program_is_caught_on_its_first_new_destination() {
    let mut db = TestStore::open("swap");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    // A flow to a known place: nothing, but the file stays suspect.
    let known = Finished {
        app: unsigned(),
        ..usual(T0)
    };
    assert!(learner.finished(&known, &e, &mut db, at(T0)).is_empty());
    let row = db.profile(&key()).unwrap().unwrap().row;
    assert_eq!(row.last_sha256.as_deref(), Some("bbbb"));

    let ru = Finished {
        app: unsigned(),
        ..russia(T0 + HOUR)
    };
    let raised = learner.finished(&ru, &e, &mut db, at(T0 + HOUR));
    assert_eq!(raised.len(), 1);
    assert_eq!(raised[0].alert.severity, Severity::High);
    assert_eq!(
        signals_of(&raised[0].alert),
        [Signal::NewCountry, Signal::BinaryChanged]
    );

    // It fired once: the next new destination is only that.
    let day2 = T0 + DAY;
    let company = Finished {
        app: unsigned(),
        ..flow(Some("chat.example"), Some("Evil Corp"), Some("DE"), day2)
    };
    assert!(learner.finished(&company, &e, &mut db, at(day2)).is_empty());
    assert_eq!(signals_of_stored(&newest(&db)), [Signal::NewCompany]);

    // A swap older than the window is no longer suspect.
    let other = AppFacts {
        sha256: Some("cccc"),
        publisher: Some("Evil Ltd"),
        signature_valid: true,
        ..app()
    };
    let day3 = T0 + 3 * DAY;
    let known = Finished {
        app: other,
        ..usual(day3)
    };
    assert!(learner.finished(&known, &e, &mut db, at(day3)).is_empty());
    let later = day3 + BINARY_CHANGE_WINDOW;
    let cn = Finished {
        app: other,
        ..flow(Some("chat.example"), Some("Chat Inc"), Some("CN"), later)
    };
    assert!(learner.finished(&cn, &e, &mut db, at(later)).is_empty());
    assert_eq!(signals_of_stored(&newest(&db)), [Signal::NewCountry]);
    assert!(learner.take_errors().is_empty());
}

#[test]
fn dismissed_pending_value_raises_a_new_alert() {
    let mut db = TestStore::open("dismiss");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    let id = learner.finished(&random_flow(T0), &e, &mut db, at(T0))[0].id;
    assert!(db.dismiss_alert(id, false, at(T0 + 60)).unwrap());
    learner
        .alert_closed(&mut db, id, false, at(T0 + 60))
        .unwrap();

    // Remind me: the next sighting, even the same day, is a new alert.
    let again = learner.finished(&random_flow(T0 + 120), &e, &mut db, at(T0 + 120));
    assert_eq!(again.len(), 1);
    assert_ne!(again[0].id, id);
    assert_eq!(
        signals_of(&again[0].alert),
        [Signal::NewSite, Signal::RandomName]
    );
    assert_eq!(
        state(&db, ItemKind::Domain, RANDOM_DOMAIN),
        Some(ItemState::Pending)
    );

    // Later sightings count on the new alert.
    let secs = T0 + 2 * HOUR;
    assert!(
        learner
            .finished(&random_flow(secs), &e, &mut db, at(secs))
            .is_empty()
    );
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 2);
    let newest = saved.iter().find(|a| a.id == again[0].id).unwrap();
    assert_eq!(newest.seen_again, 1);
    assert!(learner.take_errors().is_empty());
}

#[test]
fn allowed_pending_value_is_known_in_store_and_cache() {
    let mut db = TestStore::open("allow");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    let id = learner.finished(&random_flow(T0), &e, &mut db, at(T0))[0].id;
    assert!(db.dismiss_alert(id, true, at(T0 + 60)).unwrap());
    learner
        .alert_closed(&mut db, id, true, at(T0 + 60))
        .unwrap();
    assert_eq!(
        state(&db, ItemKind::Domain, RANDOM_DOMAIN),
        Some(ItemState::Allowed)
    );

    let secs = T0 + HOUR;
    assert!(
        learner
            .finished(&random_flow(secs), &e, &mut db, at(secs))
            .is_empty()
    );
    // The cache knows the domain is allowed: a swapped program reaching it
    // is not new behaviour (a stale "pending" would count as new and fire).
    let secs = T0 + 2 * HOUR;
    let swapped = Finished {
        app: unsigned(),
        ..random_flow(secs)
    };
    assert!(learner.finished(&swapped, &e, &mut db, at(secs)).is_empty());
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].seen_again, 0);
    assert_eq!(
        state(&db, ItemKind::Domain, RANDOM_DOMAIN),
        Some(ItemState::Allowed)
    );
    assert!(learner.take_errors().is_empty());
}

#[test]
fn this_is_fine_after_a_restart_uses_the_saved_reasons() {
    let mut db = TestStore::open("allow-restart");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let e = enricher();
    let id = {
        let mut before = Learner::new(Toggles::default(), 0);
        before.finished(&random_flow(T0), &e, &mut db, at(T0))[0].id
    };
    // The service restarted: this Learner never saw the alert. As the
    // service does, the Learner first, then the alert is marked seen.
    let mut learner = Learner::new(Toggles::default(), 0);
    learner
        .alert_closed(&mut db, id, true, at(T0 + 60))
        .unwrap();
    assert!(db.dismiss_alert(id, true, at(T0 + 60)).unwrap());
    assert_eq!(
        state(&db, ItemKind::Domain, RANDOM_DOMAIN),
        Some(ItemState::Allowed)
    );
    // Only pending items it named change.
    assert_eq!(
        state(&db, ItemKind::Country, "DE"),
        Some(ItemState::Learned)
    );
    // The cache agrees: the domain is known, so a swapped program going
    // there is not new behaviour.
    let secs = T0 + HOUR;
    let swapped = Finished {
        app: unsigned(),
        ..random_flow(secs)
    };
    assert!(learner.finished(&swapped, &e, &mut db, at(secs)).is_empty());
    assert!(learner.take_errors().is_empty());
}

#[test]
fn dismissing_after_a_restart_still_reminds() {
    let mut db = TestStore::open("dismiss-restart");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let e = enricher();
    let id =
        Learner::new(Toggles::default(), 0).finished(&random_flow(T0), &e, &mut db, at(T0))[0].id;
    // The service restarted: this Learner never saw the alert.
    let mut learner = Learner::new(Toggles::default(), 0);
    learner
        .alert_closed(&mut db, id, false, at(T0 + 60))
        .unwrap();
    assert!(db.dismiss_alert(id, false, at(T0 + 60)).unwrap());
    let again = learner.finished(&random_flow(T0 + 120), &e, &mut db, at(T0 + 120));
    assert_eq!(
        again.len(),
        1,
        "remind me: the next sighting is a new alert"
    );
    assert_ne!(again[0].id, id);
    assert!(learner.take_errors().is_empty());
}

#[test]
fn dismissed_before_a_restart_still_reminds() {
    let mut db = TestStore::open("dismissed-restart");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let e = enricher();
    let id = {
        let mut before = Learner::new(Toggles::default(), 0);
        let id = before.finished(&random_flow(T0), &e, &mut db, at(T0))[0].id;
        assert!(db.dismiss_alert(id, false, at(T0 + 60)).unwrap());
        before
            .alert_closed(&mut db, id, false, at(T0 + 60))
            .unwrap();
        id
    };
    let mut learner = Learner::new(Toggles::default(), 0);
    let again = learner.finished(&random_flow(T0 + 120), &e, &mut db, at(T0 + 120));
    assert_eq!(again.len(), 1);
    assert_ne!(again[0].id, id);
    assert!(learner.take_errors().is_empty());
}

#[test]
fn a_sighting_after_a_restart_counts_on_the_open_alert() {
    let mut db = TestStore::open("seen-restart");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let e = enricher();
    {
        let mut before = Learner::new(Toggles::default(), 0);
        assert_eq!(
            before.finished(&random_flow(T0), &e, &mut db, at(T0)).len(),
            1
        );
        let secs = T0 + HOUR;
        assert!(
            before
                .finished(&random_flow(secs), &e, &mut db, at(secs))
                .is_empty()
        );
    }
    assert_eq!(behaviour(&db)[0].seen_again, 1);
    let mut learner = Learner::new(Toggles::default(), 0);
    let secs = T0 + 2 * HOUR;
    assert!(
        learner
            .finished(&random_flow(secs), &e, &mut db, at(secs))
            .is_empty(),
        "no new alert while one waits"
    );
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].seen_again, 2, "counted on from the saved count");
    assert!(learner.take_errors().is_empty());
}

#[test]
fn allowing_with_a_failing_store_keeps_the_link() {
    let mut db = TestStore::open("allow-read-only");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let path = db.dir.join("t.db");
    let store_key = Key::from_bytes([9; 32]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    let id = learner.finished(&random_flow(T0), &e, &mut db, at(T0))[0].id;
    // Seen twice again before the user answers.
    for secs in [T0 + 20, T0 + 40] {
        learner.finished(&random_flow(secs), &e, &mut db, at(secs));
    }
    assert_eq!(behaviour(&db)[0].seen_again, 2);

    drop(db.store.take());
    set_read_only(&path, true);
    let failed = Store::open(&path, &store_key)
        .map(|mut read_only| learner.alert_closed(&mut read_only, id, true, at(T0 + 60)));
    set_read_only(&path, false);
    assert!(failed.unwrap().is_err());

    // Still pending, and still linked to its alert: a sighting counts on
    // it, after the sightings before.
    db.store = Some(Store::open(&path, &store_key).unwrap());
    assert_eq!(
        state(&db, ItemKind::Domain, RANDOM_DOMAIN),
        Some(ItemState::Pending)
    );
    let secs = T0 + HOUR;
    assert!(
        learner
            .finished(&random_flow(secs), &e, &mut db, at(secs))
            .is_empty()
    );
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].seen_again, 3);
    // Trying again works.
    learner
        .alert_closed(&mut db, id, true, at(T0 + 2 * HOUR))
        .unwrap();
    assert_eq!(
        state(&db, ItemKind::Domain, RANDOM_DOMAIN),
        Some(ItemState::Allowed)
    );
    assert!(learner.take_errors().is_empty());
}

#[test]
fn this_is_fine_allows_every_lasting_reason() {
    let mut db = TestStore::open("allow-every-reason");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let reason = |signal, value: &str| Reason {
        signal,
        value: Some(value.to_owned()),
        observed: None,
        usual: None,
        count: None,
    };
    let name = format!("behaviour|{}|random_name|{RANDOM_DOMAIN}", key());
    let hour = format!("behaviour|{}|unusual_time|03", key());
    let alert = NewAlert {
        key: format!("behaviour|{}|{T0}", key()),
        allow_key: Some(name.clone()),
        kind: AlertKind::Behaviour,
        severity: Severity::Medium,
        app_name: Some("Chat.exe".to_owned()),
        app_path: Some(PATH.to_owned()),
        target: Some(RANDOM_DOMAIN.to_owned()),
        detail: None,
        reasons: vec![
            reason(Signal::RandomName, RANDOM_DOMAIN),
            reason(Signal::UnusualTime, "03"),
        ],
    };
    let id = db.add_alert(&alert, at(T0)).unwrap().unwrap();
    let mut learner = Learner::new(Toggles::default(), 0);
    assert!(db.dismiss_alert(id, true, at(T0 + 60)).unwrap());
    learner
        .alert_closed(&mut db, id, true, at(T0 + 60))
        .unwrap();
    assert!(db.is_allowed(&name).unwrap());
    assert!(
        db.is_allowed(&hour).unwrap(),
        "every reason that can be allowed"
    );
    assert!(learner.take_errors().is_empty());
}

#[test]
fn this_is_fine_after_a_reset_allows_nothing() {
    let mut db = TestStore::open("allow-after-reset");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let e = enricher();
    let id =
        Learner::new(Toggles::default(), 0).finished(&random_flow(T0), &e, &mut db, at(T0))[0].id;
    let mut learner = Learner::new(Toggles::default(), 0);
    assert!(learner.reset(&mut db, &key(), at(T0 + 60)).unwrap());
    // The domain waits on a newer alert by now.
    db.save_items(
        &key(),
        &[ProfileItem {
            state: ItemState::Pending,
            ..item(ItemKind::Domain, RANDOM_DOMAIN)
        }],
    )
    .unwrap();
    learner
        .alert_closed(&mut db, id, true, at(T0 + 120))
        .unwrap();
    assert_eq!(
        state(&db, ItemKind::Domain, RANDOM_DOMAIN),
        Some(ItemState::Pending)
    );
    assert!(learner.take_errors().is_empty());
}

#[test]
fn reset_forgets_the_apps_lasting_allows() {
    let mut db = TestStore::open("reset-allows");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    let id = learner.finished(&random_flow(T0), &e, &mut db, at(T0))[0].id;
    assert!(db.dismiss_alert(id, true, at(T0 + 60)).unwrap());
    learner
        .alert_closed(&mut db, id, true, at(T0 + 60))
        .unwrap();
    let allow = format!("behaviour|{}|random_name|{RANDOM_DOMAIN}", key());
    let other = r"behaviour|c:\apps\chat2.exe|random_name|x.example".to_owned();
    db.add_allow_keys(std::slice::from_ref(&other), at(T0))
        .unwrap();
    assert!(db.is_allowed(&allow).unwrap());

    assert!(learner.reset(&mut db, &key(), at(T0 + 120)).unwrap());
    assert!(!db.is_allowed(&allow).unwrap(), "learns from scratch");
    assert!(db.is_allowed(&other).unwrap(), "other apps keep theirs");
    assert!(learner.take_errors().is_empty());
}

#[test]
fn reset_drops_traffic_not_yet_written() {
    let mut db = TestStore::open("reset-hour");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    let before = [delta(T0 + 60, "chat.example", 5 * MB, 1)];
    learner.traffic(&app(), &before, &e, &mut db, at(T0 + 60));
    assert!(learner.reset(&mut db, &key(), at(T0 + 120)).unwrap());
    let after = [delta(T0 + 180, "chat.example", 3 * MB, 1)];
    learner.traffic(&app(), &after, &e, &mut db, at(T0 + 180));
    learner.flush(&mut db, at(T0 + HOUR)).unwrap();
    assert!(learner.take_errors().is_empty());
    let profile = db.profile(&key()).unwrap().unwrap();
    assert_eq!(profile.row.first_data, at(T0 + 120));
    assert_eq!(profile.hours.len(), 1);
    assert_eq!(profile.hours[0].bytes_sent, 3 * MB);
    assert!(!learner.reset(&mut db, r"c:\nothing.exe", at(T0)).unwrap());
}

#[test]
fn goes_anywhere_choice_is_kept_by_the_cache() {
    let mut db = TestStore::open("goes-anywhere");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    assert!(learner.finished(&usual(T0), &e, &mut db, at(T0)).is_empty());
    assert!(
        learner
            .set_goes_anywhere(&mut db, &key(), GoesAnywhere::UserOn)
            .unwrap()
    );
    let new = flow(Some("other.example"), Some("Other Co"), Some("RU"), T0 + 60);
    assert!(learner.finished(&new, &e, &mut db, at(T0 + 60)).is_empty());
    assert!(behaviour(&db).is_empty());
    // The flow saved the cached row; the user's choice is still there.
    let row = db.profile(&key()).unwrap().unwrap().row;
    assert_eq!(row.goes_anywhere, GoesAnywhere::UserOn);
    assert!(
        !learner
            .set_goes_anywhere(&mut db, r"c:\nothing.exe", GoesAnywhere::UserOn)
            .unwrap()
    );
    assert!(learner.take_errors().is_empty());
}

fn set_read_only(path: &std::path::Path, read_only: bool) {
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_readonly(read_only);
    std::fs::set_permissions(path, permissions).unwrap();
}

#[test]
fn failed_alert_save_learns_nothing() {
    let mut db = TestStore::open("read-only");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let path = db.dir.join("t.db");
    let store_key = Key::from_bytes([9; 32]);
    let mut learner = Learner::new(Toggles::default(), 0);
    let e = enricher();
    // The learner caches the profile while the store can be written.
    assert!(learner.finished(&usual(T0), &e, &mut db, at(T0)).is_empty());

    drop(db.store.take());
    set_read_only(&path, true);
    let failed = Store::open(&path, &store_key).map(|mut read_only| {
        learner.finished(&random_flow(T0 + 60), &e, &mut read_only, at(T0 + 60))
    });
    set_read_only(&path, false);
    assert!(failed.unwrap().is_empty());
    let errors = learner.take_errors();
    assert!(
        errors.iter().any(|e| e.contains("could not save an alert")),
        "{errors:?}"
    );

    // The domain was neither learned nor counted as raised today: the next
    // flow raises it.
    db.store = Some(Store::open(&path, &store_key).unwrap());
    assert_eq!(state(&db, ItemKind::Domain, RANDOM_DOMAIN), None);
    let raised = learner.finished(&random_flow(T0 + 120), &e, &mut db, at(T0 + 120));
    assert_eq!(raised.len(), 1);
    assert_eq!(
        state(&db, ItemKind::Domain, RANDOM_DOMAIN),
        Some(ItemState::Pending)
    );
    assert!(learner.take_errors().is_empty());
}

/// `count` random-looking domains, all different.
fn random_domains(count: usize) -> Vec<String> {
    // 36 different characters: every 12-character window looks random.
    const CHARS: &[u8] = b"q7x9k2m4zt8wbhn3vr1y6pd5cjlfgs0aeiou";
    (0..count)
        .map(|n| {
            let label: String = (0..12)
                .map(|i| char::from(CHARS[(n + i) % CHARS.len()]))
                .collect();
            format!("{label}.example")
        })
        .collect()
}

#[test]
fn a_value_the_cap_dropped_still_counts_on_its_alert_after_a_restart() {
    let mut db = TestStore::open("dropped-relink");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let e = enricher();
    let domains = random_domains(30);
    {
        let mut before = Learner::new(Toggles::default(), 0);
        for (n, domain) in domains.iter().enumerate() {
            let secs = T0 + n as u64 * 10;
            let new = flow(Some(domain), Some("Chat Inc"), Some("DE"), secs);
            before.finished(&new, &e, &mut db, at(secs));
        }
        assert!(before.take_errors().is_empty());
    }
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 1, "one window, one alert");
    assert!(saved[0].dropped_reasons > 0);
    let last = domains.last().unwrap();
    assert!(
        !saved[0]
            .reasons
            .iter()
            .any(|r| r.value.as_deref() == Some(last.as_str())),
        "the cap dropped the last name"
    );
    assert_eq!(state(&db, ItemKind::Domain, last), Some(ItemState::Pending));

    // After a restart, seeing it again counts on the alert still open.
    let mut learner = Learner::new(Toggles::default(), 0);
    let secs = T0 + HOUR;
    let again = flow(Some(last), Some("Chat Inc"), Some("DE"), secs);
    assert!(
        learner.finished(&again, &e, &mut db, at(secs)).is_empty(),
        "no new alert while one waits"
    );
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].seen_again, 1);
    assert!(learner.take_errors().is_empty());
}

#[test]
fn dismissing_a_superseded_alert_keeps_the_newer_alerts_links() {
    let mut db = TestStore::open("dismiss-superseded");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let e = enricher();
    let (first, second) = {
        let mut before = Learner::new(Toggles::default(), 0);
        let first = before.finished(&random_flow(T0), &e, &mut db, at(T0))[0].id;
        // "Remind me" reached the Learner, but marking the alert seen did
        // not happen: it is still open.
        before
            .alert_closed(&mut db, first, false, at(T0 + 60))
            .unwrap();
        let again = before.finished(&random_flow(T0 + 120), &e, &mut db, at(T0 + 120));
        assert_eq!(again.len(), 1);
        assert!(before.take_errors().is_empty());
        (first, again[0].id)
    };
    // After a restart, the domain waits on the newer alert.
    let mut learner = Learner::new(Toggles::default(), 0);
    assert!(
        learner
            .finished(&usual(T0 + HOUR), &e, &mut db, at(T0 + HOUR))
            .is_empty()
    );

    // Dismissing the older alert leaves the newer one's link alone.
    learner
        .alert_closed(&mut db, first, false, at(T0 + HOUR + 60))
        .unwrap();
    assert!(db.dismiss_alert(first, false, at(T0 + HOUR + 60)).unwrap());
    let secs = T0 + 2 * HOUR;
    assert!(
        learner
            .finished(&random_flow(secs), &e, &mut db, at(secs))
            .is_empty(),
        "seen again on the newer alert, not a third alert"
    );
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 2);
    let newer = saved.iter().find(|a| a.id == second).unwrap();
    assert_eq!(newer.seen_again, 1);
    assert!(learner.take_errors().is_empty());
}

#[test]
fn a_reminder_is_not_folded_into_an_older_alert_with_dropped_reasons() {
    let mut db = TestStore::open("remind-not-folded");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let e = enricher();
    {
        let mut before = Learner::new(Toggles::default(), 0);
        // An info alert that dropped reasons, never answered.
        for n in 0..30u64 {
            let company = format!("Company {n}");
            let new = flow(Some("chat.example"), Some(&company), Some("DE"), T0 + n);
            before.finished(&new, &e, &mut db, at(T0 + n));
        }
        assert!(behaviour(&db)[0].dropped_reasons > 0);
        // An hour later a random name raises its own alert: "remind me".
        let id = before.finished(&random_flow(T0 + HOUR), &e, &mut db, at(T0 + HOUR))[0].id;
        before
            .alert_closed(&mut db, id, false, at(T0 + HOUR + 60))
            .unwrap();
        assert!(db.dismiss_alert(id, false, at(T0 + HOUR + 60)).unwrap());
        assert!(before.take_errors().is_empty());
    }
    // After a restart, the next sighting is a new medium alert.
    let mut learner = Learner::new(Toggles::default(), 0);
    let secs = T0 + 2 * HOUR;
    let again = learner.finished(&random_flow(secs), &e, &mut db, at(secs));
    assert_eq!(again.len(), 1, "remind me: a new alert");
    assert_eq!(again[0].alert.severity, Severity::Medium);
    assert_eq!(behaviour(&db).len(), 3);
    assert!(learner.take_errors().is_empty());
}

#[test]
fn dismissing_a_superseded_alert_before_its_profile_is_loaded() {
    let mut db = TestStore::open("dismiss-superseded-cold");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let e = enricher();
    let (first, second) = {
        let mut before = Learner::new(Toggles::default(), 0);
        let first = before.finished(&random_flow(T0), &e, &mut db, at(T0))[0].id;
        // "Remind me" reached the Learner, but the alert is still open.
        before
            .alert_closed(&mut db, first, false, at(T0 + 60))
            .unwrap();
        let again = before.finished(&random_flow(T0 + 120), &e, &mut db, at(T0 + 120));
        assert_eq!(again.len(), 1);
        (first, again[0].id)
    };
    // Restarted, and the older alert is dismissed before any traffic of
    // the app loads its profile.
    let mut learner = Learner::new(Toggles::default(), 0);
    learner
        .alert_closed(&mut db, first, false, at(T0 + HOUR))
        .unwrap();
    assert!(db.dismiss_alert(first, false, at(T0 + HOUR)).unwrap());
    let secs = T0 + 2 * HOUR;
    assert!(
        learner
            .finished(&random_flow(secs), &e, &mut db, at(secs))
            .is_empty(),
        "seen again on the newer alert, not a third alert"
    );
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 2);
    assert_eq!(saved.iter().find(|a| a.id == second).unwrap().seen_again, 1);
    assert!(learner.take_errors().is_empty());
}

#[test]
fn a_reminded_value_dropped_by_a_newer_alert_counts_on_it_after_a_restart() {
    let mut db = TestStore::open("reminded-dropped");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let e = enricher();
    let newer = {
        let mut before = Learner::new(Toggles::default(), 0);
        // Alert Y names the domain; "remind me".
        let first = before.finished(&random_flow(T0), &e, &mut db, at(T0))[0].id;
        before
            .alert_closed(&mut db, first, false, at(T0 + 60))
            .unwrap();
        assert!(db.dismiss_alert(first, false, at(T0 + 60)).unwrap());
        // An hour later alert Z fills up with other random names, and the
        // domain's next sighting joins it, dropped by the cap.
        for (n, domain) in random_domains(MAX_REASONS + 1).iter().enumerate().skip(1) {
            let secs = T0 + HOUR + n as u64;
            let other = flow(Some(domain), Some("Chat Inc"), Some("DE"), secs);
            before.finished(&other, &e, &mut db, at(secs));
        }
        let secs = T0 + HOUR + 100;
        assert!(
            before
                .finished(&random_flow(secs), &e, &mut db, at(secs))
                .is_empty()
        );
        assert!(before.take_errors().is_empty());
        let newer = newest(&db);
        assert!(
            !newer
                .reasons
                .iter()
                .any(|r| r.value.as_deref() == Some(RANDOM_DOMAIN)),
            "the cap dropped it"
        );
        newer.id
    };
    // After a restart, it still counts on Z: no extra alert.
    let mut learner = Learner::new(Toggles::default(), 0);
    let secs = T0 + 2 * HOUR;
    assert!(
        learner
            .finished(&random_flow(secs), &e, &mut db, at(secs))
            .is_empty(),
        "seen again on the newer alert"
    );
    let saved = behaviour(&db);
    assert_eq!(saved.len(), 2);
    assert_eq!(saved.iter().find(|a| a.id == newer).unwrap().seen_again, 1);
    assert!(learner.take_errors().is_empty());
}

#[test]
fn a_value_counted_on_its_alert_before_a_reminder_is_not_moved_to_a_newer_one() {
    let mut db = TestStore::open("counted-then-reminded");
    seed(&mut db, GoesAnywhere::Auto, &[]);
    let e = enricher();
    {
        let mut before = Learner::new(Toggles::default(), 0);
        let first = before.finished(&random_flow(T0), &e, &mut db, at(T0))[0].id;
        // A newer alert fills up and drops reasons.
        for (n, domain) in random_domains(MAX_REASONS + 2).iter().enumerate().skip(1) {
            let secs = T0 + HOUR + n as u64;
            let other = flow(Some(domain), Some("Chat Inc"), Some("DE"), secs);
            before.finished(&other, &e, &mut db, at(secs));
        }
        assert!(newest(&db).dropped_reasons > 0);
        // The domain is seen again meanwhile: it counts on its own alert,
        // which the user then dismisses ("remind me").
        let secs = T0 + HOUR + 100;
        before.finished(&random_flow(secs), &e, &mut db, at(secs));
        before
            .alert_closed(&mut db, first, false, at(secs + 60))
            .unwrap();
        assert!(db.dismiss_alert(first, false, at(secs + 60)).unwrap());
        assert!(before.take_errors().is_empty());
    }
    // After a restart, the next sighting is a reminder, not a count on the
    // newer alert.
    let mut learner = Learner::new(Toggles::default(), 0);
    let secs = T0 + 2 * HOUR;
    assert_eq!(
        learner
            .finished(&random_flow(secs), &e, &mut db, at(secs))
            .len(),
        1
    );
    assert_eq!(behaviour(&db).len(), 3);
    assert!(learner.take_errors().is_empty());
}
