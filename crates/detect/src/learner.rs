//! The Learner (design spec v0.3, §4 to §6): turns what apps do into their
//! behaviour profiles, and what does not fit a profile into explained
//! behaviour alerts.
//!
//! - **Traffic** ([`Learner::traffic`]): the bytes and connections of open
//!   flows since the last tick are added to the app's hour in memory and
//!   written when the hour ends ([`Learner::flush`]). Upload spike, ratio
//!   flip, unusual time and beaconing are checked as the traffic comes in,
//!   so a big upload is caught while it runs.
//! - **Finished flows** ([`Learner::finished`]): their destinations join the
//!   profile. New site, company and country, random-looking name and changed
//!   program file are checked. A destination that raised a medium-or-higher
//!   signal is kept `pending` instead of `learned`, and seeing it again only
//!   counts on the open alert.
//! - **The user's answers** ([`Learner::alert_closed`], [`Learner::reset`],
//!   [`Learner::set_goes_anywhere`]) change the store and what the Learner
//!   holds together, so a cached profile never undoes them.
//!
//! Nothing is raised while a profile is learning. Signals for one app within
//! [`COMBINE_WINDOW`] update one alert, and each app, signal and value is
//! raised at most once per local day.

mod alerts;

pub use alerts::COMBINE_WINDOW;

use std::collections::{BTreeSet, HashMap};
use std::time::SystemTime;

use whereabouts_enrich::Enricher;
use whereabouts_store::{
    AlertKind, GoesAnywhere, HourRow, ItemKind, ItemState, PROFILE_HOURS_KEPT, ProfileItem,
    ProfileRow, Reason, Severity, Signal, Store, StoreError, StoredProfile, known_app_key,
};

use crate::beacon::BeaconTracker;
use crate::meter::Delta;
use crate::profile::Profile;
use crate::signals::{self, Toggles, severity_of};
use crate::{Raised, unix_secs};
use alerts::{Alerts, Link, Saved, allow_key, item_kind};

/// How long, in seconds, a changed program file stays suspect: within this
/// time, the first flow to somewhere new raises "binary changed".
pub const BINARY_CHANGE_WINDOW: u64 = 24 * 3_600;

const SECS_PER_HOUR: i64 = 3_600;
const SECS_PER_DAY: i64 = 86_400;

/// What the Learner needs to know about the program behind some traffic.
#[derive(Debug, Clone, Copy)]
pub struct AppFacts<'a> {
    /// Executable file name.
    pub app_name: &'a str,
    /// The program's full path (programs without one are never profiled).
    pub path: &'a str,
    /// SHA-256 of the program file, if known.
    pub sha256: Option<&'a str>,
    /// The signing publisher, if the file is signed.
    pub publisher: Option<&'a str>,
    /// Whether the signature is valid.
    pub signature_valid: bool,
    /// Whether the file is in a folder only administrators can change.
    pub installed_by_admins: bool,
}

/// A flow the engine finished, with what is known about where it went.
#[derive(Debug, Clone, Copy)]
pub struct Finished<'a> {
    /// The program that made it.
    pub app: AppFacts<'a>,
    /// The registrable domain, only if confirmed by the Windows DNS service.
    pub domain: Option<&'a str>,
    /// The company that owns the remote network.
    pub company: Option<&'a str>,
    /// The remote country code.
    pub country: Option<&'a str>,
    /// The remote port.
    pub port: u16,
    /// When the flow started.
    pub first_seen: SystemTime,
    /// When the flow last had traffic.
    pub last_seen: SystemTime,
}

/// A program file that changed to an unsigned file or another publisher's,
/// with what the profile knew before.
#[derive(Debug)]
struct Suspect {
    /// When the change was seen, in Unix seconds.
    since: u64,
    sha256: Option<String>,
    publisher: Option<String>,
}

/// Builds behaviour profiles from traffic and raises behaviour alerts.
#[derive(Debug)]
pub struct Learner {
    toggles: Toggles,
    local_offset_secs: i32,
    /// Profiles read from the store (or created), by app key, kept up to
    /// date with what this Learner writes.
    profiles: HashMap<String, Profile>,
    /// Traffic not yet written to the store, by app key and Unix hour.
    hours: HashMap<(String, i64), HourRow>,
    beacons: BeaconTracker,
    alerts: Alerts,
    /// Changed program files, by app key.
    suspects: HashMap<String, Suspect>,
    /// The local hour (hours since the epoch, local time) in which unusual
    /// time was last checked, by app key.
    time_checked: HashMap<String, i64>,
    /// Problems with the store, for the caller to report ([`Learner::take_errors`]).
    errors: Vec<String>,
}

impl Learner {
    /// A Learner with these signals on. `local_offset_secs` is the local time
    /// zone's offset from UTC (for local days and hours of the day).
    pub fn new(toggles: Toggles, local_offset_secs: i32) -> Self {
        Self {
            toggles,
            local_offset_secs,
            profiles: HashMap::new(),
            hours: HashMap::new(),
            beacons: BeaconTracker::default(),
            alerts: Alerts::default(),
            suspects: HashMap::new(),
            time_checked: HashMap::new(),
            errors: Vec::new(),
        }
    }

    /// Changes the local time zone's offset from UTC.
    pub fn set_local_offset(&mut self, secs: i32) {
        self.local_offset_secs = secs;
    }

    /// Adds one app's traffic since the last tick (`deltas` are that app's)
    /// to its hours in memory, and checks upload spike, ratio flip, unusual
    /// time and beaconing on the hours it touches. Returns an alert to
    /// notify about, if any.
    pub fn traffic(
        &mut self,
        app: &AppFacts<'_>,
        deltas: &[Delta],
        _enricher: &Enricher,
        store: &mut Store,
        now: SystemTime,
    ) -> Vec<Raised> {
        if app.path.is_empty() || deltas.is_empty() {
            return Vec::new();
        }
        let key = known_app_key(app.path);
        self.alerts.new_day(self.local_day(now));
        if !self.load(&key, app, store, now) {
            return Vec::new();
        }

        let mut touched = BTreeSet::new();
        for delta in deltas {
            let row = self
                .hours
                .entry((key.clone(), delta.hour))
                .or_insert_with(|| empty_hour(delta.hour));
            add_to(
                row,
                &HourRow {
                    hour: delta.hour,
                    bytes_sent: delta.sent,
                    bytes_received: delta.received,
                    connections: u64::from(delta.new_connections),
                },
            );
            touched.insert(delta.hour);
        }

        let mut contacted = BTreeSet::new();
        if self.toggles.is_on(Signal::Beaconing) {
            for delta in deltas.iter().filter(|d| d.new_connections > 0) {
                if let Some(destination) = &delta.destination {
                    self.beacons.record(
                        &key,
                        destination,
                        unix_secs(now),
                        delta.new_connections,
                        delta.sent.saturating_add(delta.received),
                    );
                    contacted.insert(destination.as_str());
                }
            }
        }

        let Some(profile) = self.profiles.get_mut(&key) else {
            return Vec::new();
        };
        let row = profile.row_mut();
        row.last_data = row.last_data.max(now);
        let profile = &*profile;
        if profile.is_learning(now) {
            return Vec::new();
        }

        let mut reasons = Vec::new();
        for &hour in &touched {
            let history = history_without(profile, hour);
            let (sent, received) = running_total(&self.hours, &key, profile, hour);
            if self.toggles.is_on(Signal::UploadSpike) {
                reasons.extend(signals::upload_spike(&history, sent));
            }
            if self.toggles.is_on(Signal::RatioFlip) {
                reasons.extend(signals::ratio_flip(&history, sent, received));
            }
            let local_hour = hour
                .saturating_mul(SECS_PER_HOUR)
                .saturating_add(i64::from(self.local_offset_secs))
                .div_euclid(SECS_PER_HOUR);
            if self.toggles.is_on(Signal::UnusualTime)
                && self.time_checked.insert(key.clone(), local_hour) != Some(local_hour)
            {
                let of_day = u8::try_from(local_hour.rem_euclid(24)).unwrap_or(0);
                reasons.extend(signals::unusual_time(
                    &history,
                    of_day,
                    self.local_offset_secs,
                ));
            }
        }
        for destination in contacted {
            reasons.extend(self.beacons.check(&key, destination));
        }

        let saved = self
            .alerts
            .fresh(&key, reasons, store)
            .and_then(|fresh| self.alerts.save(&key, app, fresh, store, now));
        match saved {
            Ok(saved) => saved.raised.into_iter().collect(),
            Err(error) => {
                self.errors
                    .push(format!("could not save an alert: {error}"));
                Vec::new()
            }
        }
    }

    /// Adds a finished flow's destinations to its app's profile (creating
    /// the profile on first sight) and checks the destination, random-name
    /// and changed-program signals (none while learning). Returns an alert to
    /// notify about, if any. If the alert cannot be saved, the destinations
    /// behind it are not learned, so the next flow checks them again.
    pub fn finished(
        &mut self,
        flow: &Finished<'_>,
        enricher: &Enricher,
        store: &mut Store,
        now: SystemTime,
    ) -> Vec<Raised> {
        let app = &flow.app;
        if app.path.is_empty() {
            return Vec::new();
        }
        let key = known_app_key(app.path);
        let local_day = self.local_day(now);
        self.alerts.new_day(local_day);
        if !self.load(&key, app, store, now) {
            return Vec::new();
        }
        let secs = unix_secs(now);
        let Some(profile) = self.profiles.get_mut(&key) else {
            return Vec::new();
        };

        let port = flow.port.to_string();
        let values: Vec<(ItemKind, &str)> = [
            (ItemKind::Domain, flow.domain),
            (ItemKind::Company, flow.company),
            (ItemKind::Country, flow.country),
            (ItemKind::Port, Some(port.as_str())),
        ]
        .into_iter()
        .filter_map(|(kind, value)| Some((kind, value.filter(|v| !v.is_empty())?)))
        .collect();

        let row = profile.row_mut();
        if row.last_active_day.is_none_or(|day| local_day > day) {
            row.active_days = row.active_days.saturating_add(1);
            row.last_active_day = Some(local_day);
        }
        row.last_data = row.last_data.max(now);

        // A program file swapped for an unsigned or differently signed one
        // stays suspect for a while, so flows to known places in between do
        // not hide it.
        if self
            .suspects
            .get(&key)
            .is_some_and(|s| secs.saturating_sub(s.since) >= BINARY_CHANGE_WINDOW)
        {
            self.suspects.remove(&key);
        }
        let swapped = signals::binary_changed(
            profile,
            app.sha256,
            app.publisher,
            app.signature_valid,
            true,
        )
        .is_some();
        if swapped {
            let row = &profile.stored().row;
            self.suspects.entry(key.clone()).or_insert_with(|| Suspect {
                since: secs,
                sha256: row.last_sha256.clone(),
                publisher: row.last_publisher.clone(),
            });
        }

        let mut reasons = Vec::new();
        let mut seen_pending = Vec::new();
        if !profile.is_learning(now) {
            // A pending value counts on its open alert; after the user
            // dismissed that alert, it raises a new one ("remind me").
            let mut remind = Vec::new();
            for &(kind, value) in &values {
                if profile.pending(kind, value) {
                    match self.alerts.link(&key, kind, value) {
                        Some(Link::Open(_)) => seen_pending.push((kind, value.to_owned())),
                        Some(Link::Closed) => remind.push(kind),
                        None => {}
                    }
                }
            }
            let quiet = |kind: ItemKind, value: &str| {
                profile.pending(kind, value) && !remind.contains(&kind)
            };

            let goes_anywhere =
                profile.goes_anywhere(app.publisher, app.signature_valid, app.installed_by_admins);
            let mut new = signals::new_destinations(
                profile,
                flow.domain,
                flow.company,
                flow.country,
                goes_anywhere,
            );
            new.retain(|r| self.toggles.is_on(r.signal));
            let new_destination = !new.is_empty();
            reasons.extend(new.into_iter().filter(|r| {
                !matches!((item_kind(r.signal), r.value.as_deref()), (Some(kind), Some(value)) if quiet(kind, value))
            }));
            if self.toggles.is_on(Signal::RandomName)
                && let Some(domain) = flow.domain.filter(|d| !d.is_empty())
                && !profile.knows(ItemKind::Domain, domain)
                && !quiet(ItemKind::Domain, domain)
            {
                reasons.extend(signals::random_name(domain, enricher));
            }
            if self.toggles.is_on(Signal::BinaryChanged)
                && let Some(suspect) = self.suspects.get(&key)
            {
                reasons.extend(signals::binary_changed(
                    &facts_before(profile, suspect),
                    app.sha256,
                    app.publisher,
                    app.signature_valid,
                    new_destination,
                ));
            }
        }

        let row = profile.row_mut();
        if let Some(sha256) = app.sha256 {
            row.last_sha256 = Some(sha256.to_owned());
            row.last_publisher = app.publisher.map(str::to_owned);
        }

        // The alert first: destinations wait on it only if it was saved.
        let binary_fired = reasons.iter().any(|r| r.signal == Signal::BinaryChanged);
        let mut waiting = waiting_kinds(&reasons);
        let saved = self.alerts.fresh(&key, reasons, store).and_then(|fresh| {
            waiting = waiting_kinds(&fresh);
            self.alerts.save(&key, app, fresh, store, now)
        });
        let saved = match saved {
            Ok(saved) => {
                if binary_fired {
                    self.suspects.remove(&key);
                }
                saved
            }
            Err(error) => {
                self.errors
                    .push(format!("could not save an alert: {error}"));
                Saved::default()
            }
        };

        let Some(profile) = self.profiles.get_mut(&key) else {
            return saved.raised.into_iter().collect();
        };
        if let Err(error) = store.save_profile_row(&profile.stored().row) {
            self.errors
                .push(format!("could not save a behaviour profile: {error}"));
            return saved.raised.into_iter().collect();
        }
        let seen_on_day = profile.stored().row.active_days;
        let mut items = Vec::with_capacity(values.len());
        for &(kind, value) in &values {
            let is_waiting = waiting.contains(&kind);
            if let Some(item) = profile.item_mut(kind, value) {
                item.first_seen = item.first_seen.min(flow.first_seen);
                item.last_seen = item.last_seen.max(flow.last_seen);
                item.seen_on_day = item.seen_on_day.max(seen_on_day);
                // A reminder raised a new alert: sightings count on it now.
                if is_waiting
                    && item.state == ItemState::Pending
                    && let Some(id) = saved.id
                {
                    self.alerts.set_link(&key, kind, value, id);
                }
                items.push(item.clone());
                continue;
            }
            let Some(state) = new_item_state(is_waiting, saved.id) else {
                continue;
            };
            if let (ItemState::Pending, Some(id)) = (state, saved.id) {
                self.alerts.set_link(&key, kind, value, id);
            }
            let item = ProfileItem {
                kind,
                value: value.to_owned(),
                first_seen: flow.first_seen,
                last_seen: flow.last_seen,
                seen_on_day,
                state,
            };
            // Like the store, the profile keeps at most so many of a kind.
            profile.add_item(item.clone());
            items.push(item);
        }
        if let Err(error) = store.save_items(&key, &items) {
            self.errors
                .push(format!("could not save a behaviour profile: {error}"));
        }

        if let Err(error) = self
            .alerts
            .count_seen_again(&key, &seen_pending, store, now)
        {
            self.errors
                .push(format!("could not update an alert: {error}"));
        }
        saved.raised.into_iter().collect()
    }

    /// Writes the hours that ended before `now` (every hour held, when `now`
    /// is past them all: call it with an hour ahead on shutdown). Hours
    /// already in the store are added to. Hours that could not be written
    /// stay in memory for the next call; the first error is returned.
    pub fn flush(&mut self, store: &mut Store, now: SystemTime) -> Result<(), StoreError> {
        let current = unix_hour(now);
        let mut due: HashMap<String, Vec<HourRow>> = HashMap::new();
        for ((key, hour), row) in &self.hours {
            if *hour < current {
                due.entry(key.clone()).or_default().push(row.clone());
            }
        }
        let cutoff = unix_hour(now.checked_sub(PROFILE_HOURS_KEPT).unwrap_or(now));
        let mut result = Ok(());
        for (key, rows) in due {
            // The profile row goes first (the store has no foreign keys),
            // with the latest `last_data`.
            let written = match self.profiles.get(&key) {
                Some(profile) => store.save_profile_row(&profile.stored().row),
                None => Ok(()),
            }
            .and_then(|()| store.add_hours(&key, &rows));
            if let Err(error) = written {
                if result.is_ok() {
                    result = Err(error);
                }
                continue;
            }
            for row in &rows {
                self.hours.remove(&(key.clone(), row.hour));
            }
            if let Some(profile) = self.profiles.get_mut(&key) {
                let hours = profile.hours_mut();
                for row in rows {
                    match hours.binary_search_by_key(&row.hour, |h| h.hour) {
                        Ok(at) => add_to(&mut hours[at], &row),
                        Err(at) => hours.insert(at, row),
                    }
                }
                hours.retain(|h| h.hour >= cutoff);
            }
        }
        result
    }

    /// The user closed behaviour alert `alert_id`. Its window ends either
    /// way. With `allowed` ("this is fine"), the pending destinations it
    /// named become allowed, in the store and here, and every reason in it
    /// that can be allowed (beaconing, random-looking name, unusual time)
    /// gets its lasting allow key. Otherwise (dismiss: "remind me") they stay
    /// pending, and the next sighting of each raises a new alert. For an
    /// alert this Learner holds no links for (the service restarted), the
    /// destinations come from the alert's saved reasons: those still pending,
    /// unless the profile was reset after the alert, so the alert's
    /// destinations are gone, and except those linked to another open alert
    /// by now. A destination that could not be allowed keeps its link, so
    /// trying again finds it. The caller still marks the alert seen
    /// (`Store::dismiss_alert`).
    pub fn alert_closed(
        &mut self,
        store: &mut Store,
        alert_id: i64,
        allowed: bool,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let mut named = self.alerts.close(alert_id);
        if named.is_empty() {
            named = pending_named_by_saved(store, alert_id)?;
            // A destination that now waits on a newer open alert is that
            // alert's to answer.
            named.retain(|(key, kind, value)| {
                !matches!(
                    self.alerts.link(key, *kind, value),
                    Some(Link::Open(other)) if other != alert_id
                )
            });
        }
        if !allowed {
            for (key, kind, value) in &named {
                self.alerts.remind(key, *kind, value);
            }
            return Ok(());
        }
        let mut result = store.add_allow_keys(&allow_keys_of_saved(store, alert_id)?, now);
        for (key, kind, value) in named {
            if let Err(error) = store.set_item_state(&key, kind, &value, ItemState::Allowed) {
                if result.is_ok() {
                    result = Err(error);
                }
                continue;
            }
            self.alerts.unlink(&key, kind, &value);
            if let Some(item) = self
                .profiles
                .get_mut(&key)
                .and_then(|profile| profile.item_mut(kind, &value))
            {
                item.state = ItemState::Allowed;
            }
        }
        result
    }

    /// Resets an app's profile (it learns again from `now`), deletes its
    /// lasting "this is fine" allows (beaconing, random-looking names,
    /// unusual hours), and forgets what is held about it here, including
    /// traffic not yet written. Returns `false` if there is no such profile.
    pub fn reset(
        &mut self,
        store: &mut Store,
        key: &str,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        let reset = store.reset_profile(key, now)?;
        self.forget(key);
        if reset {
            store.delete_behaviour_allows(key)?;
        }
        Ok(reset)
    }

    /// Links the pending destinations of a profile just read from the store
    /// to the alerts waiting on them, as this Learner would hold them had it
    /// been running: to the newest open behaviour alert naming each (keeping
    /// its "seen again" count), or, when the user already closed that alert,
    /// to a reminder ("remind me"). A destination no open alert names may
    /// be one whose reason the alert dropped (it keeps only so many): it
    /// waits on the newest open alert that dropped reasons and was raised
    /// by the time the destination was last seen. Links this run already
    /// holds are kept.
    fn relink(&mut self, key: &str, store: &Store) {
        let Some(profile) = self.profiles.get(key) else {
            return;
        };
        let pending: Vec<(ItemKind, String, SystemTime)> = profile
            .stored()
            .items
            .iter()
            .filter(|item| item.state == ItemState::Pending)
            .map(|item| (item.kind, item.value.clone(), item.last_seen))
            .collect();
        if pending.is_empty() {
            return;
        }
        let reset = profile.stored().row.reset_at;
        let open = match store.open_behaviour_alerts(key) {
            Ok(open) => open,
            Err(error) => {
                self.errors
                    .push(format!("could not read behaviour alerts: {error}"));
                return;
            }
        };
        let since_reset = || {
            open.iter()
                .rev()
                .filter(|alert| reset.is_none_or(|reset| alert.created >= reset))
        };
        for (kind, value, last_seen) in pending {
            let naming = since_reset()
                .find(|alert| {
                    alert.reasons.iter().any(|r| {
                        item_kind(r.signal) == Some(kind) && r.value.as_deref() == Some(&value)
                    })
                })
                .or_else(|| {
                    since_reset()
                        .find(|alert| alert.dropped_reasons > 0 && alert.created <= last_seen)
                });
            match naming {
                Some(alert) => {
                    self.alerts
                        .restore(key, kind, &value, Link::Open(alert.id), alert.seen_again);
                }
                None => self.alerts.restore(key, kind, &value, Link::Closed, 0),
            }
        }
    }

    /// Sets whether an app is expected to go anywhere, in the store and
    /// here. Returns `false` if there is no such profile.
    pub fn set_goes_anywhere(
        &mut self,
        store: &mut Store,
        key: &str,
        value: GoesAnywhere,
    ) -> Result<bool, StoreError> {
        let changed = store.set_goes_anywhere(key, value)?;
        if changed && let Some(profile) = self.profiles.get_mut(key) {
            profile.row_mut().goes_anywhere = value;
        }
        Ok(changed)
    }

    /// Forgets everything held about an app: its cached profile, traffic not
    /// yet written, open alert, pending links and suspect program file (for
    /// "Delete everything"; [`Learner::reset`] uses it too).
    pub fn forget(&mut self, key: &str) {
        self.profiles.remove(key);
        self.hours.retain(|(app, _), _| app != key);
        self.alerts.forget(key);
        self.suspects.remove(key);
        self.time_checked.remove(key);
    }

    /// Forgets the cached profiles only, so each is read from the store again
    /// when next needed (after the store aged some out: call
    /// [`Learner::flush`] first, so no written hour is lost). Traffic not yet
    /// written, open alerts, pending links and suspect program files are
    /// kept.
    pub fn drop_profiles(&mut self) {
        self.profiles.clear();
    }

    /// Problems with the store since the last call, for the caller to report.
    pub fn take_errors(&mut self) -> Vec<String> {
        std::mem::take(&mut self.errors)
    }

    /// The local day number of `now`.
    fn local_day(&self, now: SystemTime) -> i64 {
        unix_secs_i64(now)
            .saturating_add(i64::from(self.local_offset_secs))
            .div_euclid(SECS_PER_DAY)
    }

    /// Makes sure the app's profile is cached: read from the store (with
    /// its pending destinations linked again, see [`Learner::relink`]), or
    /// created (and saved) if it has none. `false` if the store failed.
    fn load(&mut self, key: &str, app: &AppFacts<'_>, store: &mut Store, now: SystemTime) -> bool {
        if self.profiles.contains_key(key) {
            return true;
        }
        let stored = match store.profile(key) {
            Ok(Some(stored)) => stored,
            Ok(None) => {
                let row = ProfileRow {
                    key: key.to_owned(),
                    path: app.path.to_owned(),
                    app_name: app.app_name.to_owned(),
                    first_data: now,
                    learned_since: now,
                    last_data: now,
                    active_days: 0,
                    last_active_day: None,
                    last_sha256: None,
                    last_publisher: None,
                    goes_anywhere: GoesAnywhere::Auto,
                    reset_at: None,
                };
                if let Err(error) = store.save_profile_row(&row) {
                    self.errors
                        .push(format!("could not save a behaviour profile: {error}"));
                    return false;
                }
                StoredProfile {
                    row,
                    items: Vec::new(),
                    hours: Vec::new(),
                }
            }
            Err(error) => {
                self.errors
                    .push(format!("could not read a behaviour profile: {error}"));
                return false;
            }
        };
        self.profiles.insert(key.to_owned(), Profile::new(stored));
        // After a restart: what waits on which alert.
        self.relink(key, store);
        true
    }
}

/// The destinations a saved behaviour alert named that are still pending in
/// its app's profile, as `(app key, kind, value)`. None if there is no such
/// alert or profile, or the profile was reset after the alert was raised.
fn pending_named_by_saved(
    store: &Store,
    alert_id: i64,
) -> Result<Vec<(String, ItemKind, String)>, StoreError> {
    let Some(alert) = store.alert(alert_id)? else {
        return Ok(Vec::new());
    };
    let Some(path) = alert
        .app_path
        .filter(|_| alert.kind == AlertKind::Behaviour)
    else {
        return Ok(Vec::new());
    };
    let key = known_app_key(&path);
    let Some(stored) = store.profile(&key)? else {
        return Ok(Vec::new());
    };
    if stored
        .row
        .reset_at
        .is_some_and(|reset| reset > alert.created)
    {
        return Ok(Vec::new());
    }
    let profile = Profile::new(stored);
    let mut named = Vec::new();
    for reason in &alert.reasons {
        if let (Some(kind), Some(value)) = (item_kind(reason.signal), reason.value.as_deref())
            && profile.pending(kind, value)
            && !named.iter().any(|(_, k, v)| *k == kind && v == value)
        {
            named.push((key.clone(), kind, value.to_owned()));
        }
    }
    Ok(named)
}

/// The lasting allow keys of every reason in a saved behaviour alert that
/// can be allowed. None if there is no such alert, or its app's profile was
/// reset after it was raised (the reset forgot the app's allows).
fn allow_keys_of_saved(store: &Store, alert_id: i64) -> Result<Vec<String>, StoreError> {
    let Some(alert) = store.alert(alert_id)? else {
        return Ok(Vec::new());
    };
    let Some(path) = alert
        .app_path
        .as_deref()
        .filter(|_| alert.kind == AlertKind::Behaviour)
    else {
        return Ok(Vec::new());
    };
    let key = known_app_key(path);
    let reset = store
        .profile(&key)?
        .and_then(|stored| stored.row.reset_at)
        .is_some_and(|reset| reset > alert.created);
    if reset {
        return Ok(Vec::new());
    }
    let mut keys: Vec<String> = alert
        .reasons
        .iter()
        .filter_map(|reason| allow_key(&key, reason))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    Ok(keys)
}

/// The kinds of destination behind medium-or-higher reasons.
fn waiting_kinds(reasons: &[Reason]) -> Vec<ItemKind> {
    reasons
        .iter()
        .filter(|r| severity_of(r.signal) >= Severity::Medium)
        .filter_map(|r| item_kind(r.signal))
        .collect()
}

/// The state of a destination new to the profile: learned, or pending when
/// it raised a medium-or-higher signal and the alert was saved. `None` when
/// that alert could not be saved: not learned, so it is checked again.
fn new_item_state(waiting: bool, alert: Option<i64>) -> Option<ItemState> {
    match (waiting, alert) {
        (false, _) => Some(ItemState::Learned),
        (true, Some(_)) => Some(ItemState::Pending),
        (true, None) => None,
    }
}

/// Bytes sent and received in `hour` so far: what is in memory plus what
/// an earlier run already wrote for the same hour.
fn running_total(
    memory: &HashMap<(String, i64), HourRow>,
    key: &str,
    profile: &Profile,
    hour: i64,
) -> (u64, u64) {
    let held = memory.get(&(key.to_owned(), hour));
    let stored = profile.stored().hours.iter().find(|h| h.hour == hour);
    [held, stored]
        .into_iter()
        .flatten()
        .fold((0u64, 0u64), |(sent, received), h| {
            (
                sent.saturating_add(h.bytes_sent),
                received.saturating_add(h.bytes_received),
            )
        })
}

/// The profile as history for checking `hour`: its hours without that one
/// (destinations are not needed).
fn history_without(profile: &Profile, hour: i64) -> Profile {
    Profile::new(StoredProfile {
        row: profile.stored().row.clone(),
        items: Vec::new(),
        hours: profile
            .stored()
            .hours
            .iter()
            .filter(|h| h.hour != hour)
            .cloned()
            .collect(),
    })
}

/// The profile's program facts as they were before the suspect change
/// (destinations and hours are not needed).
fn facts_before(profile: &Profile, suspect: &Suspect) -> Profile {
    let mut row = profile.stored().row.clone();
    row.last_sha256.clone_from(&suspect.sha256);
    row.last_publisher.clone_from(&suspect.publisher);
    Profile::new(StoredProfile {
        row,
        items: Vec::new(),
        hours: Vec::new(),
    })
}

fn empty_hour(hour: i64) -> HourRow {
    HourRow {
        hour,
        bytes_sent: 0,
        bytes_received: 0,
        connections: 0,
    }
}

fn add_to(total: &mut HourRow, more: &HourRow) {
    total.bytes_sent = total.bytes_sent.saturating_add(more.bytes_sent);
    total.bytes_received = total.bytes_received.saturating_add(more.bytes_received);
    total.connections = total.connections.saturating_add(more.connections);
}

fn unix_secs_i64(time: SystemTime) -> i64 {
    i64::try_from(unix_secs(time)).unwrap_or(i64::MAX)
}

/// Hours since the Unix epoch (0 before it), as the meter counts them.
fn unix_hour(time: SystemTime) -> i64 {
    unix_secs_i64(time) / SECS_PER_HOUR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destinations_behind_an_unsaved_alert_are_not_learned() {
        assert_eq!(new_item_state(false, None), Some(ItemState::Learned));
        assert_eq!(new_item_state(false, Some(1)), Some(ItemState::Learned));
        assert_eq!(new_item_state(true, Some(1)), Some(ItemState::Pending));
        assert_eq!(new_item_state(true, None), None);
    }
}
