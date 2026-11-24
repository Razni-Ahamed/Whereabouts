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
//!
//! Nothing is raised while a profile is learning. Signals for one app within
//! [`COMBINE_WINDOW`] update one alert, and each app, signal and value is
//! raised at most once per local day.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::SystemTime;

use whereabouts_enrich::Enricher;
use whereabouts_store::{
    AlertKind, GoesAnywhere, HourRow, ItemKind, ItemState, NewAlert, PROFILE_HOURS_KEPT,
    ProfileItem, ProfileRow, Reason, Severity, Signal, Store, StoreError, StoredProfile,
    known_app_key,
};

use crate::beacon::BeaconTracker;
use crate::meter::Delta;
use crate::profile::Profile;
use crate::signals::{self, Toggles, severity_of};
use crate::{Raised, unix_secs};

/// Signals for the same app within this many seconds of an alert's first
/// one update that alert instead of raising another.
pub const COMBINE_WINDOW: u64 = 600;

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
    /// The open alert of each app.
    windows: HashMap<String, Window>,
    /// The alert that named each pending destination, by app key, kind and value.
    pending: HashMap<(String, ItemKind, String), i64>,
    /// How many times each alert's pending destinations were seen again.
    seen_again: HashMap<i64, u32>,
    /// Reasons raised today, by app key, signal and value.
    raised_today: HashSet<(String, Signal, String)>,
    /// The local day `raised_today` is for.
    day: Option<i64>,
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
            windows: HashMap::new(),
            pending: HashMap::new(),
            seen_again: HashMap::new(),
            raised_today: HashSet::new(),
            day: None,
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
        self.new_day(now);
        if !self.load(&key, app, store, now) {
            return Vec::new();
        }

        let mut touched = BTreeSet::new();
        for delta in deltas {
            let row = self
                .hours
                .entry((key.clone(), delta.hour))
                .or_insert_with(|| empty_hour(delta.hour));
            row.bytes_sent = row.bytes_sent.saturating_add(delta.sent);
            row.bytes_received = row.bytes_received.saturating_add(delta.received);
            row.connections = row
                .connections
                .saturating_add(u64::from(delta.new_connections));
            touched.insert(delta.hour);
        }

        let beaconing = self.toggles.is_on(Signal::Beaconing);
        let mut contacted = BTreeSet::new();
        if beaconing {
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
        profile.stored.row.last_data = profile.stored.row.last_data.max(now);
        let profile = &self.profiles[&key];
        if profile.is_learning(now) {
            return Vec::new();
        }

        let mut reasons = Vec::new();
        for &hour in &touched {
            let history = history_without(profile, hour);
            let (sent, received) = self.running_total(&key, profile, hour);
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

        let fresh = self.fresh(&key, reasons, store);
        self.save_reasons(&key, app, fresh, store, now).1
    }

    /// Adds a finished flow's destinations to its app's profile (creating
    /// the profile on first sight) and checks the destination, random-name
    /// and changed-program signals (none while learning). Returns an alert to
    /// notify about, if any.
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
        self.new_day(now);
        if !self.load(&key, app, store, now) {
            return Vec::new();
        }
        let local_day = self.local_day(now);
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

        let row = &mut profile.stored.row;
        if row.last_active_day.is_none_or(|day| local_day > day) {
            row.active_days = row.active_days.saturating_add(1);
            row.last_active_day = Some(local_day);
        }
        row.last_data = row.last_data.max(now);

        let mut reasons = Vec::new();
        let mut seen_pending = Vec::new();
        if !profile.is_learning(now) {
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
            // A pending value is not raised again: it counts on its alert.
            for &(kind, value) in &values {
                if profile.pending(kind, value) {
                    seen_pending.push((kind, value.to_owned()));
                }
            }
            reasons.extend(new.into_iter().filter(|r| {
                let kind = item_kind(r.signal);
                !matches!((kind, &r.value), (Some(kind), Some(value)) if profile.pending(kind, value))
            }));
            if self.toggles.is_on(Signal::RandomName)
                && let Some(domain) = flow.domain.filter(|d| !d.is_empty())
                && !profile.knows(ItemKind::Domain, domain)
                && !profile.pending(ItemKind::Domain, domain)
            {
                reasons.extend(signals::random_name(domain, enricher));
            }
            if self.toggles.is_on(Signal::BinaryChanged) {
                reasons.extend(signals::binary_changed(
                    profile,
                    app.sha256,
                    app.publisher,
                    app.signature_valid,
                    new_destination,
                ));
            }
        }

        let row = &mut profile.stored.row;
        if let Some(sha256) = app.sha256 {
            row.last_sha256 = Some(sha256.to_owned());
            row.last_publisher = app.publisher.map(str::to_owned);
        }
        if let Err(error) = store.save_profile_row(row) {
            self.errors
                .push(format!("could not save a behaviour profile: {error}"));
            return Vec::new();
        }

        let fresh = self.fresh(&key, reasons, store);
        // Destinations behind a medium-or-higher reason wait for the user.
        let waiting: Vec<ItemKind> = fresh
            .iter()
            .filter(|r| severity_of(r.signal) >= Severity::Medium)
            .filter_map(|r| item_kind(r.signal))
            .collect();
        let (alert_id, raised) = self.save_reasons(&key, app, fresh, store, now);

        let Some(profile) = self.profiles.get_mut(&key) else {
            return raised;
        };
        let seen_on_day = profile.stored.row.active_days;
        let mut items = Vec::with_capacity(values.len());
        for &(kind, value) in &values {
            let known = profile
                .stored
                .items
                .iter_mut()
                .find(|i| i.kind == kind && i.value == value);
            let item = match known {
                Some(item) => {
                    item.first_seen = item.first_seen.min(flow.first_seen);
                    item.last_seen = item.last_seen.max(flow.last_seen);
                    item.seen_on_day = item.seen_on_day.max(seen_on_day);
                    item.clone()
                }
                None => {
                    let state = match alert_id {
                        Some(id) if waiting.contains(&kind) => {
                            self.pending
                                .insert((key.clone(), kind, value.to_owned()), id);
                            ItemState::Pending
                        }
                        _ => ItemState::Learned,
                    };
                    let item = ProfileItem {
                        kind,
                        value: value.to_owned(),
                        first_seen: flow.first_seen,
                        last_seen: flow.last_seen,
                        seen_on_day,
                        state,
                    };
                    profile.stored.items.push(item.clone());
                    item
                }
            };
            items.push(item);
        }
        if let Err(error) = store.save_items(&key, &items) {
            self.errors
                .push(format!("could not save a behaviour profile: {error}"));
        }

        self.count_seen_again(&key, &seen_pending, store, now);
        raised
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
                Some(profile) => store.save_profile_row(&profile.stored.row),
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
                let hours = &mut profile.stored.hours;
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

    /// Forgets what is held about an app's profile, after it was reset or
    /// its goes-anywhere choice changed, so it is read again from the store.
    /// Traffic not yet written is kept.
    pub fn forget(&mut self, key: &str) {
        self.profiles.remove(key);
        if let Some(window) = self.windows.remove(key) {
            self.seen_again.remove(&window.id);
        }
        self.pending.retain(|(app, _, _), id| {
            let keep = app != key;
            if !keep {
                self.seen_again.remove(id);
            }
            keep
        });
        self.time_checked.remove(key);
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

    /// Starts a new day of reasons at local midnight.
    fn new_day(&mut self, now: SystemTime) {
        let day = self.local_day(now);
        if self.day != Some(day) {
            self.day = Some(day);
            self.raised_today.clear();
        }
    }

    /// Makes sure the app's profile is cached: read from the store, or
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
        self.profiles.insert(key.to_owned(), Profile { stored });
        true
    }

    /// Bytes sent and received in `hour` so far: what is in memory plus what
    /// an earlier run already wrote for the same hour.
    fn running_total(&self, key: &str, profile: &Profile, hour: i64) -> (u64, u64) {
        let memory = self.hours.get(&(key.to_owned(), hour));
        let stored = profile.stored.hours.iter().find(|h| h.hour == hour);
        [memory, stored]
            .into_iter()
            .flatten()
            .fold((0u64, 0u64), |(sent, received), h| {
                (
                    sent.saturating_add(h.bytes_sent),
                    received.saturating_add(h.bytes_received),
                )
            })
    }

    /// Drops reasons already raised today for this app, and those the user
    /// allowed ("this is fine" on beaconing, a random-looking name or an
    /// unusual hour). The rest count as raised today.
    fn fresh(&mut self, key: &str, reasons: Vec<Reason>, store: &Store) -> Vec<Reason> {
        let mut fresh = Vec::new();
        for reason in reasons {
            let today = (
                key.to_owned(),
                reason.signal,
                reason.value.clone().unwrap_or_default(),
            );
            if self.raised_today.contains(&today) {
                continue;
            }
            if let Some(allow) = allow_key(key, &reason) {
                match store.is_allowed(&allow) {
                    Ok(false) => {}
                    Ok(true) => continue,
                    Err(error) => {
                        self.errors
                            .push(format!("could not read alert allows: {error}"));
                        continue;
                    }
                }
            }
            self.raised_today.insert(today);
            fresh.push(reason);
        }
        fresh
    }

    /// Saves reasons as a behaviour alert: they update the app's open alert
    /// if its window is still open, otherwise they open a new one. Returns
    /// the alert's ID, and the alert if it is new (and above info) or its
    /// severity went up.
    fn save_reasons(
        &mut self,
        key: &str,
        app: &AppFacts<'_>,
        reasons: Vec<Reason>,
        store: &mut Store,
        now: SystemTime,
    ) -> (Option<i64>, Vec<Raised>) {
        let Some(first) = reasons.first() else {
            return (None, Vec::new());
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
            let seen_again = self.seen_again.get(&window.id).copied().unwrap_or(0);
            match store.update_alert(window.id, &reasons, severity, seen_again, now) {
                Ok(true) => {
                    let raised = severity > window.alert.severity;
                    window.alert.reasons = merged;
                    window.alert.severity = severity;
                    let raised = raised.then(|| Raised {
                        id: window.id,
                        alert: window.alert.clone(),
                    });
                    return (Some(window.id), raised.into_iter().collect());
                }
                // The alert is gone (all data deleted): open a new one.
                Ok(false) => {}
                Err(error) => {
                    self.errors
                        .push(format!("could not update an alert: {error}"));
                    return (None, Vec::new());
                }
            }
        }

        let allow_key = allow_key(key, first);
        let target = first.value.clone();
        let alert = NewAlert {
            key: format!("behaviour|{key}|{secs}"),
            allow_key,
            kind: AlertKind::Behaviour,
            severity: combined(&reasons),
            app_name: Some(app.app_name.to_owned()),
            app_path: Some(app.path.to_owned()),
            target,
            detail: None,
            reasons,
        };
        match store.add_alert(&alert, now) {
            Ok(Some(id)) => {
                let notify = alert.severity > Severity::Info;
                self.windows.insert(
                    key.to_owned(),
                    Window {
                        start: secs,
                        id,
                        alert: alert.clone(),
                    },
                );
                let raised = notify.then_some(Raised { id, alert });
                (Some(id), raised.into_iter().collect())
            }
            Ok(None) => (None, Vec::new()),
            Err(error) => {
                self.errors
                    .push(format!("could not save an alert: {error}"));
                (None, Vec::new())
            }
        }
    }

    /// Counts a sighting of pending destinations on the alerts that named
    /// them (once per alert). Alerts from before a restart are not known.
    fn count_seen_again(
        &mut self,
        key: &str,
        seen: &[(ItemKind, String)],
        store: &mut Store,
        now: SystemTime,
    ) {
        let mut ids: Vec<i64> = seen
            .iter()
            .filter_map(|(kind, value)| {
                self.pending
                    .get(&(key.to_owned(), *kind, value.clone()))
                    .copied()
            })
            .collect();
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            let count = self.seen_again.entry(id).or_insert(0);
            *count = count.saturating_add(1);
            // Info never lowers a severity: only the count changes.
            match store.update_alert(id, &[], Severity::Info, *count, now) {
                Ok(true) => {}
                Ok(false) => {
                    self.pending.retain(|_, alert| *alert != id);
                    self.seen_again.remove(&id);
                }
                Err(error) => self
                    .errors
                    .push(format!("could not update an alert: {error}")),
            }
        }
    }
}

/// The profile item a destination signal is about.
fn item_kind(signal: Signal) -> Option<ItemKind> {
    match signal {
        Signal::NewSite | Signal::RandomName => Some(ItemKind::Domain),
        Signal::NewCompany => Some(ItemKind::Company),
        Signal::NewCountry => Some(ItemKind::Country),
        _ => None,
    }
}

/// The lasting "this is fine" key for a reason, for the signals that have
/// one (beaconing, random-looking name, unusual time).
fn allow_key(key: &str, reason: &Reason) -> Option<String> {
    let allowable = matches!(
        reason.signal,
        Signal::Beaconing | Signal::RandomName | Signal::UnusualTime
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

/// The profile as history for checking `hour`: its hours without that one
/// (destinations are not needed).
fn history_without(profile: &Profile, hour: i64) -> Profile {
    Profile {
        stored: StoredProfile {
            row: profile.stored.row.clone(),
            items: Vec::new(),
            hours: profile
                .stored
                .hours
                .iter()
                .filter(|h| h.hour != hour)
                .cloned()
                .collect(),
        },
    }
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
