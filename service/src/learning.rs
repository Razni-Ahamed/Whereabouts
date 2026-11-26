//! Feeds the behaviour Learner (Layer 2, design spec v0.3) from the live
//! engine: each tick's traffic, finished flows, the hourly write, ageing out
//! and the first turning of saved history into profiles.
//!
//! Only flows whose program file is known are learned: the profile is the
//! program's, found by its path. The engine calls [`Learning::tick`] once per
//! refresh, [`Learning::traffic`] with every row it shows,
//! [`Learning::finished`] once for each finished flow, and
//! [`Learning::shutdown`] when it stops. Nothing is learned until the saved
//! history has been turned into profiles (it reads every saved flow, so a
//! flow learned live before then could be counted twice).
//!
//! What a profile learns about where a flow went has one rule,
//! [`destination_facts`], used for live flows, saved history and the lab's
//! replay alike.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use whereabouts_core::flow::{FlowKey, FlowStats};
use whereabouts_core::model::{AppIdentity, Signature};
use whereabouts_detect::destination::{confirmed_domain, destination_facts};
use whereabouts_detect::learner::{AppFacts, Finished, Learner};
use whereabouts_detect::meter::{Delta, FlowSample, Meter};
use whereabouts_enrich::Enricher;
use whereabouts_store::{AlertKind, GoesAnywhere, Store, known_app_key};

use crate::alerts::Raised;

/// Saved flows turned into profiles per tick while catching up.
const BACKFILL_BATCH: usize = 5_000;
/// After catching up failed, how long until it is tried again.
const BACKFILL_RETRY: Duration = crate::console::RETENTION_EVERY;
/// How often the local time zone's offset is checked again (it changes with
/// daylight saving time, or when the user travels).
const OFFSET_EVERY: Duration = Duration::from_secs(15 * 60);
/// On shutdown, hours are written as if this much later, so the hour still
/// running is written too.
const HOUR: Duration = Duration::from_secs(3_600);

/// How far turning the saved history into profiles has got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackfillState {
    /// Still reading saved flows, a batch per tick; nothing is learned live.
    Running,
    /// Done: learning from live traffic.
    Done,
    /// The last attempt failed with this error; it is tried again later.
    Failed(String),
}

/// A change to the behaviour profiles that the user asked for. The engine
/// makes it, so the Learner's cached profiles and alerts stay in step with
/// the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BehaviourCommand {
    /// Forget what was learned about an app (by its key); it learns again.
    Reset {
        /// The app's key (`known_app_key` of its path).
        key: String,
    },
    /// Set whether an app is expected to go anywhere.
    SetGoesAnywhere {
        /// The app's key (`known_app_key` of its path).
        key: String,
        /// The user's choice.
        value: GoesAnywhere,
    },
    /// Close a behaviour alert: dismiss it, or with `allow` ("this is
    /// fine") also allow the destinations it named.
    CloseAlert {
        /// The alert's ID.
        id: i64,
        /// "This is fine".
        allow: bool,
    },
}

/// One flow as the engine shows it.
#[derive(Debug, Clone, Copy)]
pub struct FlowInput<'a> {
    /// The flow's key (process, protocol, remote end).
    pub key: FlowKey,
    /// The app's name as shown.
    pub app: &'a str,
    /// The program's identity, once checked; flows without one are skipped.
    pub identity: Option<&'a AppIdentity>,
    /// The flow's totals and domain.
    pub stats: &'a FlowStats,
}

/// The Learner and what the engine keeps for it.
#[derive(Debug)]
pub struct Learning {
    learner: Learner,
    meter: Meter,
    /// Until this is `Done`, the Learner is given nothing.
    backfill: BackfillState,
    /// After a failure, when to try catching up again.
    retry_at: Option<Instant>,
    /// Saved flows read while catching up.
    backfilled: u64,
    /// The local time zone's offset from UTC, and when it was checked.
    offset_secs: i32,
    offset_checked: Instant,
    /// The Unix hour of the last tick, to write hours as they end.
    hour: Option<i64>,
    /// Whether each program file, by path and SHA-256, was installed by
    /// administrators, so the file is not opened for every flow on every
    /// tick. Bounded like the engine's identity cache.
    installed: HashMap<(String, Option<String>), bool>,
}

impl Learning {
    /// Learning that has not yet caught up with the saved history.
    pub fn new(now: SystemTime) -> Self {
        let offset_secs = crate::clock::local_offset_secs(now);
        Self {
            learner: crate::alerts::new_learner(offset_secs),
            meter: Meter::default(),
            backfill: BackfillState::Running,
            retry_at: None,
            backfilled: 0,
            offset_secs,
            offset_checked: Instant::now(),
            hour: None,
            installed: HashMap::new(),
        }
    }

    /// How far turning the saved history into profiles has got.
    pub fn backfill_state(&self) -> &BackfillState {
        &self.backfill
    }

    /// The state of learning for clients' status: `starting`, `ready`, or
    /// `paused: ` and the error.
    pub fn status_text(&self) -> String {
        match self.backfill_state() {
            BackfillState::Running => String::from("starting"),
            BackfillState::Done => String::from("ready"),
            BackfillState::Failed(error) => format!("paused: {error}"),
        }
    }

    /// Makes a change the user asked for (`store` is `None` when nothing
    /// can be saved). `Ok(false)` if there is no such profile or alert.
    /// Refused until the saved history has been turned into profiles:
    /// before then, a reset profile would fill up again from history.
    pub fn answer(
        &mut self,
        store: Option<&mut Store>,
        command: BehaviourCommand,
        now: SystemTime,
    ) -> Result<bool, String> {
        let Some(store) = store else {
            return Err(String::from(
                "Whereabouts can't save anything right now, so it has no behaviour profiles",
            ));
        };
        match &self.backfill {
            BackfillState::Done => {}
            BackfillState::Running => {
                return Err(String::from(
                    "Whereabouts is still learning from the saved history; try again in a minute",
                ));
            }
            BackfillState::Failed(error) => {
                return Err(format!("learning behaviour is paused: {error}"));
            }
        }
        let result = match command {
            BehaviourCommand::Reset { key } => self.learner.reset(store, &key, now),
            BehaviourCommand::SetGoesAnywhere { key, value } => {
                self.learner.set_goes_anywhere(store, &key, value)
            }
            BehaviourCommand::CloseAlert { id, allow } => self.close_alert(store, id, allow, now),
        };
        result.map_err(|error| error.to_string())
    }

    /// Tells the Learner about a closed behaviour alert, then marks it seen
    /// (and saves its allow key with `allow`). If the Learner's change
    /// fails, the alert is not marked seen. "This is fine" on an alert from
    /// before its profile was reset only marks it seen: what it named was
    /// forgotten with the profile.
    fn close_alert(
        &mut self,
        store: &mut Store,
        id: i64,
        allow: bool,
        now: SystemTime,
    ) -> Result<bool, whereabouts_store::StoreError> {
        let Some(alert) = store
            .alert(id)?
            .filter(|alert| alert.kind == AlertKind::Behaviour)
        else {
            return Ok(false);
        };
        let reset_since = match alert.app_path.as_deref() {
            Some(path) => store
                .profile(&known_app_key(path))?
                .and_then(|profile| profile.row.reset_at)
                .is_some_and(|reset| reset > alert.created),
            None => false,
        };
        let allow = allow && !reset_since;
        // The profile first: if it cannot be changed, the alert stays
        // unseen, so the user sees it and can answer again (marked seen, a
        // destination still linked to it would count on a hidden alert).
        self.learner.alert_closed(store, id, allow, now)?;
        store.dismiss_alert(id, allow, now)
    }

    fn ready(&self) -> bool {
        self.backfill == BackfillState::Done
    }

    /// Housekeeping, once per refresh: catches up with the saved history
    /// (a batch at a time), checks the time zone every 15 minutes, and
    /// writes the hours that ended.
    pub fn tick(&mut self, store: &mut Store, enricher: &Enricher, now: SystemTime) {
        if self.offset_checked.elapsed() >= OFFSET_EVERY {
            self.offset_secs = crate::clock::local_offset_secs(now);
            self.learner.set_local_offset(self.offset_secs);
            self.offset_checked = Instant::now();
        }
        if !self.ready() {
            self.catch_up(store, enricher);
        }
        let hour = unix_hour(now);
        if self.hour.is_some_and(|last| last != hour) {
            self.flush(store, now);
        }
        self.hour = Some(hour);
    }

    /// Turns the next batch of saved flows into profiles. After an error,
    /// it is tried again an hour later; detection keeps running meanwhile.
    fn catch_up(&mut self, store: &mut Store, enricher: &Enricher) {
        if self.retry_at.is_some_and(|at| Instant::now() < at) {
            return;
        }
        let facts = |flow: &whereabouts_store::BackfillFlow<'_>| {
            destination_facts(flow.remote_ip, flow.domain, flow.domain_source, enricher)
        };
        match store.backfill_profiles(BACKFILL_BATCH, self.offset_secs, facts) {
            Ok(progress) => {
                self.retry_at = None;
                self.backfilled = self.backfilled.saturating_add(progress.flows_read);
                if progress.done {
                    self.backfill = BackfillState::Done;
                    if self.backfilled > 0 {
                        println!(
                            "Behaviour profiles: learned from {} saved flows",
                            self.backfilled
                        );
                    }
                } else {
                    self.backfill = BackfillState::Running;
                }
            }
            Err(error) => {
                report!(
                    "warning: could not learn from the saved history yet (trying again in an \
                     hour): {error}"
                );
                self.backfill = BackfillState::Failed(error.to_string());
                self.retry_at = Some(Instant::now() + BACKFILL_RETRY);
            }
        }
    }

    /// Adds what the shown flows did since the last tick to their apps'
    /// hours, and returns the alerts that raised. Each flow is counted once
    /// per tick: rows with the same key (a flow that finished and started
    /// again) are added together. A process's flow-limit overflow counts
    /// too (so many flows cannot hide an upload), with no destination.
    pub fn traffic(
        &mut self,
        flows: &[FlowInput<'_>],
        enricher: &Enricher,
        store: &mut Store,
        now: SystemTime,
    ) -> Vec<Raised> {
        let mut samples: Vec<FlowSample> = Vec::new();
        let mut at: HashMap<FlowKey, usize> = HashMap::new();
        // The first flow seen for each app supplies its facts.
        let mut apps: HashMap<String, (&FlowInput<'_>, &AppIdentity)> = HashMap::new();
        for flow in flows {
            let Some(identity) = program(flow) else {
                continue;
            };
            let app_key = known_app_key(&identity.path);
            let destination = if flow.key.is_overflow() {
                None
            } else {
                flow_domain(flow.stats)
            };
            match at.get(&flow.key).map(|&index| &mut samples[index]) {
                Some(sample) if sample.app_key == app_key => {
                    sample.bytes_sent = sample.bytes_sent.saturating_add(flow.stats.bytes_sent);
                    sample.bytes_received = sample
                        .bytes_received
                        .saturating_add(flow.stats.bytes_received);
                    sample.connections = sample.connections.saturating_add(flow.stats.connections);
                    if sample.destination.is_none() {
                        sample.destination = destination;
                    }
                }
                // The same key for another program (a reused process ID):
                // the first one counts.
                Some(_) => {}
                None => {
                    at.insert(flow.key, samples.len());
                    samples.push(FlowSample {
                        key: flow.key,
                        app_key: app_key.clone(),
                        destination,
                        bytes_sent: flow.stats.bytes_sent,
                        bytes_received: flow.stats.bytes_received,
                        connections: flow.stats.connections,
                    });
                }
            }
            apps.entry(app_key).or_insert((flow, identity));
        }

        // The meter keeps up while catching up, so traffic from before
        // learning started is not counted afterwards.
        let deltas = self.meter.sample(now, &samples);
        if !self.ready() {
            return Vec::new();
        }
        let mut by_app: BTreeMap<String, Vec<Delta>> = BTreeMap::new();
        for delta in deltas {
            by_app.entry(delta.app_key.clone()).or_default().push(delta);
        }
        let mut raised = Vec::new();
        for (app_key, deltas) in by_app {
            let Some(&(flow, identity)) = apps.get(&app_key) else {
                continue;
            };
            let installed = self.installed_by_admins(identity);
            let facts = app_facts(flow.app, identity, installed);
            raised.extend(self.learner.traffic(&facts, &deltas, enricher, store, now));
        }
        self.report_errors();
        raised
    }

    /// Adds a finished flow's destinations to its app's profile, and
    /// returns the alerts that raised. Call it once per flow. The flow-limit
    /// overflow went to many places, so nothing is learned from it.
    pub fn finished(
        &mut self,
        flow: &FlowInput<'_>,
        enricher: &Enricher,
        store: &mut Store,
        now: SystemTime,
    ) -> Vec<Raised> {
        if !self.ready() || flow.key.is_overflow() {
            return Vec::new();
        }
        let Some(identity) = program(flow) else {
            return Vec::new();
        };
        let installed = self.installed_by_admins(identity);
        let label = flow.stats.domain.as_ref();
        let facts = destination_facts(
            flow.key.remote.ip(),
            label.map(|label| label.name.as_ref()),
            label.map(|label| label.source),
            enricher,
        );
        let finished = Finished {
            app: app_facts(flow.app, identity, installed),
            domain: facts.domain.as_deref(),
            company: facts.company.as_deref(),
            country: facts.country.as_deref(),
            port: flow.key.remote.port(),
            first_seen: flow.stats.first_seen,
            last_seen: flow.stats.last_seen,
        };
        let raised = self.learner.finished(&finished, enricher, store, now);
        self.report_errors();
        raised
    }

    /// Ages out what is old in the stored profiles. If anything went, the
    /// hours that ended are written and the cached profiles are read again
    /// when next needed, so what was deleted is not still counted as known.
    pub fn expire(&mut self, store: &mut Store, now: SystemTime) {
        let expiry = crate::storage::expire_profiles(store, now);
        if expiry.profiles > 0 || expiry.items > 0 || expiry.hours > 0 {
            self.flush(store, now);
            self.learner.drop_profiles();
        }
    }

    /// Starts over after "Delete everything": the profiles the Learner held
    /// are gone from the store, so it forgets them too. Traffic already
    /// counted is not counted again.
    pub fn reset(&mut self) {
        self.learner = crate::alerts::new_learner(self.offset_secs);
    }

    /// Writes everything held, including the hour still running (call it
    /// when the engine stops).
    pub fn shutdown(&mut self, store: &mut Store, now: SystemTime) {
        self.flush(store, now.checked_add(HOUR).unwrap_or(now));
    }

    /// Writes the hours that ended before `now`.
    fn flush(&mut self, store: &mut Store, now: SystemTime) {
        if let Err(error) = self.learner.flush(store, now) {
            report!("warning: could not save behaviour profiles: {error}");
        }
    }

    /// Whether the program file is in a place only administrators can
    /// change. Checked once per path and version (SHA-256), so a changed
    /// file is checked again; an error counts as no.
    fn installed_by_admins(&mut self, identity: &AppIdentity) -> bool {
        let key = (identity.path.clone(), identity.sha256.clone());
        if let Some(&by_admins) = self.installed.get(&key) {
            return by_admins;
        }
        if self.installed.len() >= crate::console::MAX_IDENTITIES {
            self.installed.clear();
        }
        let by_admins =
            whereabouts_win_secrets::installed_by_administrators(Path::new(&identity.path))
                .unwrap_or(false);
        self.installed.insert(key, by_admins);
        by_admins
    }

    fn report_errors(&mut self) {
        for error in self.learner.take_errors() {
            report!("warning: {error}");
        }
    }
}

/// The flow's program identity, if it has a program path.
fn program<'a>(flow: &FlowInput<'a>) -> Option<&'a AppIdentity> {
    flow.identity.filter(|identity| !identity.path.is_empty())
}

/// The flow's confirmed registrable domain (see [`destination_facts`]).
fn flow_domain(stats: &FlowStats) -> Option<String> {
    let label = stats.domain.as_ref()?;
    confirmed_domain(Some(&label.name), Some(label.source))
}

/// What the Learner is told about the program. When its signature could not
/// be checked, its file hash is left out too: the Learner then neither
/// compares the file with the profile's (no publisher would look like a lost
/// signature) nor saves it as the profile's last known file.
fn app_facts<'a>(app: &'a str, identity: &'a AppIdentity, installed: bool) -> AppFacts<'a> {
    let publisher = match &identity.signature {
        Signature::Signed { publisher, .. } => Some(publisher.as_str()),
        Signature::Unsigned | Signature::Invalid { .. } | Signature::Unknown => None,
    };
    let checked = !matches!(identity.signature, Signature::Unknown);
    AppFacts {
        app_name: app,
        path: &identity.path,
        sha256: identity.sha256.as_deref().filter(|_| checked),
        publisher,
        signature_valid: publisher.is_some(),
        installed_by_admins: installed,
    }
}

/// Hours since the Unix epoch (0 before it), as the meter counts them.
fn unix_hour(time: SystemTime) -> i64 {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    i64::try_from(secs / 3_600).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use whereabouts_core::dns::{DomainLabel, LabelSource};
    use whereabouts_core::model::Protocol;
    use whereabouts_enrich::{CompanyList, GeoDatabases, TrackerList};
    use whereabouts_store::{BACKFILL_SETTING, ItemKind, Key};

    const PATH: &str = r"C:\Apps\chat.exe";
    /// 2027-01-15 08:00 UTC, on the hour.
    const T0: u64 = 1_800_000_000;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn enricher() -> Enricher {
        Enricher::from_parts(
            TrackerList::parse(""),
            CompanyList::built_in(),
            GeoDatabases::default(),
        )
    }

    fn temp_store(name: &str) -> (Store, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "whereabouts-learning-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = Key::from_bytes([6; 32]);
        (Store::open(&dir.join("t.db"), &key).unwrap(), dir)
    }

    fn identity() -> AppIdentity {
        AppIdentity {
            path: PATH.to_owned(),
            signature: Signature::Unsigned,
            sha256: Some("cd".repeat(32)),
            size: Some(1_000),
            package_family_name: None,
            confirmed_running: true,
        }
    }

    fn stats(domain: Option<(&str, LabelSource)>, sent: u64) -> FlowStats {
        let mut stats = FlowStats::new(at(T0));
        stats.domain = domain.map(|(name, source)| DomainLabel::new(name, source));
        stats.bytes_sent = sent;
        stats.connections = 1;
        stats
    }

    fn key(remote: &str) -> FlowKey {
        FlowKey {
            pid: 40,
            protocol: Protocol::Tcp,
            remote: remote.parse().unwrap(),
        }
    }

    fn input<'a>(key: FlowKey, identity: &'a AppIdentity, stats: &'a FlowStats) -> FlowInput<'a> {
        FlowInput {
            key,
            app: "chat.exe",
            identity: Some(identity),
            stats,
        }
    }

    /// Learning that has caught up with the (empty) saved history.
    fn ready(store: &mut Store, now: SystemTime) -> Learning {
        let mut learning = Learning::new(now);
        learning.tick(store, &enricher(), now);
        assert_eq!(learning.backfill_state(), &BackfillState::Done);
        learning
    }

    fn profile(store: &Store) -> Option<whereabouts_store::StoredProfile> {
        store.profile(&known_app_key(PATH)).unwrap()
    }

    #[test]
    fn nothing_is_learned_before_the_history_is_caught_up() {
        let (mut store, dir) = temp_store("not-ready");
        let identity = identity();
        let flow = stats(Some(("chat.example", LabelSource::Verified)), 5_000);
        let row = input(key("203.0.113.9:443"), &identity, &flow);
        let e = enricher();
        let mut learning = Learning::new(at(T0));
        assert_eq!(learning.backfill_state(), &BackfillState::Running);
        assert!(learning.traffic(&[row], &e, &mut store, at(T0)).is_empty());
        assert!(learning.finished(&row, &e, &mut store, at(T0)).is_empty());
        learning.shutdown(&mut store, at(T0));
        assert!(store.profile_rows().unwrap().is_empty());
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_catch_up_waits_before_trying_again() {
        let (mut store, dir) = temp_store("retry");
        store
            .set_setting(BACKFILL_SETTING, "not a flow id")
            .unwrap();
        let e = enricher();
        let mut learning = Learning::new(at(T0));
        learning.tick(&mut store, &e, at(T0));
        assert!(matches!(
            learning.backfill_state(),
            BackfillState::Failed(_)
        ));
        // Fixed, but not tried again on the next tick.
        store.set_setting(BACKFILL_SETTING, "done").unwrap();
        learning.tick(&mut store, &e, at(T0 + 2));
        assert!(matches!(
            learning.backfill_state(),
            BackfillState::Failed(_)
        ));
        // Once the wait is over, it is.
        learning.retry_at = Some(Instant::now());
        learning.tick(&mut store, &e, at(T0 + 4));
        assert_eq!(learning.backfill_state(), &BackfillState::Done);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn user_changes_wait_for_the_history_to_be_caught_up() {
        let (mut store, dir) = temp_store("not-ready-answer");
        let reset = || BehaviourCommand::Reset {
            key: known_app_key(PATH),
        };
        let mut learning = Learning::new(at(T0));
        assert_eq!(learning.status_text(), "starting");
        let refused = learning.answer(Some(&mut store), reset(), at(T0));
        assert!(refused.unwrap_err().contains("still learning"));
        learning.backfill = BackfillState::Failed(String::from("disk full"));
        assert_eq!(learning.status_text(), "paused: disk full");
        assert!(learning.answer(Some(&mut store), reset(), at(T0)).is_err());
        // Nothing can be saved: no profiles to change.
        assert!(learning.answer(None, reset(), at(T0)).is_err());
        let mut learning = ready(&mut store, at(T0));
        assert_eq!(learning.status_text(), "ready");
        assert_eq!(
            learning.answer(Some(&mut store), reset(), at(T0)),
            Ok(false)
        );
        let close = BehaviourCommand::CloseAlert { id: 1, allow: true };
        assert_eq!(learning.answer(Some(&mut store), close, at(T0)), Ok(false));
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn overflow_bytes_are_counted_but_no_destination_is_learned() {
        let (mut store, dir) = temp_store("overflow");
        let identity = identity();
        let e = enricher();
        let mut learning = ready(&mut store, at(T0));
        let flow = stats(None, 7_000);
        let overflow = input(FlowKey::overflow(40, Protocol::Tcp), &identity, &flow);
        learning.traffic(&[overflow], &e, &mut store, at(T0 + 60));
        assert!(
            learning
                .finished(&overflow, &e, &mut store, at(T0 + 60))
                .is_empty()
        );
        learning.shutdown(&mut store, at(T0 + 60));
        let profile = profile(&store).expect("its bytes made a profile");
        assert!(profile.items.is_empty(), "{:?}", profile.items);
        assert_eq!(
            profile.hours.iter().map(|h| h.bytes_sent).sum::<u64>(),
            7_000
        );
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn hours_are_written_when_the_hour_changes() {
        let (mut store, dir) = temp_store("hour");
        let identity = identity();
        let e = enricher();
        let mut learning = ready(&mut store, at(T0 + 60));
        let flow = stats(Some(("chat.example", LabelSource::Verified)), 3_000);
        let row = input(key("203.0.113.9:443"), &identity, &flow);
        learning.traffic(&[row], &e, &mut store, at(T0 + 60));
        // Same hour: nothing written yet.
        learning.tick(&mut store, &e, at(T0 + 120));
        assert!(profile(&store).unwrap().hours.is_empty());
        // The next hour: the hour that ended is written.
        learning.tick(&mut store, &e, at(T0 + 3_600 + 5));
        let hours = profile(&store).unwrap().hours;
        assert_eq!(hours.len(), 1);
        assert_eq!(hours[0].bytes_sent, 3_000);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_signature_that_could_not_be_checked_is_not_a_changed_program() {
        use whereabouts_store::{GoesAnywhere, ProfileRow};
        let (mut store, dir) = temp_store("signature-unknown");
        // A signed program that finished learning long ago.
        let row = ProfileRow {
            key: known_app_key(PATH),
            path: PATH.to_owned(),
            app_name: String::from("chat.exe"),
            first_data: at(T0 - 30 * 86_400),
            learned_since: at(T0 - 30 * 86_400),
            last_data: at(T0 - 86_400),
            active_days: 20,
            last_active_day: None,
            last_sha256: Some("ab".repeat(32)),
            last_publisher: Some(String::from("Chat Inc")),
            goes_anywhere: GoesAnywhere::Auto,
            reset_at: None,
        };
        store.save_profile_row(&row).unwrap();
        let e = enricher();
        let mut learning = ready(&mut store, at(T0));
        // Its signature could not be checked this time, and it goes
        // somewhere new: not "lost its signature".
        let identity = AppIdentity {
            signature: Signature::Unknown,
            ..identity()
        };
        let flow = stats(Some(("new.example", LabelSource::Verified)), 10);
        let row_in = input(key("203.0.113.9:443"), &identity, &flow);
        let raised = learning.finished(&row_in, &e, &mut store, at(T0));
        assert!(raised.is_empty(), "{raised:?}");
        let kept = profile(&store).unwrap().row;
        assert_eq!(kept.last_sha256, row.last_sha256);
        assert_eq!(kept.last_publisher, row.last_publisher);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A finished profile of [`PATH`] with a pending random-looking domain,
    /// and the behaviour alert naming it (its ID).
    fn seed_pending_alert(store: &mut Store) -> i64 {
        use whereabouts_store::{
            GoesAnywhere, ItemState, NewAlert, ProfileItem, ProfileRow, Reason, Severity, Signal,
        };
        let app_key = known_app_key(PATH);
        let domain = "q7x9k2m4zt8w.example";
        store
            .save_profile_row(&ProfileRow {
                key: app_key.clone(),
                path: PATH.to_owned(),
                app_name: String::from("chat.exe"),
                first_data: at(T0 - 30 * 86_400),
                learned_since: at(T0 - 30 * 86_400),
                last_data: at(T0),
                active_days: 20,
                last_active_day: None,
                last_sha256: None,
                last_publisher: None,
                goes_anywhere: GoesAnywhere::Auto,
                reset_at: None,
            })
            .unwrap();
        store
            .save_items(
                &app_key,
                &[ProfileItem {
                    kind: ItemKind::Domain,
                    value: domain.to_owned(),
                    first_seen: at(T0),
                    last_seen: at(T0),
                    seen_on_day: 20,
                    state: ItemState::Pending,
                }],
            )
            .unwrap();
        let alert = NewAlert {
            key: format!("behaviour|{app_key}|{T0}"),
            allow_key: Some(format!("behaviour|{app_key}|random_name|{domain}")),
            kind: AlertKind::Behaviour,
            severity: Severity::Medium,
            app_name: Some(String::from("chat.exe")),
            app_path: Some(PATH.to_owned()),
            target: Some(domain.to_owned()),
            detail: None,
            reasons: vec![Reason {
                signal: Signal::RandomName,
                value: Some(domain.to_owned()),
                observed: None,
                usual: None,
                count: None,
            }],
        };
        store.add_alert(&alert, at(T0)).unwrap().unwrap()
    }

    #[test]
    fn a_failed_profile_change_leaves_the_alert_to_answer_again() {
        let (mut store, dir) = temp_store("close-fails");
        let id = seed_pending_alert(&mut store);
        // The store takes everything but the change to the profile's items.
        let raw = rusqlite::Connection::open(dir.join("t.db")).unwrap();
        raw.pragma_update(None, "key", format!("x'{}'", "06".repeat(32)))
            .unwrap();
        raw.execute_batch(
            "CREATE TRIGGER refuse BEFORE UPDATE ON profile_items \
             BEGIN SELECT RAISE(ABORT, 'refused by the test'); END;",
        )
        .unwrap();
        drop(raw);

        let mut learning = ready(&mut store, at(T0));
        let close = BehaviourCommand::CloseAlert { id, allow: true };
        let error = learning
            .answer(Some(&mut store), close, at(T0 + 60))
            .unwrap_err();
        assert!(error.contains("refused by the test"), "{error}");
        let alert = store.alert(id).unwrap().unwrap();
        assert!(!alert.dismissed, "still shown, so the user can try again");
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn closing_fails_when_the_alerts_cannot_be_read_back() {
        let (mut store, dir) = temp_store("relink-fails");
        let id = seed_pending_alert(&mut store);
        // Another alert of the app that cannot be read.
        let broken = whereabouts_store::NewAlert {
            key: String::from("behaviour|other"),
            allow_key: None,
            kind: AlertKind::Behaviour,
            severity: whereabouts_store::Severity::Info,
            app_name: Some(String::from("chat.exe")),
            app_path: Some(PATH.to_owned()),
            target: None,
            detail: None,
            reasons: Vec::new(),
        };
        let broken = store.add_alert(&broken, at(T0)).unwrap().unwrap();
        let raw = rusqlite::Connection::open(dir.join("t.db")).unwrap();
        raw.pragma_update(None, "key", format!("x'{}'", "06".repeat(32)))
            .unwrap();
        raw.execute("UPDATE alerts SET seen_again = -1 WHERE id = ?1", [broken])
            .unwrap();
        drop(raw);

        // The profile is first read on this path: its links cannot be read
        // back, so nothing would be allowed. The close fails instead.
        let mut learning = ready(&mut store, at(T0));
        let close = BehaviourCommand::CloseAlert { id, allow: true };
        assert!(
            learning
                .answer(Some(&mut store), close, at(T0 + 60))
                .is_err()
        );
        let alert = store.alert(id).unwrap().unwrap();
        assert!(!alert.dismissed, "still shown, so the user can try again");
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_finished_flow_teaches_its_confirmed_destination() {
        let (mut store, dir) = temp_store("finished");
        let identity = identity();
        let e = enricher();
        let mut learning = ready(&mut store, at(T0));
        let flow = stats(Some(("api.chat.example", LabelSource::Unverified)), 10);
        let row = input(key("192.168.1.20:8443"), &identity, &flow);
        learning.finished(&row, &e, &mut store, at(T0));
        let items: Vec<(ItemKind, String)> = profile(&store)
            .unwrap()
            .items
            .into_iter()
            .map(|item| (item.kind, item.value))
            .collect();
        // An app-reported name and a local address: only the port.
        assert_eq!(items, [(ItemKind::Port, String::from("8443"))]);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }
}
