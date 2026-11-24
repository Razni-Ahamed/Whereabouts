//! Feeds the behaviour Learner (Layer 2, design spec v0.3) from the live
//! engine: each tick's traffic, finished flows, the hourly write and the
//! first turning of saved history into profiles.
//!
//! Only flows whose program file is known are learned: the profile is the
//! program's, found by its path. The engine calls [`Learning::tick`] once per
//! refresh, [`Learning::traffic`] with every row it shows,
//! [`Learning::finished`] once for each finished flow, and
//! [`Learning::shutdown`] when it stops. Nothing is learned until the saved
//! history has been turned into profiles (it reads every saved flow, so a
//! flow learned live before then could be counted twice).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use whereabouts_core::dns::LabelSource;
use whereabouts_core::flow::{FlowKey, FlowStats};
use whereabouts_core::model::{AppIdentity, Signature};
use whereabouts_detect::learner::{AppFacts, Finished, Learner};
use whereabouts_detect::meter::{Delta, FlowSample, Meter};
use whereabouts_enrich::{Enricher, Scope};
use whereabouts_store::{Store, known_app_key};

use crate::alerts::Raised;

/// Saved flows turned into profiles per tick while catching up.
const BACKFILL_BATCH: usize = 5_000;
/// How often the local time zone's offset is checked again (it changes with
/// daylight saving time, or when the user travels).
const OFFSET_EVERY: Duration = Duration::from_secs(15 * 60);
/// On shutdown, hours are written as if this much later, so the hour still
/// running is written too.
const HOUR: Duration = Duration::from_secs(3_600);

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
    /// Whether the saved history has been turned into profiles: until then
    /// the Learner is given nothing.
    ready: bool,
    /// Whether the last attempt to catch up failed (reported once).
    backfill_failing: bool,
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
            ready: false,
            backfill_failing: false,
            backfilled: 0,
            offset_secs,
            offset_checked: Instant::now(),
            hour: None,
            installed: HashMap::new(),
        }
    }

    /// Housekeeping, once per refresh: catches up with the saved history
    /// (a batch at a time), checks the time zone every 15 minutes, and
    /// writes the hours that ended.
    pub fn tick(&mut self, store: &mut Store, now: SystemTime) {
        if self.offset_checked.elapsed() >= OFFSET_EVERY {
            self.offset_secs = crate::clock::local_offset_secs(now);
            self.learner.set_local_offset(self.offset_secs);
            self.offset_checked = Instant::now();
        }
        if !self.ready {
            self.catch_up(store);
        }
        let hour = unix_hour(now);
        if self.hour.is_some_and(|last| last != hour)
            && let Err(error) = self.learner.flush(store, now)
        {
            report!("warning: could not save behaviour profiles: {error}");
        }
        self.hour = Some(hour);
    }

    /// Turns the next batch of saved flows into profiles. An error is
    /// reported once and tried again next tick; detection keeps running.
    fn catch_up(&mut self, store: &mut Store) {
        match store.backfill_profiles(BACKFILL_BATCH, self.offset_secs) {
            Ok(progress) => {
                self.backfill_failing = false;
                self.backfilled = self.backfilled.saturating_add(progress.flows_read);
                if progress.done {
                    self.ready = true;
                    if self.backfilled > 0 {
                        println!(
                            "Behaviour profiles: learned from {} saved flows",
                            self.backfilled
                        );
                    }
                }
            }
            Err(error) => {
                if !self.backfill_failing {
                    report!(
                        "warning: could not learn from the saved history yet (will keep \
                         trying): {error}"
                    );
                }
                self.backfill_failing = true;
            }
        }
    }

    /// Adds what the shown flows did since the last tick to their apps'
    /// hours, and returns the alerts that raised. Each flow is counted once
    /// per tick: rows with the same key (a flow that finished and started
    /// again) are added together.
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
        for flow in flows.iter().filter(|flow| !flow.key.is_overflow()) {
            let Some(identity) = program(flow) else {
                continue;
            };
            let app_key = known_app_key(&identity.path);
            match at.get(&flow.key).map(|&index| &mut samples[index]) {
                Some(sample) if sample.app_key == app_key => {
                    sample.bytes_sent = sample.bytes_sent.saturating_add(flow.stats.bytes_sent);
                    sample.bytes_received = sample
                        .bytes_received
                        .saturating_add(flow.stats.bytes_received);
                    sample.connections = sample.connections.saturating_add(flow.stats.connections);
                    if sample.destination.is_none() {
                        sample.destination = confirmed_domain(flow.stats);
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
                        destination: confirmed_domain(flow.stats),
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
        if !self.ready {
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
    /// returns the alerts that raised. Call it once per flow.
    pub fn finished(
        &mut self,
        flow: &FlowInput<'_>,
        enricher: &Enricher,
        store: &mut Store,
        now: SystemTime,
    ) -> Vec<Raised> {
        if !self.ready || flow.key.is_overflow() {
            return Vec::new();
        }
        let Some(identity) = program(flow) else {
            return Vec::new();
        };
        let installed = self.installed_by_admins(identity);
        let domain = confirmed_domain(flow.stats);
        // The network's owner and country come from the IP address itself;
        // local and multicast addresses have neither.
        let ip = enricher.ip(flow.key.remote.ip());
        let (company, country) = match ip.scope {
            Scope::Internet => (ip.network, ip.country),
            Scope::Local | Scope::Multicast => (None, None),
        };
        let finished = Finished {
            app: app_facts(flow.app, identity, installed),
            domain: domain.as_deref(),
            company: company.as_deref(),
            country: country.as_deref(),
            port: flow.key.remote.port(),
            first_seen: flow.stats.first_seen,
            last_seen: flow.stats.last_seen,
        };
        let raised = self.learner.finished(&finished, enricher, store, now);
        self.report_errors();
        raised
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
        let later = now.checked_add(HOUR).unwrap_or(now);
        if let Err(error) = self.learner.flush(store, later) {
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

/// The registrable domain of the flow's name, only if the name was
/// confirmed (not one only the app itself reported, which could be false).
fn confirmed_domain(stats: &FlowStats) -> Option<String> {
    stats
        .domain
        .as_ref()
        .filter(|label| label.source != LabelSource::Unverified)
        .and_then(|label| whereabouts_enrich::registrable_domain(&label.name))
}

fn app_facts<'a>(app: &'a str, identity: &'a AppIdentity, installed: bool) -> AppFacts<'a> {
    let publisher = match &identity.signature {
        Signature::Signed { publisher, .. } => Some(publisher.as_str()),
        Signature::Unsigned | Signature::Invalid { .. } | Signature::Unknown => None,
    };
    AppFacts {
        app_name: app,
        path: &identity.path,
        sha256: identity.sha256.as_deref(),
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
