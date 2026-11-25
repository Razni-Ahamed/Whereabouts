//! Runs a timeline through the shipped detection code, one simulated user at
//! a time, and reports every alert it saved, with whether the app would have
//! notified about it (the shared rule in `whereabouts_ipc::notify`).
//!
//! Layer 1 is the [`Detector`] (lists and health counters). With Layer 2,
//! each user also gets a behaviour [`Learner`] with every signal on, fed as
//! the service feeds it (`service/src/learning.rs`):
//!
//! - each flow's bytes are spread evenly over the UTC hours it spans (the
//!   remainder to the last hour) and sent as one traffic [`Delta`] per hour,
//!   at that hour's end (the last hour at the flow's last sighting);
//! - each flow then finishes, with what its profile learns about where it
//!   went from the same rule as the app ([`destination_facts`]);
//! - each connection line is one new connection, for beaconing;
//! - the hours that ended are written when a user's next event is in a new
//!   hour, and everything held is written after the user's last event.
//!
//! Everything happens in time order.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use whereabouts_core::dns::LabelSource;
use whereabouts_core::flow::FlowKey;
use whereabouts_core::model::Protocol;
use whereabouts_detect::destination::{confirmed_domain, destination_facts};
use whereabouts_detect::learner::{AppFacts, Finished, Learner};
use whereabouts_detect::meter::Delta;
use whereabouts_detect::signals::Toggles;
use whereabouts_detect::{Detector, FlowFacts};
use whereabouts_enrich::{DropList, Enricher, registrable_domain};
use whereabouts_ipc::notify::AlertLimiter;
use whereabouts_store::{AlertKind, Key, Severity, Store, known_app_key};

use crate::timeline::{ConnectionRow, CounterRow, FlowRow, Line};

const HOUR: u64 = 3_600;

/// Which detection layers the replay runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layers {
    /// Layer 1: lists and health counters.
    One,
    /// Layers 1 and 2: also behaviour profiles, with every signal on.
    OneAndTwo,
}

/// Whether a timeline of `schema` can be replayed through `layers`. Layer 2
/// needs schema 2: without signatures, browsers would lose their
/// goes-anywhere exemption and every new site would look suspicious.
pub fn check_layers(schema: u32, layers: Layers) -> Result<(), String> {
    if layers == Layers::OneAndTwo && schema < 2 {
        return Err(format!(
            "timeline schema {schema} has no signatures, which Layer 2 needs; build it again \
             with `lab timeline` (schema 2)"
        ));
    }
    Ok(())
}

/// One alert, as the lab's scoring reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AlertOut {
    pub user: String,
    /// When it was raised (Unix seconds, simulated time).
    pub time: u64,
    /// Which detection layer raised it: 2 for behaviour alerts, else 1.
    pub layer: u8,
    /// The store's spelling, e.g. `bad_network`.
    pub kind: String,
    /// The store's spelling, e.g. `high`.
    pub severity: String,
    pub app_name: Option<String>,
    pub app_path: Option<String>,
    pub target: Option<String>,
    pub detail: Option<String>,
    /// The signals behind it, each once (`upload_spike`, ...; empty for
    /// Layer 1).
    pub reasons: Vec<String>,
    /// Whether the app would push it as a Windows notification.
    pub notified: bool,
}

struct User {
    detector: Detector,
    store: Store,
    /// The behaviour Learner (Layer 2 only).
    learner: Option<Learner>,
    /// The Unix hour of the user's last event, to write hours as they end.
    hour: Option<u64>,
    /// The time of the user's last event.
    last: u64,
}

/// One thing that happens to a user, at a moment.
enum Step<'a> {
    /// Layer 1 checks a flow (when it starts).
    Check(&'a FlowRow, FlowKey),
    /// Layer 1 reads the health counters.
    Counters(&'a CounterRow),
    /// Layer 2: one hour's share of a flow's bytes.
    Traffic {
        row: &'a FlowRow,
        hour: u64,
        sent: u64,
        received: u64,
    },
    /// Layer 2: a flow finished (at its last sighting).
    Finished(&'a FlowRow, FlowKey),
    /// Layer 2: a connection was opened.
    Connection(&'a ConnectionRow),
}

impl Step<'_> {
    fn user(&self) -> &str {
        match self {
            Step::Check(row, _) | Step::Traffic { row, .. } | Step::Finished(row, _) => &row.user,
            Step::Counters(row) => &row.user,
            Step::Connection(row) => &row.user,
        }
    }
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn ipc_severity(severity: Severity) -> whereabouts_ipc::Severity {
    match severity {
        Severity::Info => whereabouts_ipc::Severity::Info,
        Severity::Medium => whereabouts_ipc::Severity::Medium,
        Severity::High => whereabouts_ipc::Severity::High,
        Severity::Critical => whereabouts_ipc::Severity::Critical,
    }
}

fn flow_key(row: &FlowRow, number: u32) -> Result<FlowKey, String> {
    let ip: IpAddr = row
        .remote_ip
        .parse()
        .map_err(|_| format!("flow {number}: bad address {:?}", row.remote_ip))?;
    let protocol = match row.protocol.as_str() {
        "TCP" => Protocol::Tcp,
        "UDP" => Protocol::Udp,
        other => return Err(format!("flow {number}: bad protocol {other:?}")),
    };
    // Each timeline row is its own flow: the row number stands in for the
    // process ID, which the export does not keep.
    Ok(FlowKey {
        pid: number,
        protocol,
        remote: SocketAddr::new(ip, row.remote_port),
    })
}

/// How the domain name was learned, from the export's spelling.
fn label_source(text: Option<&str>) -> Option<LabelSource> {
    match text? {
        "verified" => Some(LabelSource::Verified),
        "unverified" => Some(LabelSource::Unverified),
        "inferred" => Some(LabelSource::Inferred),
        _ => None,
    }
}

/// Whether the program is in a folder only administrators can change. The
/// lab cannot check who owns the runner's files after the fact, so it goes
/// by the usual install folders.
fn installed_by_admins(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        r"c:\program files\",
        r"c:\program files (x86)\",
        r"c:\windows\",
    ]
    .iter()
    .any(|folder| lower.starts_with(folder))
}

/// The program behind a flow, as the Learner sees it (`None` without a
/// program path: such flows are never profiled).
fn app_facts(row: &FlowRow) -> Option<AppFacts<'_>> {
    let path = row.app_path.as_deref().filter(|path| !path.is_empty())?;
    let signed = row.signature.as_deref() == Some("signed");
    // As the service does: a signature that could not be checked says
    // nothing about the file, so its hash is left out too.
    let checked = row.signature.as_deref() != Some("unknown");
    Some(AppFacts {
        app_name: &row.app_name,
        path,
        sha256: row.app_sha256.as_deref().filter(|_| checked),
        publisher: row.publisher.as_deref().filter(|_| signed),
        signature_valid: signed,
        installed_by_admins: installed_by_admins(path),
    })
}

/// The hours a flow spans, each with its share of the bytes (even shares,
/// the remainder to the last hour), and when that share is sent: the end of
/// its hour, or the flow's last sighting for the last hour. Shares with no
/// bytes are left out, as the service's meter leaves them out.
fn hourly_shares(row: &FlowRow) -> Vec<(u64, u64, u64, u64)> {
    let last_seen = row.last_seen.max(row.first_seen);
    let (first, last) = (row.first_seen / HOUR, last_seen / HOUR);
    let hours = last - first + 1;
    let (sent, received) = (row.bytes_sent / hours, row.bytes_received / hours);
    (first..=last)
        .map(|hour| {
            if hour == last {
                let extra = |total: u64, share: u64| total - share * (hours - 1);
                (
                    hour,
                    last_seen,
                    extra(row.bytes_sent, sent),
                    extra(row.bytes_received, received),
                )
            } else {
                (hour, hour * HOUR + HOUR - 1, sent, received)
            }
        })
        .filter(|&(_, _, sent, received)| sent > 0 || received > 0)
        .collect()
}

/// Turns the timeline's lines into steps, in time order (equal times keep
/// the lines' order, and a flow's traffic comes before it finishes).
fn steps(lines: &[Line], layers: Layers) -> Result<Vec<(u64, Step<'_>)>, String> {
    let layer2 = layers == Layers::OneAndTwo;
    let mut steps = Vec::new();
    let mut number: u32 = 0;
    for line in lines {
        match line {
            Line::Flow(row) => {
                number += 1;
                let key = flow_key(row, number)?;
                steps.push((row.first_seen, Step::Check(row, key)));
                if layer2 {
                    for (hour, time, sent, received) in hourly_shares(row) {
                        let traffic = Step::Traffic {
                            row,
                            hour,
                            sent,
                            received,
                        };
                        steps.push((time, traffic));
                    }
                    steps.push((row.last_seen.max(row.first_seen), Step::Finished(row, key)));
                }
            }
            Line::Counters(row) => steps.push((row.time, Step::Counters(row))),
            Line::Connection(row) if layer2 => steps.push((row.time, Step::Connection(row))),
            Line::Connection(_) | Line::Header { .. } => {}
        }
    }
    steps.sort_by_key(|(time, _)| *time);
    Ok(steps)
}

/// Replays `lines` (sorted, see [`crate::timeline::parse`]) through the
/// chosen layers. Each user gets a fresh detector (and Learner) and a
/// temporary encrypted store under `work_dir`, which is deleted afterwards.
/// Alerts come back in time order.
pub fn run(
    lines: &[Line],
    enricher: &Enricher,
    drop: Option<&DropList>,
    layers: Layers,
    work_dir: &Path,
) -> Result<Vec<AlertOut>, String> {
    std::fs::create_dir_all(work_dir).map_err(|e| format!("{}: {e}", work_dir.display()))?;
    let result = replay_users(lines, enricher, drop, layers, work_dir);
    let _ = std::fs::remove_dir_all(work_dir);
    result
}

fn open_user(drop: Option<&DropList>, layers: Layers, path: &Path) -> Result<User, String> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| e.to_string())?;
    let store = Store::open(path, &Key::from_bytes(key)).map_err(|e| e.to_string())?;
    let detector = drop.map_or_else(Detector::default, |list| Detector::with_drop(list.clone()));
    // Simulated time is UTC: the local offset is 0.
    let learner = (layers == Layers::OneAndTwo).then(|| Learner::new(Toggles::all_on(), 0));
    Ok(User {
        detector,
        store,
        learner,
        hour: None,
        last: 0,
    })
}

fn replay_users(
    lines: &[Line],
    enricher: &Enricher,
    drop: Option<&DropList>,
    layers: Layers,
    work_dir: &Path,
) -> Result<Vec<AlertOut>, String> {
    let mut users: BTreeMap<String, User> = BTreeMap::new();
    for (time, step) in steps(lines, layers)? {
        let name = step.user();
        if !users.contains_key(name) {
            let path = work_dir.join(format!("user-{}.db", users.len()));
            users.insert(name.to_owned(), open_user(drop, layers, &path)?);
        }
        let Some(user) = users.get_mut(name) else {
            continue;
        };
        apply(user, &step, time, enricher).map_err(|error| format!("user {name}: {error}"))?;
    }

    let mut alerts = Vec::new();
    for (name, user) in &mut users {
        if let Some(learner) = user.learner.as_mut() {
            // Everything held, including the hour still running.
            learner
                .flush(&mut user.store, at(user.last + HOUR))
                .map_err(|e| format!("user {name}: {e}"))?;
        }
        alerts.extend(user_alerts(name, &user.store)?);
    }
    alerts.sort_by(|a, b| (a.time, &a.user).cmp(&(b.time, &b.user)));
    Ok(alerts)
}

/// Runs one step for one user.
fn apply(user: &mut User, step: &Step<'_>, time: u64, enricher: &Enricher) -> Result<(), String> {
    let now = at(time);
    user.last = user.last.max(time);
    if let Some(learner) = user.learner.as_mut() {
        // As the service's tick: the hours that ended are written when a
        // new hour starts.
        let hour = time / HOUR;
        if user.hour.is_some_and(|last| last != hour) {
            learner
                .flush(&mut user.store, now)
                .map_err(|e| e.to_string())?;
        }
        user.hour = Some(hour);
    }
    match step {
        Step::Check(row, key) => {
            // As the service: a domain counts unless only the app itself
            // reported it.
            let domain = row
                .domain
                .as_deref()
                .filter(|_| row.domain_source.as_deref() != Some("unverified"));
            let facts = FlowFacts {
                key: *key,
                app: &row.app_name,
                path: row.app_path.as_deref(),
                domain,
                aliases: &[],
            };
            user.detector
                .check_flow(&facts, enricher, &mut user.store, now);
        }
        Step::Counters(row) => {
            user.detector
                .check_counters(row.rejected, row.unattributed, &mut user.store, now);
        }
        Step::Traffic {
            row,
            hour,
            sent,
            received,
        } => {
            if let (Some(learner), Some(app)) = (user.learner.as_mut(), app_facts(row)) {
                let destination = confirmed_domain(
                    row.domain.as_deref(),
                    label_source(row.domain_source.as_deref()),
                );
                let delta = Delta {
                    app_key: known_app_key(app.path),
                    destination,
                    hour: i64::try_from(*hour).unwrap_or(i64::MAX),
                    sent: *sent,
                    received: *received,
                    new_connections: 0,
                };
                learner.traffic(&app, &[delta], enricher, &mut user.store, now);
            }
        }
        Step::Finished(row, key) => {
            if let (Some(learner), Some(app)) = (user.learner.as_mut(), app_facts(row)) {
                let facts = destination_facts(
                    key.remote.ip(),
                    row.domain.as_deref(),
                    label_source(row.domain_source.as_deref()),
                    enricher,
                );
                let finished = Finished {
                    app,
                    domain: facts.domain.as_deref(),
                    company: facts.company.as_deref(),
                    country: facts.country.as_deref(),
                    port: key.remote.port(),
                    first_seen: at(row.first_seen),
                    last_seen: at(row.last_seen.max(row.first_seen)),
                };
                learner.finished(&finished, enricher, &mut user.store, now);
            }
        }
        Step::Connection(row) => {
            if let Some(learner) = user.learner.as_mut()
                && !row.app_path.is_empty()
            {
                let app = AppFacts {
                    app_name: &row.app_name,
                    path: &row.app_path,
                    sha256: None,
                    publisher: None,
                    signature_valid: false,
                    installed_by_admins: installed_by_admins(&row.app_path),
                };
                let delta = Delta {
                    app_key: known_app_key(&row.app_path),
                    destination: connection_destination(&row.destination),
                    hour: i64::try_from(time / HOUR).unwrap_or(i64::MAX),
                    sent: 0,
                    received: 0,
                    new_connections: 1,
                };
                learner.traffic(&app, &[delta], enricher, &mut user.store, now);
            }
        }
    }
    if let Some(error) = user.detector.take_errors().first() {
        return Err(error.clone());
    }
    if let Some(error) = user
        .learner
        .as_mut()
        .and_then(|learner| learner.take_errors().into_iter().next())
    {
        return Err(error);
    }
    Ok(())
}

/// A connection line's destination as the Learner gets it from the service:
/// a confirmed name's registrable domain. A bare address (the engine had no
/// confirmed name) is no destination, so it is never tracked for beaconing,
/// as in the app; its connection still counts in the app's hour.
fn connection_destination(destination: &str) -> Option<String> {
    if destination.parse::<IpAddr>().is_ok() {
        return None;
    }
    registrable_domain(destination)
}

/// Every alert saved for one user, oldest first, with whether the app would
/// have notified about it.
fn user_alerts(name: &str, store: &Store) -> Result<Vec<AlertOut>, String> {
    let mut stored = store
        .alerts(UNIX_EPOCH, usize::MAX)
        .map_err(|e| e.to_string())?;
    stored.sort_by_key(|alert| (alert.created, alert.id));
    let mut limiter = AlertLimiter::default();
    let mut alerts = Vec::with_capacity(stored.len());
    for alert in stored {
        let time = alert
            .created
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        // As the app: an alert is about its app, or else about its kind.
        let who = alert
            .app_name
            .clone()
            .unwrap_or_else(|| format!("{:?}", alert.kind));
        let notified = limiter.allow(&who, ipc_severity(alert.severity), time);
        let mut reasons: Vec<String> = Vec::new();
        for reason in &alert.reasons {
            let signal = reason.signal.as_str();
            if !reasons.iter().any(|known| known == signal) {
                reasons.push(signal.to_owned());
            }
        }
        alerts.push(AlertOut {
            user: name.to_owned(),
            time,
            layer: if alert.kind == AlertKind::Behaviour {
                2
            } else {
                1
            },
            kind: alert.kind.as_str().to_owned(),
            severity: alert.severity.as_str().to_owned(),
            app_name: alert.app_name,
            app_path: alert.app_path,
            target: alert.target,
            detail: alert.detail,
            reasons,
            notified,
        });
    }
    Ok(alerts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(first_seen: u64, last_seen: u64, sent: u64, received: u64) -> FlowRow {
        FlowRow {
            user: String::from("u1"),
            day: 1,
            app_name: String::from("a.exe"),
            app_path: Some(String::from(r"C:\a.exe")),
            app_sha256: None,
            signature: None,
            publisher: None,
            protocol: String::from("TCP"),
            remote_ip: String::from("198.51.100.1"),
            remote_port: 443,
            domain: None,
            domain_source: None,
            owner: None,
            country: None,
            first_seen,
            last_seen,
            bytes_sent: sent,
            bytes_received: received,
            connections: 1,
            scenario: None,
        }
    }

    #[test]
    fn an_unchecked_signature_leaves_the_hash_out() {
        let mut flow = row(0, 0, 0, 0);
        flow.app_sha256 = Some(String::from("ab"));
        flow.signature = Some(String::from("unknown"));
        assert_eq!(app_facts(&flow).unwrap().sha256, None);
        flow.signature = Some(String::from("unsigned"));
        assert_eq!(app_facts(&flow).unwrap().sha256, Some("ab"));
    }

    #[test]
    fn shares_spread_evenly_with_the_remainder_last() {
        let t = 1_800_000_000; // on the hour
        assert_eq!(
            hourly_shares(&row(t + 10, t + 2 * HOUR + 30, 10, 0)),
            [
                (t / HOUR, t + HOUR - 1, 3, 0),
                (t / HOUR + 1, t + 2 * HOUR - 1, 3, 0),
                (t / HOUR + 2, t + 2 * HOUR + 30, 4, 0),
            ]
        );
        assert_eq!(
            hourly_shares(&row(t + 10, t + 20, 7, 9)),
            [(t / HOUR, t + 20, 7, 9)]
        );
        // Nothing moved: nothing to send. A last sighting before the first
        // counts as the first.
        assert!(hourly_shares(&row(t, t + 5, 0, 0)).is_empty());
        assert_eq!(
            hourly_shares(&row(t + 5, t, 1, 1)),
            [(t / HOUR, t + 5, 1, 1)]
        );
    }

    #[test]
    fn install_folders_are_recognised_in_any_case() {
        assert!(installed_by_admins(r"C:\Program Files\App\app.exe"));
        assert!(installed_by_admins(r"c:\PROGRAM FILES (X86)\App\app.exe"));
        assert!(installed_by_admins(r"C:\Windows\System32\curl.exe"));
        assert!(!installed_by_admins(
            r"C:\Users\u\AppData\Local\Lab\Discord.exe"
        ));
        assert!(!installed_by_admins(r"C:\Program Files Evil\app.exe"));
    }

    #[test]
    fn bare_addresses_are_no_destination() {
        assert_eq!(connection_destination("203.0.113.5"), None);
        assert_eq!(connection_destination("2001:db8::1"), None);
        assert_eq!(
            connection_destination("cdn-1.files.example.net").as_deref(),
            Some("example.net")
        );
    }
}
