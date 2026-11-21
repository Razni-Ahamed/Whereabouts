//! Runs a timeline through the shipped detector, one simulated user at a
//! time, and reports every alert it saved, with whether the app would have
//! notified about it (the shared rule in `whereabouts_ipc::notify`).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use whereabouts_core::flow::FlowKey;
use whereabouts_core::model::Protocol;
use whereabouts_detect::{Detector, FlowFacts};
use whereabouts_enrich::{DropList, Enricher};
use whereabouts_ipc::notify::AlertLimiter;
use whereabouts_store::{Key, Severity, Store};

use crate::timeline::{FlowRow, Line};

/// One alert, as the lab's scoring reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AlertOut {
    pub user: String,
    /// When it was raised (Unix seconds, simulated time).
    pub time: u64,
    /// Which detection layer raised it.
    pub layer: u8,
    /// The store's spelling, e.g. `bad_network`.
    pub kind: String,
    /// The store's spelling, e.g. `high`.
    pub severity: String,
    pub app_name: Option<String>,
    pub app_path: Option<String>,
    pub target: Option<String>,
    pub detail: Option<String>,
    /// Signals behind it (Layer 2 and later; empty for Layer 1).
    pub reasons: Vec<String>,
    /// Whether the app would push it as a Windows notification.
    pub notified: bool,
}

struct User {
    detector: Detector,
    store: Store,
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

/// Replays `lines` (sorted, see [`crate::timeline::parse`]). Each user gets
/// a fresh detector and a temporary encrypted store under `work_dir`, which
/// is deleted afterwards. Alerts come back in time order.
pub fn run(
    lines: &[Line],
    enricher: &Enricher,
    drop: Option<&DropList>,
    work_dir: &Path,
) -> Result<Vec<AlertOut>, String> {
    std::fs::create_dir_all(work_dir).map_err(|e| format!("{}: {e}", work_dir.display()))?;
    let result = replay_users(lines, enricher, drop, work_dir);
    let _ = std::fs::remove_dir_all(work_dir);
    result
}

fn open_user(drop: Option<&DropList>, path: &Path) -> Result<User, String> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| e.to_string())?;
    let store = Store::open(path, &Key::from_bytes(key)).map_err(|e| e.to_string())?;
    let detector = drop.map_or_else(Detector::default, |list| Detector::with_drop(list.clone()));
    Ok(User { detector, store })
}

fn replay_users(
    lines: &[Line],
    enricher: &Enricher,
    drop: Option<&DropList>,
    work_dir: &Path,
) -> Result<Vec<AlertOut>, String> {
    let mut users: BTreeMap<String, User> = BTreeMap::new();
    let mut number: u32 = 0;
    for line in lines {
        let name = match line {
            Line::Flow(row) => &row.user,
            Line::Counters(row) => &row.user,
            Line::Header { .. } => continue,
        };
        if !users.contains_key(name) {
            let path = work_dir.join(format!("user-{}.db", users.len()));
            users.insert(name.clone(), open_user(drop, &path)?);
        }
        let Some(user) = users.get_mut(name) else {
            continue;
        };
        match line {
            Line::Flow(row) => {
                number += 1;
                let key = flow_key(row, number)?;
                // As the service: a domain counts unless only the app itself
                // reported it.
                let domain = row
                    .domain
                    .as_deref()
                    .filter(|_| row.domain_source.as_deref() != Some("unverified"));
                let facts = FlowFacts {
                    key,
                    app: &row.app_name,
                    path: row.app_path.as_deref(),
                    domain,
                    aliases: &[],
                };
                user.detector
                    .check_flow(&facts, enricher, &mut user.store, at(row.first_seen));
            }
            Line::Counters(row) => {
                user.detector.check_counters(
                    row.rejected,
                    row.unattributed,
                    &mut user.store,
                    at(row.time),
                );
            }
            Line::Header { .. } => {}
        }
        if let Some(error) = user.detector.take_errors().first() {
            return Err(format!("user {name}: {error}"));
        }
    }

    let mut alerts = Vec::new();
    for (name, user) in &users {
        let mut stored = user
            .store
            .alerts(UNIX_EPOCH, usize::MAX)
            .map_err(|e| e.to_string())?;
        stored.sort_by_key(|alert| (alert.created, alert.id));
        let mut limiter = AlertLimiter::default();
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
            alerts.push(AlertOut {
                user: name.clone(),
                time,
                layer: 1,
                kind: alert.kind.as_str().to_owned(),
                severity: alert.severity.as_str().to_owned(),
                app_name: alert.app_name,
                app_path: alert.app_path,
                target: alert.target,
                detail: alert.detail,
                reasons: Vec::new(),
                notified,
            });
        }
    }
    alerts.sort_by(|a, b| (a.time, &a.user).cmp(&(b.time, &b.user)));
    Ok(alerts)
}
