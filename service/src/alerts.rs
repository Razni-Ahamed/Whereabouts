//! How the service shows alerts to clients. The detection itself lives in
//! `whereabouts-detect` (shared with the lab's replay tool).

use std::time::{SystemTime, UNIX_EPOCH};

pub use whereabouts_detect::learner::Learner;
use whereabouts_detect::signals::Toggles;
pub use whereabouts_detect::{Detector, FlowFacts, Raised};
use whereabouts_store::{AlertKind, Reason, Severity};

/// The detector, with this computer's Spamhaus DROP list if it downloaded one.
pub fn load_detector() -> Detector {
    let (detector, warning) = Detector::load(&crate::updates::lists_dir());
    if let Some(warning) = warning {
        report!("warning: {warning}");
    }
    if let Some(ranges) = detector.drop_ranges() {
        println!("Spamhaus DROP: {ranges} network ranges");
    }
    detector
}

/// The behaviour Learner (Layer 2), with its signals' starting switches.
/// `local_offset_secs` is the local time zone's offset from UTC.
pub fn new_learner(local_offset_secs: i32) -> Learner {
    Learner::new(Toggles::default(), local_offset_secs)
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// An alert's kind as clients see it.
pub fn kind_view(kind: AlertKind) -> whereabouts_ipc::AlertKind {
    match kind {
        AlertKind::Tracker => whereabouts_ipc::AlertKind::Tracker,
        AlertKind::BadNetwork => whereabouts_ipc::AlertKind::BadNetwork,
        AlertKind::FakedDns => whereabouts_ipc::AlertKind::FakedDns,
        AlertKind::Unattributed => whereabouts_ipc::AlertKind::Unattributed,
        AlertKind::Behaviour => whereabouts_ipc::AlertKind::Behaviour,
    }
}

/// A behaviour alert's reason as clients see it.
fn reason_view(reason: Reason) -> whereabouts_ipc::ReasonView {
    whereabouts_ipc::ReasonView {
        signal: String::from(reason.signal.as_str()),
        value: reason.value,
        observed: reason.observed,
        usual: reason.usual,
        count: reason.count,
    }
}

/// An alert's severity as clients see it.
pub fn severity_view(severity: Severity) -> whereabouts_ipc::Severity {
    match severity {
        Severity::Info => whereabouts_ipc::Severity::Info,
        Severity::Medium => whereabouts_ipc::Severity::Medium,
        Severity::High => whereabouts_ipc::Severity::High,
        Severity::Critical => whereabouts_ipc::Severity::Critical,
    }
}

/// A saved alert as clients see it.
pub fn view(alert: whereabouts_store::StoredAlert) -> whereabouts_ipc::AlertView {
    whereabouts_ipc::AlertView {
        id: alert.id,
        created_secs: unix_secs(alert.created),
        kind: kind_view(alert.kind),
        severity: severity_view(alert.severity),
        app: alert.app_name,
        path: alert.app_path,
        target: alert.target,
        detail: alert.detail,
        dismissed: alert.dismissed,
        can_allow: alert.can_allow,
        reasons: alert.reasons.into_iter().map(reason_view).collect(),
        seen_again: alert.seen_again,
        dropped_reasons: alert.dropped_reasons,
    }
}

/// Room left in a message for the JSON around the alerts.
const MESSAGE_MARGIN: usize = 4 * 1024;

/// Leaves out alerts until the list fits in one message: info alerts first,
/// the oldest first (the list comes above-info first, each part newest
/// first), so an alert that needs a look is never left out while an info
/// one remains. Real lists are far smaller; this guards against many alerts
/// that each hold many long reasons.
pub fn fit(alerts: &mut Vec<whereabouts_ipc::AlertView>) {
    let size = |alert: &whereabouts_ipc::AlertView| {
        // An alert that cannot be measured is left out first.
        serde_json::to_vec(alert).map_or(usize::MAX, |json| json.len().saturating_add(1))
    };
    let mut sizes: Vec<usize> = alerts.iter().map(size).collect();
    let limit = whereabouts_ipc::MAX_MESSAGE - MESSAGE_MARGIN;
    let mut total = sizes.iter().fold(0usize, |sum, &s| sum.saturating_add(s));
    while total > limit && !alerts.is_empty() {
        let at = alerts
            .iter()
            .rposition(|alert| alert.severity == whereabouts_ipc::Severity::Info)
            .unwrap_or(alerts.len() - 1);
        alerts.remove(at);
        total = total.saturating_sub(sizes.remove(at));
    }
}

/// The notice that tells clients about a raised alert.
pub fn notice(raised: &Raised) -> whereabouts_ipc::NoticeKind {
    whereabouts_ipc::NoticeKind::Alert {
        id: raised.id,
        alert: kind_view(raised.alert.kind),
        severity: severity_view(raised.alert.severity),
        app: raised.alert.app_name.clone(),
    }
}
