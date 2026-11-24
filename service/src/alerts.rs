//! How the service shows alerts to clients. The detection itself lives in
//! `whereabouts-detect` (shared with the lab's replay tool).

use std::time::{SystemTime, UNIX_EPOCH};

pub use whereabouts_detect::learner::Learner;
use whereabouts_detect::signals::Toggles;
pub use whereabouts_detect::{Detector, FlowFacts, Raised};
use whereabouts_store::{AlertKind, Severity};

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
        // Nothing raises behaviour alerts yet, and clients have no kind for
        // them until the IPC changes of v0.3 land; show them as the
        // closest existing kind meanwhile.
        AlertKind::Behaviour => whereabouts_ipc::AlertKind::Unattributed,
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
