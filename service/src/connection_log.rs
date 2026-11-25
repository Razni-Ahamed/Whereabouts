//! `--record-connections <FILE>`: a lab diagnostic for the console engine.
//!
//! **For the lab only** (`lab/capture/run-session.ps1`, on disposable
//! runners): it is never on by default, the installed service refuses it, and
//! nothing else writes this file. It appends one JSON line per connection a
//! program opened (`app_path`, `app_name`, `destination`, `remote_ip`,
//! `remote_port`, `time_ms`), so the lab can replay beaconing, which needs
//! when each connection was opened. The file is **not encrypted** and names
//! which programs contacted which servers, in the file the operator chose.
//!
//! A connection counts as new when a flow's connection count rises between
//! ticks: the signal the behaviour Learner's meter uses
//! (`whereabouts_detect::meter::Meter`). A flow seen for the first time counts
//! all of its connections. As for learning, only flows with a known program
//! file count, and never the flow-limit overflow. The destination follows the
//! profiles' rule (a confirmed name's registrable domain), else the address.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use whereabouts_core::flow::FlowKey;
use whereabouts_detect::destination::confirmed_domain;

use crate::learning::FlowInput;

/// Largest file: writing stops (with a warning) at this size.
pub const MAX_BYTES: u64 = 50 * 1024 * 1024;

/// The open connection file and what was seen at the last tick.
#[derive(Debug)]
pub struct ConnectionLog {
    out: BufWriter<File>,
    path: PathBuf,
    /// Bytes in the file.
    size: u64,
    /// Whether the size limit was reached (nothing more is written).
    full: bool,
    /// Connections of each flow at the last tick.
    previous: HashMap<FlowKey, u32>,
}

impl ConnectionLog {
    /// Opens `path` for appending (created if missing).
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            out: BufWriter::new(file),
            path: path.to_owned(),
            size,
            full: size >= MAX_BYTES,
            previous: HashMap::new(),
        })
    }

    /// Writes a line for each connection opened since the last call, at
    /// `now`. Flows are those shown this tick; rows with the same key (a
    /// flow that finished and started again) are added together, and flows
    /// missing from `flows` are forgotten. Problems are reported, never
    /// fatal; at [`MAX_BYTES`] writing stops.
    pub fn record(&mut self, flows: &[FlowInput<'_>], now: SystemTime) {
        let mut current: HashMap<FlowKey, u32> = HashMap::with_capacity(flows.len());
        let mut first: HashMap<FlowKey, &FlowInput<'_>> = HashMap::new();
        for flow in flows {
            if flow.key.is_overflow() || !has_program(flow) {
                continue;
            }
            let total = current.entry(flow.key).or_default();
            *total = total.saturating_add(flow.stats.connections);
            first.entry(flow.key).or_insert(flow);
        }
        let time_ms = now
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let mut text = String::new();
        for (key, flow) in &first {
            let before = self.previous.get(key).copied().unwrap_or(0);
            let opened = current
                .get(key)
                .copied()
                .unwrap_or(0)
                .saturating_sub(before);
            if opened == 0 {
                continue;
            }
            let line = line(flow, time_ms);
            for _ in 0..opened {
                text.push_str(&line);
                text.push('\n');
            }
        }
        self.previous = current;
        self.write(&text);
    }

    fn write(&mut self, text: &str) {
        if self.full || text.is_empty() {
            return;
        }
        let len = text.len() as u64;
        if self.size.saturating_add(len) > MAX_BYTES {
            self.full = true;
            report!(
                "warning: {} reached {} MB; no more connections are recorded",
                self.path.display(),
                MAX_BYTES / (1024 * 1024)
            );
            return;
        }
        let written = self
            .out
            .write_all(text.as_bytes())
            .and_then(|()| self.out.flush());
        match written {
            Ok(()) => self.size += len,
            Err(error) => {
                self.full = true;
                report!(
                    "warning: could not record connections to {} ({error}); stopped",
                    self.path.display()
                );
            }
        }
    }
}

fn has_program(flow: &FlowInput<'_>) -> bool {
    flow.identity
        .is_some_and(|identity| !identity.path.is_empty())
}

/// One connection's JSON line (without the line break).
fn line(flow: &FlowInput<'_>, time_ms: u64) -> String {
    let path = flow.identity.map_or("", |identity| identity.path.as_str());
    let ip = flow.key.remote.ip();
    let label = flow.stats.domain.as_ref();
    let destination = confirmed_domain(
        label.map(|label| label.name.as_ref()),
        label.map(|label| label.source),
    )
    .unwrap_or_else(|| ip.to_string());
    serde_json::json!({
        "app_path": path,
        "app_name": flow.app,
        "destination": destination,
        "remote_ip": ip.to_string(),
        "remote_port": flow.key.remote.port(),
        "time_ms": time_ms,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use whereabouts_core::dns::{DomainLabel, LabelSource};
    use whereabouts_core::flow::FlowStats;
    use whereabouts_core::model::{AppIdentity, Protocol, Signature};

    const T0: u64 = 1_800_000_000;

    fn identity(path: &str) -> AppIdentity {
        AppIdentity {
            path: path.to_owned(),
            signature: Signature::Unsigned,
            sha256: None,
            size: None,
            package_family_name: None,
            confirmed_running: true,
        }
    }

    fn stats(domain: Option<(&str, LabelSource)>, connections: u32) -> FlowStats {
        let mut stats = FlowStats::new(UNIX_EPOCH + Duration::from_secs(T0));
        stats.domain = domain.map(|(name, source)| DomainLabel::new(name, source));
        stats.connections = connections;
        stats
    }

    fn key(pid: u32, remote: &str) -> FlowKey {
        FlowKey {
            pid,
            protocol: Protocol::Tcp,
            remote: remote.parse().unwrap(),
        }
    }

    fn input<'a>(
        key: FlowKey,
        identity: Option<&'a AppIdentity>,
        stats: &'a FlowStats,
    ) -> FlowInput<'a> {
        FlowInput {
            key,
            app: "beacon.exe",
            identity,
            stats,
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("whereabouts-connlog-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("connections.jsonl")
    }

    fn lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn one_line_per_new_connection() {
        let path = temp("new");
        let app = identity(r"C:\Apps\beacon.exe");
        let mut log = ConnectionLog::open(&path).unwrap();
        let k = key(7, "203.0.113.9:443");
        let named = Some(("api.c2.example.net", LabelSource::Verified));
        log.record(&[input(k, Some(&app), &stats(named, 1))], at(T0));
        // Nothing new: nothing written.
        log.record(&[input(k, Some(&app), &stats(named, 1))], at(T0 + 2));
        log.record(&[input(k, Some(&app), &stats(named, 3))], at(T0 + 60));
        let written = lines(&path);
        assert_eq!(written.len(), 3);
        assert_eq!(
            written[0],
            serde_json::json!({
                "app_path": r"C:\Apps\beacon.exe", "app_name": "beacon.exe",
                "destination": "example.net", "remote_ip": "203.0.113.9",
                "remote_port": 443, "time_ms": T0 * 1000,
            })
        );
        assert!(
            written[1..]
                .iter()
                .all(|l| l["time_ms"] == (T0 + 60) * 1000)
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn unconfirmed_names_give_the_address_and_unknown_programs_are_skipped() {
        let path = temp("skip");
        let app = identity(r"C:\Apps\beacon.exe");
        let mut log = ConnectionLog::open(&path).unwrap();
        let app_only = stats(Some(("evil.example", LabelSource::Unverified)), 1);
        let one = stats(None, 1);
        log.record(
            &[
                input(key(7, "203.0.113.9:443"), Some(&app), &app_only),
                input(key(8, "203.0.113.10:443"), None, &one),
                input(FlowKey::overflow(7, Protocol::Tcp), Some(&app), &one),
            ],
            at(T0),
        );
        let written = lines(&path);
        assert_eq!(written.len(), 1);
        assert_eq!(written[0]["destination"], "203.0.113.9");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_flow_that_went_away_counts_again_and_rows_with_one_key_add_up() {
        let path = temp("again");
        let app = identity(r"C:\Apps\beacon.exe");
        let mut log = ConnectionLog::open(&path).unwrap();
        let k = key(7, "203.0.113.9:443");
        let (closed, open) = (stats(None, 1), stats(None, 1));
        log.record(&[input(k, Some(&app), &closed)], at(T0));
        // The finished row is still shown, and the flow started again.
        log.record(
            &[input(k, Some(&app), &closed), input(k, Some(&app), &open)],
            at(T0 + 10),
        );
        log.record(&[], at(T0 + 20));
        log.record(&[input(k, Some(&app), &open)], at(T0 + 30));
        assert_eq!(lines(&path).len(), 3);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn stops_at_the_size_limit() {
        let path = temp("full");
        let app = identity(r"C:\Apps\beacon.exe");
        let mut log = ConnectionLog::open(&path).unwrap();
        log.size = MAX_BYTES - 10;
        log.record(
            &[input(
                key(7, "203.0.113.9:443"),
                Some(&app),
                &stats(None, 1),
            )],
            at(T0),
        );
        assert!(log.full);
        log.size = 0;
        log.record(
            &[input(
                key(8, "203.0.113.9:443"),
                Some(&app),
                &stats(None, 1),
            )],
            at(T0),
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
