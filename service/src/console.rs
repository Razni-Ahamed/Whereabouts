//! `--console` mode: live table of network flows per app.

use std::collections::{HashMap, VecDeque};
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime};

use whereabouts_core::flow::{FlowKey, FlowStats, FlowTable};
use whereabouts_core::model::{CaptureEvent, NetEvent, Protocol};
use whereabouts_win_capture::{Capture, CaptureCounts, process};

/// Maximum number of events waiting between the capture thread and us.
const EVENT_QUEUE: usize = 20_000;
/// How often the table is redrawn.
const REFRESH: Duration = Duration::from_secs(2);
/// Rows shown per refresh.
const TOP_ROWS: usize = 25;
/// Flows with no traffic for this long are closed.
const IDLE_AFTER: Duration = Duration::from_secs(300);
/// Closed flows kept for display; the oldest are discarded first.
const MAX_CLOSED: usize = 2_000;
/// How long after a process exits its late traffic is still attributed to
/// it. Windows sends a few bytes (such as TLS close messages) for a process
/// after it has exited.
const LATE_TRAFFIC_WINDOW: Duration = Duration::from_secs(10);

/// A flow together with the app name it had when it was recorded.
#[derive(Debug, Clone)]
struct Row {
    app: String,
    key: FlowKey,
    stats: FlowStats,
}

/// Runs the console view until `limit` passes, or forever if `None`.
pub fn run(limit: Option<Duration>) -> ExitCode {
    let (sender, receiver) = mpsc::sync_channel(EVENT_QUEUE);
    let capture = match Capture::start(sender) {
        Ok(capture) => capture,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("Whereabouts is watching network connections. Press Ctrl+C to stop.");

    let started = Instant::now();
    let mut last_draw = Instant::now();
    let mut table = FlowTable::new();
    let mut names = ProcessNames::default();
    let mut closed = VecDeque::new();
    let mut exited = RecentlyExited::default();

    loop {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(CaptureEvent::Net(event)) => {
                if let Some(app) = exited.name(event.pid) {
                    add_late_traffic(&mut closed, app, &event);
                } else {
                    // Look the process up while it is still running.
                    names.resolve(event.pid);
                    table.record(&event);
                }
            }
            Ok(CaptureEvent::ProcessStarted { pid, image }) => {
                // A new process with a reused ID: its traffic is its own.
                exited.forget(pid);
                names.set(pid, file_name(&image));
            }
            Ok(CaptureEvent::ProcessExited { pid }) => {
                // Windows may reuse this ID, so close everything tied to it.
                close(&mut closed, &names, table.take_process(pid));
                exited.insert(pid, names.get(pid).to_owned());
                names.forget(pid);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if last_draw.elapsed() >= REFRESH {
            exited.expire();
            close(
                &mut closed,
                &names,
                table.take_idle(SystemTime::now(), IDLE_AFTER),
            );
            draw(&table, &closed, &names, capture.counts(), started.elapsed());
            last_draw = Instant::now();
        }
        if limit.is_some_and(|limit| started.elapsed() >= limit) {
            break;
        }
    }

    draw(&table, &closed, &names, capture.counts(), started.elapsed());
    if let Err(error) = capture.stop() {
        eprintln!("warning: {error}");
    }
    ExitCode::SUCCESS
}

/// Cache of process ID to executable file name.
#[derive(Debug, Default)]
struct ProcessNames(HashMap<u32, Option<String>>);

impl ProcessNames {
    /// Looks up `pid` if it is not cached yet.
    fn resolve(&mut self, pid: u32) {
        self.0
            .entry(pid)
            .or_insert_with(|| process::image_path(pid).map(|path| file_name(&path).to_owned()));
    }

    fn set(&mut self, pid: u32, name: &str) {
        self.0.insert(pid, Some(name.to_owned()));
    }

    fn forget(&mut self, pid: u32) {
        self.0.remove(&pid);
    }

    fn get(&self, pid: u32) -> &str {
        self.0
            .get(&pid)
            .and_then(Option::as_deref)
            .unwrap_or("(unknown)")
    }
}

/// Names of processes that exited recently, for attributing late traffic.
#[derive(Debug, Default)]
struct RecentlyExited(HashMap<u32, (String, Instant)>);

impl RecentlyExited {
    fn insert(&mut self, pid: u32, app: String) {
        self.0.insert(pid, (app, Instant::now()));
    }

    fn forget(&mut self, pid: u32) {
        self.0.remove(&pid);
    }

    fn name(&self, pid: u32) -> Option<&str> {
        self.0
            .get(&pid)
            .filter(|(_, at)| at.elapsed() < LATE_TRAFFIC_WINDOW)
            .map(|(app, _)| app.as_str())
    }

    fn expire(&mut self) {
        self.0
            .retain(|_, (_, at)| at.elapsed() < LATE_TRAFFIC_WINDOW);
    }
}

/// Adds traffic that arrived after its process exited to the matching
/// closed flow, or starts a new closed flow for it.
fn add_late_traffic(closed: &mut VecDeque<Row>, app: &str, event: &NetEvent) {
    if event.is_loopback() {
        return;
    }
    let key = FlowKey {
        pid: event.pid,
        protocol: event.protocol,
        remote: event.remote,
    };
    if let Some(row) = closed.iter_mut().rev().find(|row| row.key == key) {
        row.stats.record(event);
        return;
    }
    let mut stats = FlowStats::new(event.timestamp);
    stats.record(event);
    if closed.len() >= MAX_CLOSED {
        closed.pop_front();
    }
    closed.push_back(Row {
        app: app.to_owned(),
        key,
        stats,
    });
}

/// Moves finished flows into the bounded `closed` list, keeping their names.
fn close(closed: &mut VecDeque<Row>, names: &ProcessNames, flows: Vec<(FlowKey, FlowStats)>) {
    for (key, stats) in flows {
        if closed.len() >= MAX_CLOSED {
            closed.pop_front();
        }
        closed.push_back(Row {
            app: names.get(key.pid).to_owned(),
            key,
            stats,
        });
    }
}

fn draw(
    table: &FlowTable,
    closed: &VecDeque<Row>,
    names: &ProcessNames,
    counts: CaptureCounts,
    elapsed: Duration,
) {
    let mut rows: Vec<Row> = table
        .snapshot()
        .into_iter()
        .map(|(key, stats)| Row {
            app: names.get(key.pid).to_owned(),
            key,
            stats,
        })
        .collect();
    let active = rows.len();
    rows.extend(closed.iter().cloned());
    rows.sort_by(|a, b| {
        b.stats
            .total_bytes()
            .cmp(&a.stats.total_bytes())
            .then_with(|| a.key.cmp(&b.key))
    });

    println!();
    println!(
        "── {}s · {active} active flows · {} closed · {} events · {} dropped · {} unreadable · {} over limit ──",
        elapsed.as_secs(),
        closed.len(),
        counts.events,
        counts.dropped,
        counts.malformed,
        table.overflowed_events()
    );
    println!(
        "{:>6}  {:<24} {:<5} {:<46} {:>10} {:>10}",
        "PID", "APP", "PROTO", "REMOTE", "SENT", "RECEIVED"
    );
    for row in rows.iter().take(TOP_ROWS) {
        println!("{}", format_row(row));
    }
    if rows.len() > TOP_ROWS {
        println!("  … and {} more", rows.len() - TOP_ROWS);
    }
}

fn format_row(row: &Row) -> String {
    let proto = match row.key.protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
    };
    let remote = if row.key.is_overflow() {
        String::from("(many destinations: flow limit reached)")
    } else {
        row.key.remote.to_string()
    };
    format!(
        "{:>6}  {:<24} {:<5} {:<46} {:>10} {:>10}",
        row.key.pid,
        truncate(&row.app, 24),
        proto,
        remote,
        format_bytes(row.stats.bytes_sent),
        format_bytes(row.stats.bytes_received)
    )
}

/// Returns the last component of a Windows or Unix path.
fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Shortens `text` to at most `max` characters, marking the cut with `…`.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_owned()
    } else {
        let kept: String = text.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

/// Formats a byte count for people, e.g. `1.5 MB`.
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;
    use whereabouts_core::model::NetEventKind;

    fn late_send(pid: u32, bytes: u64) -> NetEvent {
        NetEvent {
            pid,
            protocol: Protocol::Tcp,
            kind: NetEventKind::Send,
            local: "192.168.1.10:50000".parse().unwrap(),
            remote: "203.0.113.10:443".parse().unwrap(),
            bytes,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn late_traffic_merges_into_the_closed_flow() {
        let mut closed = VecDeque::new();
        add_late_traffic(&mut closed, "curl.exe", &late_send(7, 600));
        add_late_traffic(&mut closed, "curl.exe", &late_send(7, 24));
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].app, "curl.exe");
        assert_eq!(closed[0].stats.bytes_sent, 624);
    }

    #[test]
    fn recently_exited_names_are_cleared_when_the_id_is_reused() {
        let mut exited = RecentlyExited::default();
        exited.insert(7, String::from("old.exe"));
        assert_eq!(exited.name(7), Some("old.exe"));
        exited.forget(7); // ProcessStarted for a new process with ID 7
        assert_eq!(exited.name(7), None);
    }

    #[test]
    fn formats_bytes_in_readable_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(150 * 1024 * 1024), "150.0 MB");
        assert_eq!(format_bytes(u64::MAX), "16.0 EB");
    }

    #[test]
    fn extracts_file_names_from_paths() {
        assert_eq!(file_name(r"C:\Program Files\App\app.exe"), "app.exe");
        assert_eq!(file_name("System"), "System");
        assert_eq!(file_name("/usr/bin/curl"), "curl");
    }

    #[test]
    fn truncates_long_names_on_character_boundaries() {
        assert_eq!(truncate("short.exe", 24), "short.exe");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("ééééé", 3), "éé…");
    }
}
