//! `--console` mode: live table of network flows per app.

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use whereabouts_core::flow::{FlowKey, FlowStats, FlowTable};
use whereabouts_core::model::Protocol;
use whereabouts_win_capture::{Capture, CaptureCounts, process};

/// Maximum number of events waiting between the capture thread and us.
const EVENT_QUEUE: usize = 20_000;
/// How often the table is redrawn.
const REFRESH: Duration = Duration::from_secs(2);
/// Rows shown per refresh.
const TOP_ROWS: usize = 25;

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

    loop {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(event) => {
                // Look the process up while it is still running.
                names.resolve(event.pid);
                table.record(&event);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if last_draw.elapsed() >= REFRESH {
            draw(&table, &names, capture.counts(), started.elapsed());
            last_draw = Instant::now();
        }
        if limit.is_some_and(|limit| started.elapsed() >= limit) {
            break;
        }
    }

    draw(&table, &names, capture.counts(), started.elapsed());
    if let Err(error) = capture.stop() {
        eprintln!("warning: {error}");
    }
    ExitCode::SUCCESS
}

/// Cache of process ID to executable file name.
#[derive(Debug, Default)]
struct ProcessNames(HashMap<u32, Option<String>>);

impl ProcessNames {
    fn resolve(&mut self, pid: u32) {
        self.0
            .entry(pid)
            .or_insert_with(|| process::image_path(pid).map(|path| file_name(&path).to_owned()));
    }

    fn get(&self, pid: u32) -> &str {
        self.0
            .get(&pid)
            .and_then(Option::as_deref)
            .unwrap_or("(unknown)")
    }
}

fn draw(table: &FlowTable, names: &ProcessNames, counts: CaptureCounts, elapsed: Duration) {
    let flows = table.snapshot();
    println!();
    println!(
        "── {}s · {} flows · {} events · {} dropped · {} unreadable ──",
        elapsed.as_secs(),
        flows.len(),
        counts.events,
        counts.dropped + table.dropped_events(),
        counts.malformed
    );
    println!(
        "{:>6}  {:<24} {:<5} {:<46} {:>10} {:>10}",
        "PID", "APP", "PROTO", "REMOTE", "SENT", "RECEIVED"
    );
    for (key, stats) in flows.iter().take(TOP_ROWS) {
        println!("{}", row(key, stats, names.get(key.pid)));
    }
    if flows.len() > TOP_ROWS {
        println!("  … and {} more", flows.len() - TOP_ROWS);
    }
}

fn row(key: &FlowKey, stats: &FlowStats, app: &str) -> String {
    let proto = match key.protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
    };
    format!(
        "{:>6}  {:<24} {:<5} {:<46} {:>10} {:>10}",
        key.pid,
        truncate(app, 24),
        proto,
        key.remote.to_string(),
        format_bytes(stats.bytes_sent),
        format_bytes(stats.bytes_received)
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
