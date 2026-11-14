//! `--console` mode: live table of network flows per app.

use std::collections::{HashMap, VecDeque};
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime};

use whereabouts_core::dns::{DnsMap, LabelSource};
use whereabouts_core::flow::{FlowKey, FlowStats, FlowTable};
use whereabouts_core::model::{AppIdentity, CaptureEvent, NetEvent, Protocol};
use whereabouts_win_capture::identity::{DevicePaths, lock_running_image};
use whereabouts_win_capture::resolver::IdentityResolver;
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

/// Width of the PUBLISHER column.
const PUBLISHER_WIDTH: usize = 22;

/// Most program identities kept for display.
const MAX_IDENTITIES: usize = 20_000;

/// A flow together with the app name and process instance it had when
/// recorded. The publisher is looked up from the instance's token when
/// drawing, so a signature check that finishes after the app exited still
/// shows up.
#[derive(Debug, Clone)]
struct Row {
    app: String,
    token: Option<u64>,
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
    if !capture.kernel_events_protected() {
        println!(
            "!! Warning: this version of Windows lets programs write fake kernel network and \
             process events, so which app made a connection could be faked."
        );
    }
    println!(
        "Domains: plain = confirmed by the Windows DNS service · ? = reported only by the app"
    );
    println!("         itself (could be false) · * = guessed from another app's lookup");
    println!(
        "Publisher: from the program's code signature · ? = checked by file path only; not          confirmed as the file the process ran (e.g. it had already exited)"
    );

    let started = Instant::now();
    let mut last_draw = Instant::now();
    let mut table = FlowTable::new();
    let mut names = ProcessNames::new();
    let mut closed = VecDeque::new();
    let mut exited = RecentlyExited::default();
    // Start time of each running process, so that a process is identified by
    // its ID *and* start time, not by its ID alone.
    let mut starts: HashMap<u32, SystemTime> = HashMap::new();
    let mut dns = DnsMap::new();

    loop {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(CaptureEvent::Net(event)) => {
                let current_start = starts.get(&event.pid).copied();
                if let Some(owner) = exited.owner(&event, current_start) {
                    add_late_traffic(&mut closed, &owner.app, owner.token, &event);
                } else {
                    // Look the process up while it is still running.
                    names.note_traffic(event.pid);
                    let label = dns.lookup(event.pid, event.remote.ip(), event.timestamp);
                    table.record_labeled(&event, label);
                }
            }
            Ok(CaptureEvent::ProcessStarted {
                pid,
                image,
                timestamp,
            }) => {
                starts.insert(pid, timestamp);
                names.set_started(pid, &image);
            }
            Ok(CaptureEvent::ProcessExited { pid, timestamp }) => {
                // Windows may reuse this ID, so close everything tied to it.
                close(&mut closed, &names, table.take_process(pid));
                exited.insert(pid, names.get(pid).to_owned(), names.token(pid), timestamp);
                names.forget(pid);
                starts.remove(&pid);
                dns.forget_process(pid);
            }
            Ok(CaptureEvent::DnsAnswer {
                pid,
                name,
                addresses,
                timestamp,
                ..
            }) => {
                dns.record_app_answer(pid, &name, &addresses, timestamp);
            }
            Ok(CaptureEvent::DnsConfirmed {
                name,
                addresses,
                timestamp,
            }) => {
                dns.record_confirmed(&name, &addresses, timestamp);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        names.poll();
        if last_draw.elapsed() >= REFRESH {
            exited.expire();
            dns.expire(SystemTime::now());
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

    names.settle(Duration::from_secs(5));
    draw(&table, &closed, &names, capture.counts(), started.elapsed());
    // Release any process event waiting for queue space before stopping.
    drop(receiver);
    if let Err(error) = capture.stop() {
        eprintln!("warning: {error}");
    }
    ExitCode::SUCCESS
}

/// Name and executable path of a process.
#[derive(Debug)]
struct ProcessInfo {
    name: String,
    /// Drive-letter path, if known.
    path: Option<String>,
    /// Identifies this process instance (process IDs are reused), and its
    /// identity result.
    token: u64,
    /// Whether its identity has been asked for. Only processes that use
    /// the network are checked.
    requested: bool,
}

/// What the console knows about each process, plus each process's program
/// identity (signature, hash), worked out by a background worker.
///
/// Identities are stored per process instance, never looked up by path: a
/// file swapped at the same path must not inherit another process's result.
#[derive(Debug)]
struct ProcessNames {
    processes: HashMap<u32, Option<ProcessInfo>>,
    /// Identities by process-instance token.
    identities: HashMap<u64, AppIdentity>,
    next_token: u64,
    resolver: IdentityResolver,
    devices: DevicePaths,
}

impl ProcessNames {
    fn new() -> Self {
        Self {
            processes: HashMap::new(),
            identities: HashMap::new(),
            next_token: 0,
            resolver: IdentityResolver::start(),
            devices: DevicePaths::load(),
        }
    }

    fn new_token(&mut self) -> u64 {
        self.next_token += 1;
        self.next_token
    }

    /// Called for each network event of `pid`: looks the process up if it
    /// is not known yet, and asks for its program's identity once.
    fn note_traffic(&mut self, pid: u32) {
        if !self.processes.contains_key(&pid) {
            let token = self.new_token();
            let info = process::image_path(pid).map(|path| ProcessInfo {
                name: file_name(&path).to_owned(),
                path: self.devices.to_dos(&path),
                token,
                requested: false,
            });
            self.processes.insert(pid, info);
        }
        let Some(Some(info)) = self.processes.get_mut(&pid) else {
            return;
        };
        if info.requested {
            return;
        }
        // Check the file the process is actually running, per the kernel's
        // record (which follows renames), locked while the process is alive
        // so it cannot be swapped before the check. If that cannot be
        // confirmed (e.g. the process already exited), the file at its start
        // path is checked and the result is marked as unconfirmed.
        info.requested = match lock_running_image(pid) {
            Some((path, file)) => {
                let requested = self
                    .resolver
                    .request(info.token, &path, Some(file), Some(pid));
                info.path = Some(path);
                requested
            }
            None => match info.path.as_deref() {
                Some(path) => self.resolver.request(info.token, path, None, Some(pid)),
                None => true,
            },
        };
    }

    /// Records a process from its start event. `image` may be a
    /// `\Device\HarddiskVolumeN\...` path. Its identity is only checked
    /// once it uses the network.
    fn set_started(&mut self, pid: u32, image: &str) {
        let info = ProcessInfo {
            name: file_name(image).to_owned(),
            path: self.devices.to_dos(image),
            token: self.new_token(),
            requested: false,
        };
        self.processes.insert(pid, Some(info));
    }

    /// Waits up to `limit` for identity checks still running, so a final
    /// table is complete.
    fn settle(&mut self, limit: Duration) {
        let deadline = Instant::now() + limit;
        while !self.resolver.is_idle() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
            self.poll();
        }
        self.poll();
    }

    /// Collects identities the background worker has finished.
    fn poll(&mut self) {
        for (token, identity) in self.resolver.finished() {
            if self.identities.len() >= MAX_IDENTITIES {
                self.identities.clear();
            }
            self.identities.insert(token, identity);
        }
    }

    fn forget(&mut self, pid: u32) {
        self.processes.remove(&pid);
    }

    fn get(&self, pid: u32) -> &str {
        self.processes
            .get(&pid)
            .and_then(Option::as_ref)
            .map_or("(unknown)", |info| info.name.as_str())
    }

    /// Token of `pid`'s current process instance, if it has a program file
    /// whose identity can be checked.
    fn token(&self, pid: u32) -> Option<u64> {
        self.processes
            .get(&pid)
            .and_then(Option::as_ref)
            .filter(|info| info.path.is_some())
            .map(|info| info.token)
    }

    /// Publisher text for a process instance: the signer, `UNSIGNED`,
    /// `INVALID SIGNATURE`, `…` while being checked, or `-` if there is no
    /// program file.
    ///
    /// A `?` at the end means the file was checked by path only and could
    /// not be confirmed as the file the process ran.
    fn publisher(&self, token: Option<u64>) -> String {
        let Some(token) = token else {
            return String::from("-");
        };
        match self.identities.get(&token) {
            None => String::from("…"),
            Some(identity) if identity.confirmed_running => {
                truncate(&identity.publisher_text(), PUBLISHER_WIDTH)
            }
            Some(identity) => format!(
                "{}?",
                truncate(&identity.publisher_text(), PUBLISHER_WIDTH - 1)
            ),
        }
    }
}

/// A process that exited recently.
#[derive(Debug)]
struct Exited {
    app: String,
    token: Option<u64>,
    /// Exit time reported by Windows.
    exited_at: SystemTime,
    /// When we learned about the exit, for expiring the entry.
    noted: Instant,
}

/// Processes that exited recently, for attributing late traffic.
#[derive(Debug, Default)]
struct RecentlyExited(HashMap<u32, Exited>);

impl RecentlyExited {
    fn insert(&mut self, pid: u32, app: String, token: Option<u64>, exited_at: SystemTime) {
        let noted = Instant::now();
        self.0.insert(
            pid,
            Exited {
                app,
                token,
                exited_at,
                noted,
            },
        );
    }

    /// Returns the exited process that `event` belongs to, if it is late
    /// traffic from a process that exited recently.
    ///
    /// `current_start` is the start time of the process that now has the
    /// event's ID, if any. Traffic at or after that start belongs to the new
    /// process, even if the events arrive out of order.
    fn owner(&self, event: &NetEvent, current_start: Option<SystemTime>) -> Option<&Exited> {
        let exited = self.0.get(&event.pid)?;
        if exited.noted.elapsed() >= LATE_TRAFFIC_WINDOW {
            return None;
        }
        let newer_process = current_start
            .is_some_and(|start| start >= exited.exited_at && event.timestamp >= start);
        if newer_process {
            return None;
        }
        Some(exited)
    }

    fn expire(&mut self) {
        self.0
            .retain(|_, exited| exited.noted.elapsed() < LATE_TRAFFIC_WINDOW);
    }
}

/// Adds traffic that arrived after its process exited to the matching
/// closed flow, or starts a new closed flow for it.
fn add_late_traffic(closed: &mut VecDeque<Row>, app: &str, token: Option<u64>, event: &NetEvent) {
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
        token,
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
            app: app_name(&key, names),
            token: token_for(&key, names),
            key,
            stats,
        });
    }
}

fn token_for(key: &FlowKey, names: &ProcessNames) -> Option<u64> {
    if key.is_global_overflow() {
        None
    } else {
        names.token(key.pid)
    }
}

fn app_name(key: &FlowKey, names: &ProcessNames) -> String {
    if key.is_global_overflow() {
        String::from("(many processes)")
    } else {
        names.get(key.pid).to_owned()
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
            app: app_name(&key, names),
            token: token_for(&key, names),
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
    if counts.rejected > 0 {
        println!(
            "!! {} DNS events claimed to come from the Windows DNS service but did not: a \
             program may be trying to fake domain names.",
            counts.rejected
        );
    }
    if table.shared_overflow_events() > 0 {
        println!(
            "!! {} events could not be attributed to a process: many processes are flooding the \
             flow table at once, which may be an attempt to evade monitoring.",
            table.shared_overflow_events()
        );
    }
    println!(
        "{:>6}  {:<20} {:<22} {:<5} {:<30} {:<40} {:>10} {:>10}",
        "PID", "APP", "PUBLISHER", "PROTO", "DOMAIN", "REMOTE", "SENT", "RECEIVED"
    );
    for row in rows.iter().take(TOP_ROWS) {
        println!("{}", format_row(row, &names.publisher(row.token)));
    }
    if rows.len() > TOP_ROWS {
        println!("  … and {} more", rows.len() - TOP_ROWS);
    }
}

fn format_row(row: &Row, publisher: &str) -> String {
    let proto = match row.key.protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
    };
    let (domain, remote) = if row.key.is_overflow() {
        (
            String::from("(many)"),
            String::from("(many destinations: flow limit reached)"),
        )
    } else {
        (domain_text(row), row.key.remote.to_string())
    };
    format!(
        "{:>6}  {:<20} {:<22} {:<5} {:<30} {:<40} {:>10} {:>10}",
        row.key.pid,
        truncate(&row.app, 20),
        truncate(publisher, PUBLISHER_WIDTH),
        proto,
        domain,
        remote,
        format_bytes(row.stats.bytes_sent),
        format_bytes(row.stats.bytes_received)
    )
}

/// Domain column text: the name with a trust marker, or `-`.
fn domain_text(row: &Row) -> String {
    match &row.stats.domain {
        Some(label) => match label.source {
            LabelSource::Verified => truncate(&label.name, 30),
            LabelSource::Unverified => format!("{}?", truncate(&label.name, 29)),
            LabelSource::Inferred => format!("{}*", truncate(&label.name, 29)),
        },
        None => String::from("-"),
    }
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

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

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
        add_late_traffic(&mut closed, "curl.exe", None, &late_send(7, 600));
        add_late_traffic(&mut closed, "curl.exe", None, &late_send(7, 24));
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].app, "curl.exe");
        assert_eq!(closed[0].stats.bytes_sent, 624);
    }

    #[test]
    fn late_traffic_goes_to_the_exited_process() {
        let mut exited = RecentlyExited::default();
        exited.insert(7, String::from("old.exe"), None, at(100));
        let mut event = late_send(7, 24);
        event.timestamp = at(101);
        assert_eq!(
            exited.owner(&event, None).map(|e| e.app.as_str()),
            Some("old.exe")
        );
    }

    #[test]
    fn traffic_from_a_new_process_with_a_reused_id_is_not_late_traffic() {
        let mut exited = RecentlyExited::default();
        exited.insert(7, String::from("old.exe"), None, at(100));
        let new_start = Some(at(105));

        let mut new_traffic = late_send(7, 500);
        new_traffic.timestamp = at(106);
        assert!(exited.owner(&new_traffic, new_start).is_none());

        // Late traffic from the old process that arrives out of order, after
        // the new process's start event, still goes to the old process.
        let mut old_traffic = late_send(7, 24);
        old_traffic.timestamp = at(101);
        assert_eq!(
            exited
                .owner(&old_traffic, new_start)
                .map(|e| e.app.as_str()),
            Some("old.exe")
        );
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
