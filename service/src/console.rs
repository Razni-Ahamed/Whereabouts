//! `--console` mode: live table of network flows per app.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use whereabouts_core::dns::{DnsMap, LabelSource};
use whereabouts_core::flow::{FlowKey, FlowStats, FlowTable};
use whereabouts_core::model::{AppIdentity, CaptureEvent, NetEvent, Protocol};
use whereabouts_core::privacy::is_web_browser;
use whereabouts_core::text::display_safe;
use whereabouts_enrich::{ATTRIBUTION, Enricher, Scope, registrable_domain};
use whereabouts_ipc::{DomainTrust, FlowView, MAX_ROWS, PIPE_NAME, Status};
use whereabouts_store::{FlowRecord, Store};
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

/// Longest text sent to clients per field, in characters.
const CLIENT_TEXT: usize = 256;

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
    /// When the flow was closed; `None` for active flows.
    closed_at: Option<Instant>,
    /// Whether it has been saved to the store.
    saved: bool,
}

/// Recently finished flows, for display and for saving.
#[derive(Debug, Default)]
struct Closed {
    rows: VecDeque<Row>,
    /// Rows pushed out of the display list before they were saved; they are
    /// saved at the next opportunity rather than lost. Only kept while a
    /// store is open, and bounded.
    unsaved_evicted: VecDeque<Row>,
    /// Whether evicted rows are kept for saving (only if a store is open).
    keep_evicted: bool,
    /// Rows that could not be kept for saving because the bound was hit.
    lost: u64,
}

/// Most evicted rows waiting to be saved.
const MAX_UNSAVED_EVICTED: usize = 10_000;

impl Closed {
    fn push(&mut self, row: Row) {
        if self.rows.len() >= MAX_CLOSED {
            if let Some(old) = self.rows.pop_front() {
                if !old.saved && self.keep_evicted {
                    if self.unsaved_evicted.len() >= MAX_UNSAVED_EVICTED {
                        self.unsaved_evicted.pop_front();
                        self.lost += 1;
                    }
                    self.unsaved_evicted.push_back(old);
                }
            }
        }
        self.rows.push_back(row);
    }
}

/// How often retention runs while the console is open.
const RETENTION_EVERY: Duration = Duration::from_secs(60 * 60);

/// How the engine runs.
#[derive(Debug, Default)]
pub struct Options {
    /// Stop after this long; `None` to run until stopped.
    pub limit: Option<Duration>,
    /// Print the live table (console mode).
    pub show_table: bool,
    /// Stop when this becomes `true` (service mode).
    pub stop: Option<Arc<AtomicBool>>,
    /// Account allowed to use the pipe; `None` for the current account.
    pub client_sid: Option<String>,
    /// Offline data folder; `None` to search for it (see [`data_dir`]).
    pub data_dir: Option<PathBuf>,
}

/// `--console`: runs the engine with the live table until `limit` passes,
/// or forever if `None`.
pub fn run(limit: Option<Duration>) -> ExitCode {
    // Two captures cannot run at once: starting one ends the other's
    // Windows event session.
    if crate::service_mode::is_running() {
        eprintln!(
            "error: the Whereabouts service is running. See what it sees with --status, or \
             stop it first (as administrator: sc stop Whereabouts)."
        );
        return ExitCode::FAILURE;
    }
    let options = Options {
        limit,
        show_table: true,
        ..Options::default()
    };
    match run_engine(&options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Captures, labels, saves and serves flows until stopped (see [`Options`]).
pub fn run_engine(options: &Options) -> Result<(), String> {
    let (sender, receiver) = mpsc::sync_channel(EVENT_QUEUE);
    let capture = Capture::start(sender).map_err(|error| error.to_string())?;
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
    println!("Publisher: from the program's code signature · ? = checked by file path only, not");
    println!("           confirmed as the file the process ran (e.g. it had already exited)");

    let (enricher, data) = Enricher::load(&options.data_dir.clone().unwrap_or_else(data_dir));
    println!(
        "Offline data: {} tracker domains · {} company domains{}",
        data.tracker_domains,
        data.company_domains,
        if data.missing.is_empty() {
            String::new()
        } else {
            format!(
                " · missing {} (run scripts/update-data.ps1)",
                data.missing.join(", ")
            )
        }
    );
    println!("Data credits: {ATTRIBUTION}");

    let mut store = match crate::storage::open() {
        Ok(mut store) => {
            crate::storage::apply_retention(&mut store);
            println!(
                "Saving finished flows, encrypted, to {}",
                crate::storage::home_dir().display()
            );
            Some(store)
        }
        Err(error) => {
            report!("warning: history will not be saved: {error}");
            None
        }
    };
    let mut last_retention = Instant::now();

    let live: crate::server::SharedState =
        Arc::new(Mutex::new(crate::server::LiveState::default()));
    let serving = match crate::server::start(
        PIPE_NAME,
        options.client_sid.as_deref(),
        Arc::clone(&live),
    ) {
        Ok(()) => {
            println!(
                "Answering Whereabouts clients on {PIPE_NAME} (try --status in another terminal)"
            );
            true
        }
        Err(error) => {
            report!("warning: {error}");
            false
        }
    };

    let started = Instant::now();
    let mut last_draw = Instant::now();
    let mut table = FlowTable::new();
    let mut names = ProcessNames::new();
    let mut closed = Closed {
        keep_evicted: store.is_some(),
        ..Closed::default()
    };
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
            if let Some(store) = store.as_mut() {
                save_closed(store, &mut closed, &names, &enricher, false);
                if last_retention.elapsed() >= RETENTION_EVERY {
                    crate::storage::apply_retention(store);
                    last_retention = Instant::now();
                }
            }
            let view = View::collect(&table, &closed, &names);
            if serving {
                let counts = capture.counts();
                let status = Status {
                    uptime_secs: started.elapsed().as_secs(),
                    events: counts.events,
                    dropped: counts.dropped,
                    unreadable: counts.malformed,
                    rejected: counts.rejected,
                    over_limit: view.over_limit,
                    unattributed: view.unattributed,
                    active_flows: u64::try_from(view.active).unwrap_or(u64::MAX),
                    kernel_events_protected: capture.kernel_events_protected(),
                    saving: store.is_some(),
                    tracker_domains: u64::try_from(data.tracker_domains).unwrap_or(u64::MAX),
                };
                publish(&live, &view, &names, &enricher, status);
            }
            if options.show_table {
                draw(
                    &view,
                    &names,
                    &enricher,
                    capture.counts(),
                    started.elapsed(),
                );
            }
            last_draw = Instant::now();
        }
        if options
            .limit
            .is_some_and(|limit| started.elapsed() >= limit)
        {
            break;
        }
        if options
            .stop
            .as_ref()
            .is_some_and(|stop| stop.load(Ordering::Acquire))
        {
            break;
        }
    }

    names.settle(Duration::from_secs(5));
    if let Some(store) = store.as_mut() {
        save_closed(store, &mut closed, &names, &enricher, true);
        let active: Vec<FlowRecord> = table
            .snapshot()
            .into_iter()
            .map(|(key, stats)| {
                let row = Row {
                    app: app_name(&key, &names),
                    token: token_for(&key, &names),
                    key,
                    stats,
                    closed_at: None,
                    saved: false,
                };
                to_record(&row, &names, &enricher)
            })
            .collect();
        let saved = active.len();
        match store.insert_flows(&active) {
            Ok(()) => println!("Saved {saved} active flows."),
            Err(error) => report!("warning: could not save active flows: {error}"),
        }
    }
    if options.show_table {
        draw(
            &View::collect(&table, &closed, &names),
            &names,
            &enricher,
            capture.counts(),
            started.elapsed(),
        );
    }
    // Release any process event waiting for queue space before stopping.
    drop(receiver);
    if let Err(error) = capture.stop() {
        report!("warning: {error}");
    }
    Ok(())
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

    /// The identity worked out for a process instance, if finished.
    fn identity(&self, token: u64) -> Option<&AppIdentity> {
        self.identities.get(&token)
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
    ///
    /// The text is made safe to show and shortened to `max` characters.
    fn publisher(&self, token: Option<u64>, max: usize) -> String {
        let (text, confirmed) = self.publisher_parts(token);
        marked(&text, if confirmed { "" } else { "?" }, max)
    }

    /// Publisher text (not yet made safe to show) and whether it was
    /// confirmed as the running file. Placeholders count as confirmed:
    /// there is nothing to qualify.
    fn publisher_parts(&self, token: Option<u64>) -> (String, bool) {
        let Some(token) = token else {
            return (String::from("-"), true);
        };
        match self.identities.get(&token) {
            None => (String::from("…"), true),
            Some(identity) => (identity.publisher_text(), identity.confirmed_running),
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
fn add_late_traffic(closed: &mut Closed, app: &str, token: Option<u64>, event: &NetEvent) {
    if event.is_loopback() {
        return;
    }
    let key = FlowKey {
        pid: event.pid,
        protocol: event.protocol,
        remote: event.remote,
    };
    if let Some(row) = closed.rows.iter_mut().rev().find(|row| row.key == key) {
        row.stats.record(event);
        return;
    }
    let mut stats = FlowStats::new(event.timestamp);
    stats.record(event);
    closed.push(Row {
        app: app.to_owned(),
        token,
        key,
        stats,
        closed_at: Some(Instant::now()),
        saved: false,
    });
}

/// Moves finished flows into the bounded `closed` list, keeping their names.
fn close(closed: &mut Closed, names: &ProcessNames, flows: Vec<(FlowKey, FlowStats)>) {
    for (key, stats) in flows {
        closed.push(Row {
            app: app_name(&key, names),
            token: token_for(&key, names),
            key,
            stats,
            closed_at: Some(Instant::now()),
            saved: false,
        });
    }
}

/// Saves finished flows to the store. Normally only flows closed at least
/// [`LATE_TRAFFIC_WINDOW`] ago are saved, because late traffic may still be
/// added to them; with `everything`, all unsaved flows are saved.
fn save_closed(
    store: &mut Store,
    closed: &mut Closed,
    names: &ProcessNames,
    enricher: &Enricher,
    everything: bool,
) {
    let mut records: Vec<FlowRecord> = closed
        .unsaved_evicted
        .drain(..)
        .map(|row| to_record(&row, names, enricher))
        .collect();
    for row in closed.rows.iter_mut().filter(|row| {
        !row.saved
            && (everything
                || row
                    .closed_at
                    .is_some_and(|at| at.elapsed() >= LATE_TRAFFIC_WINDOW))
    }) {
        records.push(to_record(row, names, enricher));
        row.saved = true;
    }
    if closed.lost > 0 {
        report!(
            "warning: {} finished flows could not be kept for saving (too many at once)",
            closed.lost
        );
        closed.lost = 0;
    }
    if records.is_empty() {
        return;
    }
    if let Err(error) = store.insert_flows(&records) {
        report!("warning: could not save {} flows: {error}", records.len());
    }
}

/// Converts a row into what is stored.
///
/// For web browsers, only the registrable domain is stored (`example.com`,
/// not `mail.example.com`): a browser's list of domains is the user's
/// browsing history (design spec, decision D5).
fn to_record(row: &Row, names: &ProcessNames, enricher: &Enricher) -> FlowRecord {
    let identity = row.token.and_then(|token| names.identity(token));
    let (owner, country) = if row.key.is_overflow() {
        (String::from("(many destinations)"), String::from("--"))
    } else {
        owner_and_country(row, enricher)
    };
    let domain = row.stats.domain.as_ref().map(|label| {
        if is_web_browser(&row.app) {
            registrable_domain(&label.name).unwrap_or_else(|| label.name.to_string())
        } else {
            label.name.to_string()
        }
    });
    FlowRecord {
        app_name: row.app.clone(),
        app_path: identity.map(|identity| identity.path.clone()),
        app_sha256: identity.and_then(|identity| identity.sha256.clone()),
        signature: identity.map(|identity| identity.signature.clone()),
        signature_confirmed: identity.is_some_and(|identity| identity.confirmed_running),
        protocol: row.key.protocol,
        remote_ip: row.key.remote.ip(),
        remote_port: row.key.remote.port(),
        domain,
        domain_source: row.stats.domain.as_ref().map(|label| label.source),
        owner: (owner != "-").then_some(owner),
        country: (country != "--").then_some(country),
        first_seen: row.stats.first_seen,
        last_seen: row.stats.last_seen,
        bytes_sent: row.stats.bytes_sent,
        bytes_received: row.stats.bytes_received,
        connections: row.stats.connections,
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

/// All current rows, active and recently closed, largest first, with the
/// table's counters: what one refresh shows.
#[derive(Debug)]
struct View {
    rows: Vec<Row>,
    active: usize,
    closed: usize,
    over_limit: u64,
    unattributed: u64,
}

impl View {
    fn collect(table: &FlowTable, closed: &Closed, names: &ProcessNames) -> Self {
        let mut rows: Vec<Row> = table
            .snapshot()
            .into_iter()
            .map(|(key, stats)| Row {
                app: app_name(&key, names),
                token: token_for(&key, names),
                key,
                stats,
                closed_at: None,
                saved: false,
            })
            .collect();
        let active = rows.len();
        rows.extend(closed.rows.iter().cloned());
        rows.sort_by(|a, b| {
            b.stats
                .total_bytes()
                .cmp(&a.stats.total_bytes())
                .then_with(|| a.key.cmp(&b.key))
        });
        Self {
            rows,
            active,
            closed: closed.rows.len(),
            over_limit: table.overflowed_events(),
            unattributed: table.shared_overflow_events(),
        }
    }
}

/// Replaces what clients see with the latest view.
fn publish(
    live: &Mutex<crate::server::LiveState>,
    view: &View,
    names: &ProcessNames,
    enricher: &Enricher,
    status: Status,
) {
    let max = usize::try_from(MAX_ROWS).unwrap_or(usize::MAX);
    let flows: Vec<FlowView> = view
        .rows
        .iter()
        .take(max)
        .map(|row| flow_view(row, names, enricher))
        .collect();
    let mut live = live.lock().unwrap_or_else(PoisonError::into_inner);
    live.status = status;
    live.flows = flows;
}

/// A row as clients see it. Texts are made safe to show and bounded.
fn flow_view(row: &Row, names: &ProcessNames, enricher: &Enricher) -> FlowView {
    let (domain, owner, country, remote) = if row.key.is_overflow() {
        (
            None,
            None,
            None,
            String::from("(many destinations: flow limit reached)"),
        )
    } else {
        let (owner, country) = owner_and_country(row, enricher);
        (
            row.stats.domain.as_ref(),
            (owner != "-").then(|| truncate(&owner, CLIENT_TEXT)),
            (country != "--").then_some(country),
            row.key.remote.to_string(),
        )
    };
    let (publisher, publisher_confirmed) = names.publisher_parts(row.token);
    FlowView {
        pid: row.key.pid,
        app: truncate(&row.app, CLIENT_TEXT),
        publisher: truncate(&publisher, CLIENT_TEXT),
        publisher_confirmed,
        protocol: String::from(protocol_text(row.key.protocol)),
        domain: domain.map(|label| truncate(&label.name, CLIENT_TEXT)),
        domain_trust: domain.map(|label| domain_trust(label.source)),
        owner,
        country,
        remote,
        bytes_sent: row.stats.bytes_sent,
        bytes_received: row.stats.bytes_received,
        active: row.closed_at.is_none(),
    }
}

fn protocol_text(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
    }
}

fn draw(
    view: &View,
    names: &ProcessNames,
    enricher: &Enricher,
    counts: CaptureCounts,
    elapsed: Duration,
) {
    let rows = &view.rows;
    println!();
    println!(
        "── {}s · {} active flows · {} closed · {} events · {} dropped · {} unreadable · {} over limit ──",
        elapsed.as_secs(),
        view.active,
        view.closed,
        counts.events,
        counts.dropped,
        counts.malformed,
        view.over_limit
    );
    if counts.rejected > 0 {
        println!(
            "!! {} DNS events claimed to come from the Windows DNS service but did not: a \
             program may be trying to fake domain names.",
            counts.rejected
        );
    }
    if view.unattributed > 0 {
        println!(
            "!! {} events could not be attributed to a process: many processes are flooding the \
             flow table at once, which may be an attempt to evade monitoring.",
            view.unattributed
        );
    }
    println!(
        "{:>6}  {:<20} {:<22} {:<5} {:<30} {:<26} {:<2} {:<40} {:>10} {:>10}",
        "PID", "APP", "PUBLISHER", "PROTO", "DOMAIN", "OWNER", "CC", "REMOTE", "SENT", "RECEIVED"
    );
    for row in rows.iter().take(TOP_ROWS) {
        println!(
            "{}",
            format_row(row, &names.publisher(row.token, PUBLISHER_WIDTH), enricher)
        );
    }
    if rows.len() > TOP_ROWS {
        println!("  … and {} more", rows.len() - TOP_ROWS);
    }
}

fn format_row(row: &Row, publisher: &str, enricher: &Enricher) -> String {
    let proto = protocol_text(row.key.protocol);
    let (domain, owner, country, remote) = if row.key.is_overflow() {
        (
            String::from("(many)"),
            String::from("-"),
            String::from("--"),
            String::from("(many destinations: flow limit reached)"),
        )
    } else {
        let (owner, country) = owner_and_country(row, enricher);
        (
            domain_text(row, 30).unwrap_or_else(|| String::from("-")),
            owner,
            country,
            row.key.remote.to_string(),
        )
    };
    format!(
        "{:>6}  {:<20} {:<22} {:<5} {:<30} {:<26} {:<2} {:<40} {:>10} {:>10}",
        row.key.pid,
        truncate(&row.app, 20),
        truncate(publisher, PUBLISHER_WIDTH),
        proto,
        domain,
        truncate(&owner, 26),
        country,
        remote,
        format_bytes(row.stats.bytes_sent),
        format_bytes(row.stats.bytes_received)
    )
}

/// OWNER and CC column texts for a row.
///
/// The owner is the company and kind of service when the domain is a known
/// tracking or analytics service, otherwise the organisation that runs the
/// IP address's network. A domain the app only reported about itself (`?`)
/// could be fake, so its company is not used; the network owner, which
/// comes from the IP address itself, is shown instead.
fn owner_and_country(row: &Row, enricher: &Enricher) -> (String, String) {
    let ip = enricher.ip(row.key.remote.ip());
    let country = ip.country.clone().unwrap_or_else(|| String::from("--"));
    match ip.scope {
        Scope::Local => return (String::from("local network"), country),
        Scope::Multicast => return (String::from("multicast"), country),
        Scope::Internet => {}
    }
    let trusted_domain = row
        .stats
        .domain
        .as_ref()
        .filter(|label| label.source != LabelSource::Unverified);
    if let Some(label) = trusted_domain {
        let info = enricher.domain(&label.name);
        if let Some(company) = info.company {
            return (format!("{} · {}", company.name, company.category), country);
        }
        if info.tracker {
            let network = ip.network.as_deref().unwrap_or("unknown");
            return (format!("tracker · {network}"), country);
        }
    }
    (ip.network.unwrap_or_else(|| String::from("-")), country)
}

/// Finds the folder with the offline data files: `WHEREABOUTS_DATA`, a
/// `data` folder next to the program or in the current folder, or the
/// project's `data` folder for development builds.
pub fn data_dir() -> PathBuf {
    use std::path::PathBuf;
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::var_os("WHEREABOUTS_DATA") {
        candidates.push(PathBuf::from(dir));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("data"));
            // target\debug\whereabouts-service.exe -> project\data
            candidates.push(dir.join("..").join("..").join("data"));
        }
    }
    candidates.push(PathBuf::from("data"));
    candidates
        .iter()
        .find(|dir| dir.join(whereabouts_enrich::EASYPRIVACY_FILE).is_file())
        .cloned()
        .unwrap_or_else(|| PathBuf::from("data"))
}

/// Domain text with its trust marker, at most `max` characters, if the
/// flow has a domain.
fn domain_text(row: &Row, max: usize) -> Option<String> {
    let label = row.stats.domain.as_ref()?;
    Some(marked(
        &label.name,
        domain_trust(label.source).marker(),
        max,
    ))
}

fn domain_trust(source: LabelSource) -> DomainTrust {
    match source {
        LabelSource::Verified => DomainTrust::Verified,
        LabelSource::Unverified => DomainTrust::AppReported,
        LabelSource::Inferred => DomainTrust::Guessed,
    }
}

/// Like [`truncate`], but keeps `marker` (such as a `?` trust marker) at
/// the end: only the text before it is shortened.
pub(crate) fn marked(text: &str, marker: &str, max: usize) -> String {
    let room = max.saturating_sub(marker.chars().count());
    format!("{}{marker}", truncate(text, room))
}

/// Returns the last component of a Windows or Unix path.
fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Makes `text` safe to show (see [`display_safe`]) and shortens it to at
/// most `max` characters, marking the cut with `…`.
pub(crate) fn truncate(text: &str, max: usize) -> String {
    let text = display_safe(text);
    if text.chars().count() <= max {
        text
    } else {
        let kept: String = text.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

/// Formats a byte count for people, e.g. `1.5 MB`.
pub(crate) fn format_bytes(bytes: u64) -> String {
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
    use std::sync::Arc;
    use whereabouts_core::dns::DomainLabel;
    use whereabouts_enrich::{CompanyList, GeoDatabases, TrackerList};

    fn enricher() -> Enricher {
        Enricher::from_parts(
            TrackerList::parse("||tracker.example^\n"),
            CompanyList::built_in(),
            GeoDatabases::default(),
        )
    }

    fn row_to(remote: &str, domain: Option<(&str, LabelSource)>) -> Row {
        let mut stats = FlowStats::new(SystemTime::UNIX_EPOCH);
        stats.domain = domain.map(|(name, source)| DomainLabel {
            name: Arc::from(name),
            source,
        });
        Row {
            app: String::from("app.exe"),
            token: None,
            key: FlowKey {
                pid: 7,
                protocol: Protocol::Tcp,
                remote: remote.parse().unwrap(),
            },
            stats,
            closed_at: None,
            saved: false,
        }
    }

    #[test]
    fn owner_shows_the_company_behind_known_services() {
        let row = row_to(
            "142.250.0.1:443",
            Some(("app-measurement.com", LabelSource::Verified)),
        );
        let (owner, _) = owner_and_country(&row, &enricher());
        assert_eq!(owner, "Google (Firebase) · analytics");
    }

    #[test]
    fn owner_marks_listed_trackers_without_a_known_company() {
        let row = row_to(
            "203.0.113.5:443",
            Some(("x.tracker.example", LabelSource::Inferred)),
        );
        let (owner, _) = owner_and_country(&row, &enricher());
        assert!(owner.starts_with("tracker · "), "{owner}");
    }

    #[test]
    fn a_name_only_the_app_reported_never_supplies_the_company() {
        // The app could claim any name, so the network owner is used instead.
        let row = row_to(
            "203.0.113.5:443",
            Some(("app-measurement.com", LabelSource::Unverified)),
        );
        let (owner, _) = owner_and_country(&row, &enricher());
        assert_eq!(owner, "-");
    }

    #[test]
    fn browsers_store_only_the_registrable_domain() {
        let names = ProcessNames::new();
        let mut row = row_to(
            "203.0.113.5:443",
            Some(("mail.private.example.com", LabelSource::Verified)),
        );
        row.app = String::from("chrome.exe");
        let record = to_record(&row, &names, &enricher());
        assert_eq!(record.domain.as_deref(), Some("example.com"));

        // Other apps keep the full name.
        row.app = String::from("claude.exe");
        let record = to_record(&row, &names, &enricher());
        assert_eq!(record.domain.as_deref(), Some("mail.private.example.com"));
    }

    #[test]
    fn local_addresses_are_labelled_as_such() {
        let row = row_to("192.168.1.1:53", None);
        assert_eq!(owner_and_country(&row, &enricher()).0, "local network");
    }
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
    fn evicted_rows_are_only_kept_when_saving_and_are_bounded() {
        let row = || row_to("203.0.113.5:443", None);
        // Not saving: evicted rows are simply dropped.
        let mut closed = Closed::default();
        for _ in 0..MAX_CLOSED + 10 {
            closed.push(row());
        }
        assert_eq!(closed.rows.len(), MAX_CLOSED);
        assert!(closed.unsaved_evicted.is_empty());

        // Saving: they are kept, up to the bound.
        let mut closed = Closed {
            keep_evicted: true,
            ..Closed::default()
        };
        for _ in 0..MAX_CLOSED + MAX_UNSAVED_EVICTED + 5 {
            closed.push(row());
        }
        assert_eq!(closed.unsaved_evicted.len(), MAX_UNSAVED_EVICTED);
        assert_eq!(closed.lost, 5);
    }

    #[test]
    fn late_traffic_merges_into_the_closed_flow() {
        let mut closed = Closed::default();
        add_late_traffic(&mut closed, "curl.exe", None, &late_send(7, 600));
        add_late_traffic(&mut closed, "curl.exe", None, &late_send(7, 24));
        assert_eq!(closed.rows.len(), 1);
        assert_eq!(closed.rows[0].app, "curl.exe");
        assert_eq!(closed.rows[0].stats.bytes_sent, 624);
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
