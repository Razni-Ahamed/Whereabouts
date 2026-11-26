//! `--console` mode: live table of network flows per app.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use whereabouts_core::dns::{DnsMap, DomainLabel, LabelSource};
use whereabouts_core::flow::{FlowKey, FlowStats, FlowTable};
use whereabouts_core::model::{AppIdentity, CaptureEvent, NetEvent, Protocol};
use whereabouts_core::privacy::is_web_browser;
use whereabouts_core::text::display_safe;
use whereabouts_enrich::{ATTRIBUTION, Enricher, Scope, registrable_domain};
use whereabouts_ipc::{DomainTrust, FlowView, MAX_FLOW_PATH, MAX_ROWS, PIPE_NAME, Status};
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
pub(crate) const MAX_IDENTITIES: usize = 20_000;

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
    /// Whether the behaviour Learner has had it (each finished flow once,
    /// whether history is saved or not).
    learned: bool,
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
        if self.rows.len() >= MAX_CLOSED
            && let Some(old) = self.rows.pop_front()
            && !old.saved
            && self.keep_evicted
        {
            if self.unsaved_evicted.len() >= MAX_UNSAVED_EVICTED {
                self.unsaved_evicted.pop_front();
                self.lost += 1;
            }
            self.unsaved_evicted.push_back(old);
        }
        self.rows.push_back(row);
    }
}

/// How often retention runs while the console is open.
pub(crate) const RETENTION_EVERY: Duration = Duration::from_secs(60 * 60);

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
    /// Lab only (`--record-connections`): append each new connection to
    /// this file (see [`crate::connection_log`]). Never set for the service.
    pub record_connections: Option<PathBuf>,
}

/// `--console`: runs the engine with the live table until `limit` passes,
/// or forever if `None`, recording connections to `record_connections` if
/// given (lab only).
pub fn run(limit: Option<Duration>, record_connections: Option<PathBuf>) -> ExitCode {
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
        record_connections,
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

    let (mut enricher, mut data) =
        Enricher::load(&options.data_dir.clone().unwrap_or_else(data_dir));
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
            crate::storage::expire_profiles(&mut store, SystemTime::now());
            Some(store)
        }
        Err(error) => {
            report!("warning: history will not be saved: {error}");
            None
        }
    };
    let mut history = crate::history::HistorySwitch::load(store.as_ref());
    if store.is_some() {
        if history.on() {
            println!(
                "Saving finished flows, encrypted, to {}",
                crate::storage::home_dir().display()
            );
        } else {
            println!("Not saving finished flows: history is turned off");
        }
    }
    let mut last_retention = Instant::now();
    let mut connection_log = match &options.record_connections {
        Some(path) => {
            let log = crate::connection_log::ConnectionLog::open(path)
                .map_err(|error| format!("could not open {} ({error})", path.display()))?;
            println!(
                "Lab: recording each new connection to {} (NOT encrypted)",
                path.display()
            );
            Some(log)
        }
        None => None,
    };
    let mut new_apps = crate::apps::NewApps::load(store.as_mut(), SystemTime::now());
    let mut detector = crate::alerts::load_detector();
    // Learns each app's usual behaviour (only while a store is open).
    let mut learning = crate::learning::Learning::new(SystemTime::now());
    let mut blocking = crate::blocking::Blocking::start(
        whereabouts_win_firewall::Firewall::open,
        store.as_ref(),
        SystemTime::now(),
    );
    // App rules from before fingerprints existed are pinned now, once.
    blocking.pin_existing(store.as_mut());

    // Clients ask the engine for work only it can do (deleting everything)
    // through this channel.
    let (command_sender, commands) = mpsc::channel::<crate::server::EngineCommand>();
    let live: crate::server::SharedState = Arc::new(Mutex::new(crate::server::LiveState {
        commands: Some(command_sender),
        ..crate::server::LiveState::default()
    }));
    // If another program holds the pipe name, this keeps trying; status is
    // published either way, so clients see it as soon as the pipe is up.
    crate::server::start_or_retry(
        PIPE_NAME,
        options.client_sid.clone(),
        Arc::clone(&live),
        |live| {
            println!(
                "Answering Whereabouts clients on {PIPE_NAME} (try --status in another terminal)"
            );
            let updates = crate::updates::start(Arc::clone(live));
            live.lock().unwrap_or_else(PoisonError::into_inner).updates = Some(updates);
        },
    );

    let started = Instant::now();
    let mut last_draw = Instant::now();
    let mut table = FlowTable::new();
    let mut names = ProcessNames::new();
    let mut closed = Closed {
        keep_evicted: store.is_some() && history.on(),
        ..Closed::default()
    };
    let mut exited = RecentlyExited::default();
    // Start time of each running process, so that a process is identified by
    // its ID *and* start time, not by its ID alone.
    let mut starts: HashMap<u32, SystemTime> = HashMap::new();
    let mut dns = DnsMap::new();
    // Names Windows looked up before Whereabouts started.
    let prefilled = prefill_from_cache(&mut dns, SystemTime::now());
    if prefilled > 0 {
        println!("Read {prefilled} names from Windows' DNS cache");
    }

    loop {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(CaptureEvent::Net(event)) => {
                let current_start = starts.get(&event.pid).copied();
                if let Some(owner) = exited.owner(&event, current_start) {
                    add_late_traffic(&mut closed, &owner.app, owner.token, &event);
                } else {
                    // Look the process up while it is still running.
                    names.note_traffic(event.pid);
                    if let Some((app, path)) = names.first_traffic(event.pid)
                        && new_apps.seen(store.as_mut(), &path, SystemTime::now())
                    {
                        live.lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push_notice(
                                whereabouts_ipc::NoticeKind::NewApp {
                                    app: truncate(&app, CLIENT_TEXT),
                                    path: truncate(&path, CLIENT_TEXT * 2),
                                },
                                SystemTime::now(),
                            );
                    }
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
                aliases,
                addresses,
                timestamp,
            }) => {
                dns.record_confirmed(&name, &addresses, timestamp);
                dns.record_confirmed_aliases(&name, &aliases, timestamp);
                blocking.on_confirmed_answer(&name, &aliases, &addresses, SystemTime::now());
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        for identity in names.poll() {
            block_if_copy(&identity, &mut blocking, store.as_mut(), &live);
        }
        while let Ok(command) = commands.try_recv() {
            match command {
                crate::server::EngineCommand::DeleteAll { reply } => {
                    let result = delete_everything(&mut store, &mut closed, &mut learning);
                    if result.is_ok() {
                        new_apps.reset(store.as_mut(), SystemTime::now());
                    }
                    let _ = reply.send(result);
                }
                crate::server::EngineCommand::SetSaveHistory {
                    save,
                    delete_saved,
                    reply,
                } => {
                    let result =
                        set_save_history(&mut store, &mut closed, &mut history, save, delete_saved);
                    let _ = reply.send(result);
                }
                crate::server::EngineCommand::ReloadData => {
                    if options.data_dir.is_none() {
                        let (fresh, report) = Enricher::load(&data_dir());
                        if report.missing.is_empty() {
                            enricher = fresh;
                            data = report;
                            println!(
                                "Offline data reloaded: {} tracker domains",
                                data.tracker_domains
                            );
                        } else {
                            report!(
                                "warning: the updated data is incomplete; keeping the old data"
                            );
                        }
                    }
                }
                crate::server::EngineCommand::ReloadDrop => {
                    detector = crate::alerts::load_detector();
                }
                crate::server::EngineCommand::Rules { command, reply } => {
                    // A new domain rule (or resuming) also applies to names
                    // still in Windows' DNS cache: their answers are not
                    // confirmed again until the cache entry expires, so the
                    // confirmed answers already seen are replayed.
                    let replay = matches!(
                        command,
                        crate::blocking::RuleCommand::Add(_)
                            | crate::blocking::RuleCommand::SetPaused(false)
                    );
                    let now = SystemTime::now();
                    let answer = blocking.answer(store.as_mut(), command, now);
                    if replay && !matches!(answer, whereabouts_ipc::Response::Error { .. }) {
                        // Also what Windows still has cached from before.
                        prefill_from_cache(&mut dns, now);
                        for (name, aliases, addresses) in dns.confirmed_answers(now) {
                            blocking.on_confirmed_answer(&name, &aliases, &addresses, now);
                        }
                    }
                    let _ = reply.send(answer);
                }
                crate::server::EngineCommand::Behaviour { command, reply } => {
                    // Through the Learner, so its cached profiles and open
                    // alerts follow the change.
                    let result = learning.answer(store.as_mut(), command, SystemTime::now());
                    let _ = reply.send(result);
                }
            }
        }
        if last_draw.elapsed() >= REFRESH {
            exited.expire();
            dns.expire(SystemTime::now());
            blocking.expire(SystemTime::now());
            close(
                &mut closed,
                &names,
                table.take_idle(SystemTime::now(), IDLE_AFTER),
            );
            let mut raised = Vec::new();
            if let Some(store) = store.as_mut() {
                learning.tick(store, &enricher, SystemTime::now());
                raised.extend(store_finished(
                    store,
                    &mut closed,
                    &names,
                    &enricher,
                    history,
                    &mut learning,
                    false,
                ));
                if last_retention.elapsed() >= RETENTION_EVERY {
                    crate::storage::apply_retention(store);
                    learning.expire(store, SystemTime::now());
                    last_retention = Instant::now();
                }
            }
            let view = View::collect(&table, &closed, &names);
            if let Some(log) = connection_log.as_mut() {
                let flows: Vec<crate::learning::FlowInput<'_>> = view
                    .rows
                    .iter()
                    .map(|row| flow_input(row, &names))
                    .collect();
                log.record(&flows, SystemTime::now());
            }
            if let Some(store) = store.as_mut() {
                let now = SystemTime::now();
                for row in view.rows.iter().filter(|row| !row.key.is_overflow()) {
                    let facts = crate::alerts::FlowFacts {
                        key: row.key,
                        app: &row.app,
                        path: row
                            .token
                            .and_then(|token| names.identity(token))
                            .map(|identity| identity.path.as_str()),
                        domain: row
                            .stats
                            .domain
                            .as_ref()
                            .filter(|label| label.source != LabelSource::Unverified)
                            .map(|label| label.name.as_ref()),
                        aliases: row
                            .stats
                            .domain
                            .as_ref()
                            .filter(|label| label.source != LabelSource::Unverified)
                            .map_or(&[][..], |label| &label.aliases[..]),
                    };
                    raised.extend(detector.check_flow(&facts, &enricher, store, now));
                }
                raised.extend(detector.check_counters(
                    capture.counts().rejected,
                    view.unattributed,
                    store,
                    now,
                ));
                for error in detector.take_errors() {
                    report!("warning: {error}");
                }
                raised.extend(learn_traffic(
                    &mut learning,
                    &view.rows,
                    &names,
                    &enricher,
                    store,
                    now,
                ));
                if !raised.is_empty() {
                    let mut state = live.lock().unwrap_or_else(PoisonError::into_inner);
                    for alert in &raised {
                        state.push_notice(crate::alerts::notice(alert), now);
                    }
                }
            }
            let counts = capture.counts();
            let (block_rules, blocking_paused) = blocking.summary();
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
                saving: store.is_some() && history.on(),
                save_history: history.choice(),
                tracker_domains: u64::try_from(data.tracker_domains).unwrap_or(u64::MAX),
                block_rules,
                blocking_paused,
                drop_list: detector.has_drop(),
                // Filled in from the updater's state when answering.
                lists: whereabouts_ipc::ListsView::default(),
                behaviour_learning: store.is_some().then(|| learning.status_text()),
            };
            publish(&live, &view, &names, &enricher, status);
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
        // Alerts raised now are saved; there is no one left to notify.
        let _ = store_finished(
            store,
            &mut closed,
            &names,
            &enricher,
            history,
            &mut learning,
            true,
        );
        // Flows still open end here, so they are learned (and saved) too.
        let active: Vec<Row> = table
            .snapshot()
            .into_iter()
            .map(|(key, stats)| Row {
                app: app_name(&key, &names),
                token: token_for(&key, &names),
                key,
                stats,
                closed_at: None,
                saved: false,
                learned: false,
            })
            .collect();
        let now = SystemTime::now();
        for row in &active {
            let _ = learning.finished(&flow_input(row, &names), &enricher, store, now);
        }
        learning.shutdown(store, now);
        if history.on() {
            let records: Vec<FlowRecord> = active
                .iter()
                .map(|row| to_record(row, &names, &enricher))
                .collect();
            match store.insert_flows(&records) {
                Ok(()) => println!("Saved {} active flows.", records.len()),
                Err(error) => report!("warning: could not save active flows: {error}"),
            }
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
    /// Whether its first use of the network has been handled.
    noted: bool,
    /// A WebView2 process showing another app's web content: `name`,
    /// `path` and `token` are that app's (see [`ProcessNames::note_traffic`]).
    web_content: bool,
}

/// The program file every WebView2 app's web content runs in.
const WEBVIEW2: &str = "msedgewebview2.exe";

/// Whether `path` is the installed WebView2 runtime's program, in its
/// folder under Program Files, which only administrators can change. Any
/// program can call itself `msedgewebview2.exe`; only the real runtime may
/// be credited to the app that started it, or a program could borrow that
/// app's name and publisher (and get the app blocked instead of itself).
fn is_webview2_runtime(path: &str) -> bool {
    use std::sync::OnceLock;
    use whereabouts_win_secrets::{KnownFolder, known_folder};
    static ROOTS: OnceLock<Vec<String>> = OnceLock::new();
    let roots = ROOTS.get_or_init(|| {
        [KnownFolder::ProgramFilesX86, KnownFolder::ProgramFiles]
            .into_iter()
            .filter_map(|folder| known_folder(folder).ok())
            .map(|dir| {
                let root = dir.join(r"Microsoft\EdgeWebView\Application");
                format!("{}\\", root.to_string_lossy().to_lowercase())
            })
            .collect()
    });
    let path = path.to_lowercase();
    file_name(&path) == WEBVIEW2
        && !path.contains(r"\..\")
        && roots.iter().any(|root| path.starts_with(root.as_str()))
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
    ///
    /// A WebView2 process (`msedgewebview2.exe`, one file shared by every
    /// WebView2 app) is credited to the app that started it: it fetches that
    /// app's web pages and ads, and "msedgewebview2 contacted Google" named
    /// no app at all. It takes the app's name, path and identity, so the
    /// app's publisher is shown and blocking blocks the app (whose web
    /// content Whereabouts then keeps offline too).
    fn note_traffic(&mut self, pid: u32) {
        if !self.processes.contains_key(&pid) {
            let token = self.new_token();
            let info = process::image_path(pid).map(|path| ProcessInfo {
                name: file_name(&path).to_owned(),
                path: self.devices.to_dos(&path),
                token,
                requested: false,
                noted: false,
                web_content: false,
            });
            self.processes.insert(pid, info);
        }
        let Some(Some(info)) = self.processes.get(&pid) else {
            return;
        };
        if info.requested {
            return;
        }
        if info.path.as_deref().is_some_and(is_webview2_runtime)
            && let Some((host, _)) = process::ancestor_not_named(pid, WEBVIEW2)
        {
            self.note_traffic(host);
            if let Some(Some(host_info)) = self.processes.get(&host) {
                let shown = ProcessInfo {
                    name: host_info.name.clone(),
                    path: host_info.path.clone(),
                    token: host_info.token,
                    requested: true,
                    noted: false,
                    web_content: true,
                };
                self.processes.insert(pid, Some(shown));
                return;
            }
        }
        let Some(Some(info)) = self.processes.get_mut(&pid) else {
            return;
        };
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

    /// The program path of `pid` the first time this process instance uses
    /// the network (call after [`ProcessNames::note_traffic`]); `None`
    /// afterwards, or if the path is not known.
    fn first_traffic(&mut self, pid: u32) -> Option<(String, String)> {
        let info = self.processes.get_mut(&pid)?.as_mut()?;
        if info.noted {
            return None;
        }
        info.noted = true;
        Some((info.name.clone(), info.path.clone()?))
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
            noted: false,
            web_content: false,
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

    /// Collects identities the background worker has finished, and returns
    /// them.
    fn poll(&mut self) -> Vec<AppIdentity> {
        let mut finished = Vec::new();
        for (token, identity) in self.resolver.finished() {
            if self.identities.len() >= MAX_IDENTITIES {
                self.identities.clear();
            }
            finished.push(identity.clone());
            self.identities.insert(token, identity);
        }
        finished
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

    /// Whether `pid` is a WebView2 process showing another app's web content
    /// (its name and path are that app's).
    fn is_web_content(&self, pid: u32) -> bool {
        self.processes
            .get(&pid)
            .and_then(Option::as_ref)
            .is_some_and(|info| info.web_content)
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

/// Blocks the program `identity` describes if it is a byte-identical copy
/// (or a link) of a blocked program in another place, with a rule of its own
/// that shows on the Rules screen, and tells the app.
///
/// Unconfirmed checks count too (the process exited before its file could be
/// locked, as a short download does): what is blocked is the path, and the
/// file now at that path is the blocked program, whichever file ran.
fn block_if_copy(
    identity: &AppIdentity,
    blocking: &mut crate::blocking::Blocking<whereabouts_win_firewall::Firewall>,
    store: Option<&mut Store>,
    live: &Mutex<crate::server::LiveState>,
) {
    let (Some(sha256), Some(store)) = (identity.sha256.as_deref(), store) else {
        return;
    };
    let now = SystemTime::now();
    let Some(original) = blocking.copy_of(store, &identity.path, sha256, now) else {
        return;
    };
    match blocking.block_copy(store, &identity.path, &original, now) {
        whereabouts_ipc::Response::RuleAdded { already: false, .. } => {
            println!("Blocked {}: a copy of blocked {original}", identity.path);
            live.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_notice(
                    whereabouts_ipc::NoticeKind::BlockedCopy {
                        app: truncate(file_name(&identity.path), CLIENT_TEXT),
                        path: truncate(&identity.path, CLIENT_TEXT * 2),
                        of: truncate(&original, CLIENT_TEXT * 2),
                    },
                    now,
                );
        }
        whereabouts_ipc::Response::Error { message } => {
            report!(
                "warning: could not block {}, a copy of blocked {original}: {message}",
                identity.path
            );
        }
        _ => {}
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
        learned: false,
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
            learned: false,
        });
    }
}

/// The alias of a trusted label that revealed a tracker or company when
/// the name alone did not (a tracker hidden behind a site's own name).
fn revealing_alias(label: &DomainLabel, enricher: &Enricher) -> Option<String> {
    if label.source == LabelSource::Unverified {
        return None;
    }
    let known = |name: &str| {
        let info = enricher.domain(name);
        info.tracker || info.company.is_some()
    };
    if known(&label.name) {
        return None;
    }
    label
        .aliases
        .iter()
        .find(|alias| known(alias))
        .map(|alias| truncate(alias, CLIENT_TEXT))
}

/// Records what Windows' DNS cache holds as confirmed answers (the DNS
/// service filled it). Returns how many names were read.
fn prefill_from_cache(dns: &mut DnsMap, now: SystemTime) -> usize {
    let answers = whereabouts_win_capture::dns_cache::cached_answers();
    for answer in &answers {
        dns.record_confirmed(&answer.name, &answer.addresses, now);
        dns.record_confirmed_aliases(&answer.name, &answer.aliases, now);
    }
    answers.len()
}

/// Whether a finished flow is ready to be saved and learned at `now`: it
/// closed at least [`LATE_TRAFFIC_WINDOW`] ago (late traffic may still be
/// added to it, and its program's identity may still arrive), or
/// `everything` is wanted.
fn is_due(row: &Row, everything: bool, now: Instant) -> bool {
    everything
        || row
            .closed_at
            .is_some_and(|at| now.saturating_duration_since(at) >= LATE_TRAFFIC_WINDOW)
}

/// Saves finished flows to the store: those due at `now` (see [`is_due`]),
/// and those pushed off the live list.
fn save_closed(
    store: &mut Store,
    closed: &mut Closed,
    names: &ProcessNames,
    enricher: &Enricher,
    everything: bool,
    now: Instant,
) {
    let mut records: Vec<FlowRecord> = closed
        .unsaved_evicted
        .drain(..)
        .map(|row| to_record(&row, names, enricher))
        .collect();
    for row in closed
        .rows
        .iter_mut()
        .filter(|row| !row.saved && is_due(row, everything, now))
    {
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

/// Hands finished flows to the behaviour Learner, then saves them if
/// history is on; otherwise forgets them, so they are only ever shown live.
/// Profiles are learned either way. Returns the behaviour alerts raised.
fn store_finished(
    store: &mut Store,
    closed: &mut Closed,
    names: &ProcessNames,
    enricher: &Enricher,
    history: crate::history::HistorySwitch,
    learning: &mut crate::learning::Learning,
    everything: bool,
) -> Vec<crate::alerts::Raised> {
    let now = Instant::now();
    let raised = learn_finished(store, closed, names, enricher, learning, everything, now);
    if history.on() {
        save_closed(store, closed, names, enricher, everything, now);
    } else {
        forget_unsaved(closed);
    }
    raised
}

/// Gives each finished flow to the behaviour Learner once, when it is due
/// for saving too (see [`is_due`]; rows pushed off the live list are saved
/// at once, so they are learned at once). Flows that
/// finish while saved history is still being turned into profiles are
/// passed over: the saved ones are learned from the history instead.
fn learn_finished(
    store: &mut Store,
    closed: &mut Closed,
    names: &ProcessNames,
    enricher: &Enricher,
    learning: &mut crate::learning::Learning,
    everything: bool,
    now: Instant,
) -> Vec<crate::alerts::Raised> {
    let time = SystemTime::now();
    let evicted = closed.unsaved_evicted.iter_mut().map(|row| (row, true));
    let shown = closed.rows.iter_mut().map(|row| (row, false));
    let mut raised = Vec::new();
    for (row, evicted) in evicted.chain(shown) {
        if row.learned || !(evicted || is_due(row, everything, now)) {
            continue;
        }
        row.learned = true;
        raised.extend(learning.finished(&flow_input(row, names), enricher, store, time));
    }
    raised
}

/// Adds what the shown rows did since the last tick to their apps'
/// behaviour profiles. Returns the behaviour alerts raised.
fn learn_traffic(
    learning: &mut crate::learning::Learning,
    rows: &[Row],
    names: &ProcessNames,
    enricher: &Enricher,
    store: &mut Store,
    now: SystemTime,
) -> Vec<crate::alerts::Raised> {
    let flows: Vec<crate::learning::FlowInput<'_>> =
        rows.iter().map(|row| flow_input(row, names)).collect();
    learning.traffic(&flows, enricher, store, now)
}

/// A row as the behaviour Learner sees it.
fn flow_input<'a>(row: &'a Row, names: &'a ProcessNames) -> crate::learning::FlowInput<'a> {
    crate::learning::FlowInput {
        key: row.key,
        app: &row.app,
        identity: row.token.and_then(|token| names.identity(token)),
        stats: &row.stats,
    }
}

/// Marks every finished flow as dealt with and drops those waiting to be
/// saved, so none of them is saved later. They stay on the live list.
fn forget_unsaved(closed: &mut Closed) {
    closed.unsaved_evicted.clear();
    closed.lost = 0;
    for row in &mut closed.rows {
        row.saved = true;
    }
}

/// Saves the user's choice whether to save history and applies it. Turning
/// it off forgets finished flows not saved yet (nothing more is saved), and
/// with `delete_saved` deletes the saved flows and hourly totals. Turning
/// it on saves only flows that finish from then on.
fn set_save_history(
    store: &mut Option<Store>,
    closed: &mut Closed,
    history: &mut crate::history::HistorySwitch,
    save: bool,
    delete_saved: bool,
) -> Result<(), String> {
    let Some(store) = store.as_mut() else {
        return Err(String::from(
            "the database could not be opened, so nothing is saved anyway",
        ));
    };
    // Flows that finished while history was off are never saved, even if
    // it is turned on before they were forgotten.
    if !(save && history.on()) {
        forget_unsaved(closed);
    }
    let result = history.set(store, save, delete_saved);
    closed.keep_evicted = history.on();
    result
}

/// Deletes all saved data, including behaviour profiles, and forgets
/// finished flows that were waiting to be saved or learned, so nothing from
/// before reappears. Flows still open are saved and learned as usual when
/// they finish.
fn delete_everything(
    store: &mut Option<Store>,
    closed: &mut Closed,
    learning: &mut crate::learning::Learning,
) -> Result<(), String> {
    forget_unsaved(closed);
    for row in &mut closed.rows {
        row.learned = true;
    }
    learning.reset();
    let result = match store.as_mut() {
        Some(store) => store.wipe().map_err(|e| e.to_string()),
        // Not saving now, but older data may exist.
        None => {
            crate::storage::open().and_then(|mut store| store.wipe().map_err(|e| e.to_string()))
        }
    };
    match &result {
        Ok(()) => report!("All saved data was deleted at the user's request"),
        Err(error) => report!("warning: deleting all saved data failed: {error}"),
    }
    result
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
                learned: false,
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
        // A shortened path would name another program, so long ones are
        // left out.
        path: row
            .token
            .and_then(|token| names.identity(token))
            .map(|identity| identity.path.clone())
            .filter(|path| path.chars().count() <= MAX_FLOW_PATH),
        publisher: truncate(&publisher, CLIENT_TEXT),
        publisher_confirmed,
        protocol: String::from(protocol_text(row.key.protocol)),
        domain: domain.map(|label| truncate(&label.name, CLIENT_TEXT)),
        domain_trust: domain.map(|label| domain_trust(label.source)),
        via: domain.and_then(|label| revealing_alias(label, enricher)),
        owner,
        country,
        remote,
        bytes_sent: row.stats.bytes_sent,
        bytes_received: row.stats.bytes_received,
        active: row.closed_at.is_none(),
        web_content: names.is_web_content(row.key.pid),
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
        // The name itself first, then the names it points to (a tracker or
        // company hidden behind a site's own name).
        let names = std::iter::once(&label.name).chain(label.aliases.iter());
        for name in names {
            let info = enricher.domain(name);
            if let Some(company) = info.company {
                return (format!("{} · {}", company.name, company.category), country);
            }
            if info.tracker {
                let network = ip.network.as_deref().unwrap_or("unknown");
                return (format!("tracker · {network}"), country);
            }
        }
    }
    (ip.network.unwrap_or_else(|| String::from("-")), country)
}

/// Finds the folder with the offline data files: `WHEREABOUTS_DATA`, the
/// last accepted signed data update, a `data` folder next to the program
/// or in the current folder, or the project's `data` folder for
/// development builds.
pub fn data_dir() -> PathBuf {
    use std::path::PathBuf;
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::var_os("WHEREABOUTS_DATA") {
        candidates.push(PathBuf::from(dir));
    }
    // Only a bundle the updater verified and swapped in has a manifest.
    let updated = crate::updates::data_home();
    if updated.join(whereabouts_data_bundle::MANIFEST).is_file() {
        candidates.push(updated);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join("data"));
        // target\debug\whereabouts-service.exe -> project\data
        candidates.push(dir.join("..").join("..").join("data"));
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

/// For each row of an app table, given as (file name, full path if known):
/// when another row has the same file name (ignoring case), a line to print
/// under the row naming its folder, so programs that share a name can be told
/// apart. Invisible characters in the folder are shown as `?`.
pub(crate) fn folder_lines(apps: &[(&str, Option<&str>)]) -> Vec<Option<String>> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for (name, _) in apps {
        *counts.entry(name.to_lowercase()).or_default() += 1;
    }
    apps.iter()
        .map(|&(name, path)| {
            if counts.get(&name.to_lowercase()).copied().unwrap_or(0) < 2 {
                return None;
            }
            let folder = match path {
                Some(path) => path.rsplit_once('\\').map_or(path, |(folder, _)| folder),
                None => "(folder not saved)",
            };
            Some(format!("  in {}", display_safe(folder)))
        })
        .collect()
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
        stats.domain = domain.map(|(name, source)| DomainLabel::new(name, source));
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
            learned: false,
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
    fn a_tracker_hidden_behind_a_sites_own_name_is_labelled() {
        let mut row = row_to(
            "198.51.100.9:443",
            Some(("metrics.shop.example", LabelSource::Verified)),
        );
        if let Some(label) = row.stats.domain.as_mut() {
            label.aliases = Arc::from([Arc::from("eu.tracker.example")]);
        }
        let (owner, _) = owner_and_country(&row, &enricher());
        assert!(owner.starts_with("tracker"), "{owner}");
        let label = row.stats.domain.as_ref().unwrap();
        assert_eq!(
            revealing_alias(label, &enricher()).as_deref(),
            Some("eu.tracker.example")
        );
        // A name that is itself known needs no alias.
        let plain = row_to(
            "198.51.100.9:443",
            Some(("tracker.example", LabelSource::Verified)),
        );
        assert_eq!(
            revealing_alias(plain.stats.domain.as_ref().unwrap(), &enricher()),
            None
        );
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
    fn deleting_everything_forgets_flows_waiting_to_be_saved() {
        let mut closed = Closed {
            keep_evicted: true,
            ..Closed::default()
        };
        for _ in 0..MAX_CLOSED + 3 {
            closed.push(row_to("203.0.113.5:443", None));
        }
        assert!(!closed.unsaved_evicted.is_empty());
        // With no store, the deletion itself may fail in a test, but the
        // waiting flows must be forgotten either way.
        let mut learning = crate::learning::Learning::new(SystemTime::now());
        let _ = delete_everything(&mut None, &mut closed, &mut learning);
        assert!(closed.unsaved_evicted.is_empty());
        assert!(closed.rows.iter().all(|row| row.saved && row.learned));
    }

    fn temp_store(name: &str) -> (Store, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("whereabouts-console-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = whereabouts_store::Key::from_bytes([8; 32]);
        (Store::open(&dir.join("t.db"), &key).unwrap(), dir)
    }

    /// A flow that finished long enough ago to be saved.
    fn finished(remote: &str) -> Row {
        let mut row = row_to(remote, None);
        row.closed_at = Instant::now().checked_sub(LATE_TRAFFIC_WINDOW * 2);
        row
    }

    #[test]
    fn no_flows_are_saved_while_history_is_off() {
        let (store, dir) = temp_store("off");
        let mut store = Some(store);
        let names = ProcessNames::new();
        let enricher = enricher();
        let mut history = crate::history::HistorySwitch::load(store.as_ref());
        let mut learning = crate::learning::Learning::new(SystemTime::now());
        let mut closed = Closed {
            keep_evicted: history.on(),
            ..Closed::default()
        };

        // On (the default): finished flows are saved.
        closed.push(finished("203.0.113.1:443"));
        let saved = store.as_mut().unwrap();
        store_finished(
            saved,
            &mut closed,
            &names,
            &enricher,
            history,
            &mut learning,
            false,
        );
        assert_eq!(saved.flow_count().unwrap(), 1);

        // Off: a flow waiting to be saved, and later ones, are forgotten,
        // even at shutdown; they stay on the live list.
        closed.push(finished("203.0.113.2:443"));
        set_save_history(&mut store, &mut closed, &mut history, false, false).unwrap();
        assert!(!closed.keep_evicted);
        closed.push(finished("203.0.113.3:443"));
        let saved = store.as_mut().unwrap();
        store_finished(
            saved,
            &mut closed,
            &names,
            &enricher,
            history,
            &mut learning,
            false,
        );
        store_finished(
            saved,
            &mut closed,
            &names,
            &enricher,
            history,
            &mut learning,
            true,
        );
        assert_eq!(saved.flow_count().unwrap(), 1, "kept what was saved before");
        assert_eq!(closed.rows.len(), 3);
        // Evicted rows are not kept for saving either.
        for _ in 0..MAX_CLOSED {
            closed.push(finished("203.0.113.4:443"));
        }
        assert!(closed.unsaved_evicted.is_empty());

        // The choice survives a restart.
        assert!(!crate::history::HistorySwitch::load(store.as_ref()).on());

        // On again: only flows that finish from now on are saved.
        set_save_history(&mut store, &mut closed, &mut history, true, false).unwrap();
        assert!(closed.keep_evicted);
        closed.push(finished("203.0.113.5:443"));
        let saved = store.as_mut().unwrap();
        store_finished(
            saved,
            &mut closed,
            &names,
            &enricher,
            history,
            &mut learning,
            false,
        );
        assert_eq!(saved.flow_count().unwrap(), 2);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn turning_history_off_can_delete_what_was_saved() {
        let (store, dir) = temp_store("delete");
        let mut store = Some(store);
        let names = ProcessNames::new();
        let mut history = crate::history::HistorySwitch::default();
        let mut learning = crate::learning::Learning::new(SystemTime::now());
        let mut closed = Closed::default();
        closed.push(finished("203.0.113.1:443"));
        let saved = store.as_mut().unwrap();
        store_finished(
            saved,
            &mut closed,
            &names,
            &enricher(),
            history,
            &mut learning,
            true,
        );
        saved
            .add_rule(
                &whereabouts_store::RuleTarget::App {
                    path: String::from("C:/Apps/a.exe"),
                },
                SystemTime::now(),
            )
            .unwrap();
        set_save_history(&mut store, &mut closed, &mut history, false, true).unwrap();
        let saved = store.as_ref().unwrap();
        assert_eq!(saved.flow_count().unwrap(), 0);
        assert_eq!(saved.rules().unwrap().len(), 1, "rules are kept");
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A program identity, as the resolver would report it.
    fn identity(path: &str) -> AppIdentity {
        AppIdentity {
            path: path.to_owned(),
            signature: whereabouts_core::model::Signature::Signed {
                publisher: String::from("Example Corp"),
                via_catalog: false,
            },
            sha256: Some("ab".repeat(32)),
            size: Some(1_000),
            package_family_name: None,
            confirmed_running: true,
        }
    }

    /// Learning, with the (empty) saved history already turned into
    /// profiles, so it learns from live flows.
    fn learning(store: &mut Store) -> crate::learning::Learning {
        let mut learning = crate::learning::Learning::new(SystemTime::now());
        learning.tick(store, &enricher(), SystemTime::now());
        learning
    }

    #[test]
    fn history_off_still_learns() {
        let (store, dir) = temp_store("learn-off");
        let mut store = Some(store);
        let mut names = ProcessNames::new();
        names.identities.insert(1, identity(r"C:\Apps\chat.exe"));
        let enricher = enricher();
        let mut history = crate::history::HistorySwitch::load(store.as_ref());
        let mut closed = Closed::default();
        set_save_history(&mut store, &mut closed, &mut history, false, false).unwrap();
        let saved = store.as_mut().unwrap();
        let mut learning = learning(saved);

        let mut row = finished("203.0.113.1:443");
        row.token = Some(1);
        row.stats.domain = Some(DomainLabel::new("api.chat.example", LabelSource::Verified));
        closed.push(row);
        store_finished(
            saved,
            &mut closed,
            &names,
            &enricher,
            history,
            &mut learning,
            false,
        );

        assert_eq!(saved.flow_count().unwrap(), 0, "history is off");
        assert!(closed.rows[0].learned);
        let profile = saved
            .profile(&whereabouts_store::known_app_key(r"C:\Apps\chat.exe"))
            .unwrap()
            .expect("the flow made a profile");
        let has = |kind, value: &str| {
            profile
                .items
                .iter()
                .any(|item| item.kind == kind && item.value == value)
        };
        assert!(has(whereabouts_store::ItemKind::Domain, "chat.example"));
        assert!(has(whereabouts_store::ItemKind::Port, "443"));
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rows_without_path_are_not_profiled() {
        let (mut store, dir) = temp_store("learn-no-path");
        let mut names = ProcessNames::new();
        names.identities.insert(1, identity(r"C:\Apps\chat.exe"));
        names.identities.insert(2, identity(r"C:\Apps\many.exe"));
        let enricher = enricher();
        let history = crate::history::HistorySwitch::default();
        let mut learning = learning(&mut store);
        let now = SystemTime::now();

        // A finished flow whose program is not known.
        let mut closed = Closed::default();
        let mut unknown = finished("203.0.113.1:443");
        unknown.stats.bytes_sent = 5_000;
        closed.push(unknown.clone());
        store_finished(
            &mut store,
            &mut closed,
            &names,
            &enricher,
            history,
            &mut learning,
            false,
        );
        assert!(closed.rows[0].learned, "passed over once, not kept waiting");

        // Live traffic: no program path, and (to show learning works at
        // all) a flow with a path.
        let mut known = row_to("203.0.113.2:443", None);
        known.token = Some(1);
        known.stats.bytes_sent = 9_000;
        learn_traffic(
            &mut learning,
            &[unknown, known],
            &names,
            &enricher,
            &mut store,
            now,
        );
        learning.shutdown(&mut store, now);

        let keys: Vec<String> = store
            .profile_rows()
            .unwrap()
            .into_iter()
            .map(|row| row.key)
            .collect();
        assert_eq!(
            keys,
            [whereabouts_store::known_app_key(r"C:\Apps\chat.exe")]
        );
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The downloaded offline data if present (so network owners and
    /// countries are looked up too), otherwise the built-in lists only.
    fn real_or_built_in_enricher() -> (Enricher, bool) {
        let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../data"));
        let (real, report) = Enricher::load(&dir);
        if report.missing.is_empty() {
            (real, true)
        } else {
            eprintln!("note: data files missing, so owners and countries are not compared");
            (enricher(), false)
        }
    }

    #[test]
    fn backfill_and_live_learn_the_same_destinations() {
        use std::collections::BTreeSet;
        use whereabouts_store::ItemKind;

        let (enricher, real_data) = real_or_built_in_enricher();
        let path = r"C:\Apps\chat.exe";
        let mut names = ProcessNames::new();
        names.identities.insert(1, identity(path));
        let verified = LabelSource::Verified;
        let flows = || {
            [
                // A known company's domain: the saved owner text was
                // "Google (Firebase) · analytics", never a company name.
                ("8.8.8.8:443", Some(("app-measurement.com", verified))),
                // A full name of a non-browser app is saved as it is.
                ("203.0.113.7:443", Some(("api.chat.example", verified))),
                // Only the app said so: no domain.
                (
                    "198.51.100.3:443",
                    Some(("fake.example", LabelSource::Unverified)),
                ),
                // Local: no owner or country.
                ("192.168.1.20:8443", None),
            ]
            .map(|(remote, domain)| {
                let mut row = finished(remote);
                row.token = Some(1);
                row.stats.domain = domain.map(|(name, source)| DomainLabel::new(name, source));
                row
            })
        };
        // By kind's stored spelling, so the sets compare in order.
        let items = |store: &Store| -> BTreeSet<(&'static str, String)> {
            store
                .profile(&whereabouts_store::known_app_key(path))
                .unwrap()
                .expect("a profile")
                .items
                .into_iter()
                .map(|item| (item.kind.as_str(), item.value))
                .collect()
        };
        let history_on = crate::history::HistorySwitch::default();

        // From history: saved before learning caught up, then read back.
        let (mut saved, saved_dir) = temp_store("same-history");
        let mut later = crate::learning::Learning::new(SystemTime::now());
        let mut closed = Closed::default();
        for row in flows() {
            closed.push(row);
        }
        store_finished(
            &mut saved,
            &mut closed,
            &names,
            &enricher,
            history_on,
            &mut later,
            false,
        );
        assert_eq!(saved.flow_count().unwrap(), 4);
        assert!(saved.profile_rows().unwrap().is_empty(), "not learned live");
        later.tick(&mut saved, &enricher, SystemTime::now());

        // Live.
        let (mut live, live_dir) = temp_store("same-live");
        let mut learning = learning(&mut live);
        let mut closed = Closed::default();
        for row in flows() {
            closed.push(row);
        }
        store_finished(
            &mut live,
            &mut closed,
            &names,
            &enricher,
            history_on,
            &mut learning,
            false,
        );

        let learned = items(&live);
        assert_eq!(items(&saved), learned);
        let of = |kind: ItemKind| {
            learned
                .iter()
                .filter(|(k, _)| *k == kind.as_str())
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            of(ItemKind::Domain),
            ["app-measurement.com", "chat.example"]
        );
        assert_eq!(of(ItemKind::Port), ["443", "8443"]);
        assert!(of(ItemKind::Company).iter().all(|c| !c.contains(" · ")));
        if real_data {
            assert!(
                of(ItemKind::Company).iter().any(|c| c.contains("Google")),
                "{learned:?}"
            );
            assert!(of(ItemKind::Country).contains(&"US"), "{learned:?}");
        }
        drop((saved, live));
        let _ = std::fs::remove_dir_all(saved_dir);
        let _ = std::fs::remove_dir_all(live_dir);
    }

    #[test]
    fn history_cannot_be_switched_without_a_database() {
        let mut closed = Closed::default();
        let mut history = crate::history::HistorySwitch::default();
        assert!(set_save_history(&mut None, &mut closed, &mut history, false, true).is_err());
        assert_eq!(history.choice(), None);
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
    fn only_the_installed_webview2_runtime_is_credited_to_its_app() {
        let x86 = whereabouts_win_secrets::known_folder(
            whereabouts_win_secrets::KnownFolder::ProgramFilesX86,
        )
        .unwrap();
        let runtime =
            x86.join(r"Microsoft\EdgeWebView\Application\157.0.4341.60\msedgewebview2.exe");
        assert!(is_webview2_runtime(&runtime.to_string_lossy()));
        assert!(is_webview2_runtime(
            &runtime.to_string_lossy().to_uppercase()
        ));
        // Anything can be called msedgewebview2.exe.
        assert!(!is_webview2_runtime(
            r"C:\Users\x\AppData\Local\Temp\msedgewebview2.exe"
        ));
        let other = x86.join(r"Microsoft\EdgeWebView\Application\157.0.4341.60\other.exe");
        assert!(!is_webview2_runtime(&other.to_string_lossy()));
        let sneaky =
            x86.join(r"Microsoft\EdgeWebView\Application\..\..\..\..\Users\x\msedgewebview2.exe");
        assert!(!is_webview2_runtime(&sneaky.to_string_lossy()));
    }

    #[test]
    fn extracts_file_names_from_paths() {
        assert_eq!(file_name(r"C:\Program Files\App\app.exe"), "app.exe");
        assert_eq!(file_name("System"), "System");
        assert_eq!(file_name("/usr/bin/curl"), "curl");
    }

    #[test]
    fn apps_that_share_a_name_show_their_folder() {
        let lines = folder_lines(&[
            (
                "chrome.exe",
                Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            ),
            (
                "Chrome.exe",
                Some(r"C:\Users\me\AppData\Local\Temp\Chrome.exe"),
            ),
            ("chrome.exe", None),
            ("code.exe", Some(r"C:\Apps\code.exe")),
        ]);
        assert_eq!(
            lines,
            [
                Some(String::from(
                    r"  in C:\Program Files\Google\Chrome\Application"
                )),
                Some(String::from(r"  in C:\Users\me\AppData\Local\Temp")),
                Some(String::from("  in (folder not saved)")),
                None,
            ]
        );
    }

    #[test]
    fn folder_lines_hide_invisible_characters() {
        let lines = folder_lines(&[
            ("a.exe", Some("C:\\Temp\u{202E}exe.\\a.exe")),
            ("a.exe", None),
        ]);
        assert_eq!(lines[0].as_deref(), Some(r"  in C:\Temp?exe."));
    }

    #[test]
    fn truncates_long_names_on_character_boundaries() {
        assert_eq!(truncate("short.exe", 24), "short.exe");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("ééééé", 3), "éé…");
    }
}
