//! Message types shared by the Whereabouts service and UI (design spec §5.8).
//!
//! The service and the UI talk over a local named pipe that only SYSTEM,
//! Administrators and the user running Whereabouts can open. Messages are
//! typed and versioned, and the UI can only send the requests defined here;
//! it cannot run arbitrary queries.
//!
//! On the wire, each message is a 4-byte little-endian length followed by
//! that many bytes of JSON. Messages larger than [`MAX_MESSAGE`] are refused
//! without reading them, so a misbehaving peer cannot make the other side
//! allocate unbounded memory.

#![forbid(unsafe_code)]

pub mod notify;

use std::io::{self, Read, Write};
use std::net::IpAddr;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Version of the service <-> UI protocol.
///
/// Increase this when a message changes in a way that old clients cannot
/// understand.
pub const PROTOCOL_VERSION: u32 = 1;

/// Name of the pipe the service listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\Whereabouts";

/// Largest message accepted, in bytes.
pub const MAX_MESSAGE: usize = 1024 * 1024;

/// Most rows a client may ask for in one request.
pub const MAX_ROWS: u32 = 500;

/// Longest history window a client may ask for, in hours (30 days).
pub const MAX_HOURS: u32 = 30 * 24;

/// Most flows in one page of the CSV export.
pub const EXPORT_PAGE_ROWS: u32 = 2000;

/// Most CSV text in one export page, in bytes; well under [`MAX_MESSAGE`],
/// leaving room for one more (long) line and the JSON around it.
pub const EXPORT_PAGE_BYTES: usize = 512 * 1024;

/// What a client must send with [`Request::DeleteAll`], so that deleting
/// everything cannot happen by accident.
pub const DELETE_ALL_CONFIRMATION: &str = "delete all saved data";

/// Longest program path sent with a flow, in characters (Windows' classic
/// path limit); longer paths are left out rather than shortened.
pub const MAX_FLOW_PATH: usize = 260;

/// Most blocking rules the service keeps.
pub const MAX_RULES: usize = 256;

/// Longest program path in a rule, in characters.
pub const MAX_RULE_PATH: usize = 512;

// The rule list (each path at most MAX_RULE_PATH characters, up to 3 bytes
// each, doubled by JSON escaping in the worst case) must fit in a message.
const _: () = assert!(MAX_RULES * (MAX_RULE_PATH * 6 + 1024) <= MAX_MESSAGE);

// An export page, plus one more long line and its JSON, must fit in a message.
const _: () = assert!(EXPORT_PAGE_BYTES * 2 <= MAX_MESSAGE);

/// What a client can ask the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// First message on a connection: says which protocol the client speaks.
    Hello {
        /// The client's [`PROTOCOL_VERSION`].
        protocol: u32,
    },
    /// Counters and health of the capture. (An empty struct variant rather
    /// than a unit variant, so that unknown fields are refused: serde does
    /// not check unit variants of internally tagged enums.)
    Status {},
    /// The current flows, largest first.
    LiveFlows {
        /// Most rows to return; clamped to [`MAX_ROWS`].
        limit: u32,
    },
    /// Saved per-app totals.
    History {
        /// How many hours back; clamped to [`MAX_HOURS`].
        hours: u32,
        /// Most rows to return; clamped to [`MAX_ROWS`].
        limit: u32,
    },
    /// One page of all saved flows as CSV. Start with `after: 0`, then pass
    /// the `last` of each answer until it is `None`.
    ExportPage {
        /// Continue after this flow (0 for the first page).
        after: i64,
        /// Most flows in the page; clamped to [`EXPORT_PAGE_ROWS`].
        limit: u32,
    },
    /// Deletes all saved flows and totals. Flows that are still open are
    /// saved as usual when they finish.
    DeleteAll {
        /// Must be [`DELETE_ALL_CONFIRMATION`].
        confirm: String,
    },
    /// The blocking rules.
    ListRules {},
    /// Saves a blocking rule and applies it. Answered with
    /// [`Response::RuleAdded`].
    AddRule {
        /// What to block.
        rule: RuleSpec,
    },
    /// Deletes a blocking rule and unblocks what it blocked.
    RemoveRule {
        /// The rule's ID.
        id: i64,
    },
    /// Pauses blocking (every block is lifted, the rules are kept) or
    /// resumes it.
    SetBlockingPaused {
        /// `true` to pause, `false` to resume.
        paused: bool,
    },
    /// Things worth telling the user about (see [`Notice`]) newer than
    /// `after`. Start with `after: 0`.
    Notices {
        /// The last notice ID already seen.
        after: u64,
    },
    /// Saved alerts, newest first.
    Alerts {
        /// How many hours back; clamped to [`MAX_HOURS`].
        hours: u32,
        /// Most alerts to return; clamped to [`MAX_ROWS`].
        limit: u32,
    },
    /// Turns list updates on or off (both are off until the user chooses).
    SetListUpdates {
        /// Whereabouts' signed data updates.
        data: bool,
        /// Spamhaus' DROP list.
        drop: bool,
    },
    /// Checks for list updates now (Spamhaus at most hourly).
    CheckListsNow {},
    /// Turns saving connection history on or off (on until the user
    /// chooses). Answered with [`Response::SaveHistory`]. The live view,
    /// alerts and blocking work either way.
    SetSaveHistory {
        /// `true` to save finished connections, `false` to stop.
        save: bool,
        /// When turning saving off: also delete the connections and hourly
        /// totals saved so far. Ignored when turning it on.
        delete_saved: bool,
    },
    /// Marks an alert as seen and fine. For a behaviour alert, `allow`
    /// ("this is fine") also adds the destinations it named to the app's
    /// profile.
    DismissAlert {
        /// The alert's ID.
        id: i64,
        /// Also stop alerts like it (same app and target), if it can.
        allow: bool,
    },
    /// One program's behaviour profile. Answered with
    /// [`Response::Profile`] (`None` if it has none).
    Profile {
        /// The program's full path (at most [`MAX_RULE_PATH`] characters).
        path: String,
    },
    /// Forgets what was learned about a program; it learns again from now.
    /// Answered with [`Response::ProfileReset`].
    ResetProfile {
        /// The program's full path (at most [`MAX_RULE_PATH`] characters).
        path: String,
    },
    /// Sets whether a program is expected to connect anywhere (a web
    /// browser), so new sites, companies and countries are not unusual for
    /// it. Answered with [`Response::Profile`].
    SetGoesAnywhere {
        /// The program's full path (at most [`MAX_RULE_PATH`] characters).
        path: String,
        /// The user's choice.
        value: GoesAnywhereChoice,
    },
}

/// Whether a program is expected to connect anywhere, as the user chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoesAnywhereChoice {
    /// Decided by Whereabouts: yes for a genuine web browser installed by
    /// administrators.
    Auto,
    /// The user said it goes anywhere.
    On,
    /// The user said it does not.
    Off,
}

/// How much an alert matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Worth knowing; never notified on its own.
    Info,
    /// Worth a look.
    Medium,
    /// Needs a look.
    High,
    /// Needs a look now.
    Critical,
}

/// What an alert is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// An app contacted a known tracker (`target` is its domain, `detail`
    /// the company if known).
    Tracker,
    /// An app connected to a network on Spamhaus' DROP list (`target` is
    /// the address, `detail` the listed range and its reference).
    BadNetwork,
    /// Events claimed to come from the Windows DNS service but did not
    /// (`detail` says how many).
    FakedDns,
    /// Traffic could not be tied to any process (`detail` says how much).
    Unattributed,
    /// An app behaved differently from what Whereabouts learned is usual
    /// for it (`reasons` say how; `target` is the first reason's value).
    Behaviour,
}

/// One reason behind a behaviour alert.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReasonView {
    /// Which signal fired, e.g. `new_country` or `upload_spike`.
    pub signal: String,
    /// The domain, company, country code or port concerned.
    pub value: Option<String>,
    /// What was seen (e.g. bytes sent in the hour).
    pub observed: Option<f64>,
    /// What is usual for this app.
    pub usual: Option<f64>,
    /// A count (e.g. connections).
    pub count: Option<u32>,
}

/// A saved alert.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertView {
    /// The alert's ID.
    pub id: i64,
    /// When it was raised, in seconds since 1970.
    pub created_secs: u64,
    pub kind: AlertKind,
    pub severity: Severity,
    /// Executable file name, if it concerns one app.
    pub app: Option<String>,
    /// The program's full path.
    pub path: Option<String>,
    /// The domain or address concerned.
    pub target: Option<String>,
    /// More detail: a company, a listing, a count.
    pub detail: Option<String>,
    /// Whether the user marked it as seen and fine.
    pub dismissed: bool,
    /// Whether "this is fine" can also stop alerts like it.
    pub can_allow: bool,
    /// Why a behaviour alert was raised (empty for other kinds).
    #[serde(default)]
    pub reasons: Vec<ReasonView>,
    /// How many more times a behaviour alert's destinations were seen
    /// while it waited for the user.
    #[serde(default)]
    pub seen_again: u32,
}

/// One program's behaviour profile: what Whereabouts learned is usual for
/// it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileView {
    /// The program's full path (at most [`MAX_RULE_PATH`] characters).
    pub path: String,
    /// Executable file name.
    pub app: String,
    /// Whether it is still in its first week of learning (no behaviour
    /// alerts meanwhile).
    pub learning: bool,
    /// When learning ends (or ended), in seconds since 1970.
    pub learning_ends_secs: u64,
    /// When learning started (it starts again on reset), in seconds since
    /// 1970.
    pub learned_since_secs: u64,
    /// Whether new sites, companies and countries are expected of it, all
    /// things considered.
    pub goes_anywhere: bool,
    /// The user's choice behind `goes_anywhere`.
    pub goes_anywhere_choice: GoesAnywhereChoice,
    /// Whether Whereabouts recognises it as a genuine web browser (what
    /// [`GoesAnywhereChoice::Auto`] goes by).
    pub recognised_browser: bool,
    /// Sites (registrable domains), newest first, at most [`MAX_ROWS`].
    pub sites: Vec<ProfileItemView>,
    /// Companies, newest first, at most [`MAX_ROWS`].
    pub companies: Vec<ProfileItemView>,
    /// Country codes, newest first, at most [`MAX_ROWS`].
    pub countries: Vec<ProfileItemView>,
    /// Bytes sent in a typical active hour (the median), if it was active.
    pub usual_sent_per_hour: Option<u64>,
    /// Bytes sent in its busiest hour, if it was active.
    pub busiest_sent_per_hour: Option<u64>,
    /// The share of its active hours in each local hour of the day (0 to
    /// 23); all zeros if it was never active.
    pub active_hours: [f32; 24],
}

/// One destination in a [`ProfileView`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileItemView {
    /// The domain, company or country code.
    pub value: String,
    /// When the program last used it, in seconds since 1970.
    pub last_seen_secs: u64,
    /// `learned` (seen during normal use), `allowed` (the user said it is
    /// fine) or `pending` (raised an alert that waits for the user).
    pub state: String,
}

/// Most notices the service keeps; older ones are dropped.
pub const MAX_NOTICES: usize = 100;

/// Something worth telling the user about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// Increases with each notice (since the service started).
    pub id: u64,
    /// When it happened, in seconds since 1970.
    pub at_secs: u64,
    /// What happened.
    pub kind: NoticeKind,
}

/// What a [`Notice`] is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NoticeKind {
    /// A program used the network for the first time that Whereabouts saw.
    NewApp {
        /// Executable file name.
        app: String,
        /// The program's full path.
        path: String,
    },
    /// An alert worth notifying about (medium severity or higher).
    Alert {
        /// The alert's ID.
        id: i64,
        /// What it is about.
        alert: AlertKind,
        severity: Severity,
        /// Executable file name, if it concerns one app.
        app: Option<String>,
    },
    /// A byte-identical copy (or link) of a blocked program connected from
    /// another place, so Whereabouts blocked it too, with a rule of its own.
    BlockedCopy {
        /// The copy's file name.
        app: String,
        /// The copy's full path.
        path: String,
        /// The blocked program it is a copy of (full path).
        of: String,
    },
}

/// What a blocking rule blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleSpec {
    /// Every connection of a program.
    App {
        /// The program's full path.
        path: String,
    },
    /// A domain and its subdomains. Blocked by address: each address the
    /// Windows DNS service confirms for the domain is blocked.
    Domain {
        /// The domain, e.g. `tracker.example.com`.
        name: String,
        /// The program's full path, or `None` for every program.
        app: Option<String>,
    },
    /// One remote address.
    Address {
        /// The remote address.
        ip: IpAddr,
        /// The program's full path, or `None` for every program.
        app: Option<String>,
    },
}

/// A saved blocking rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleView {
    /// The rule's ID.
    pub id: i64,
    /// What it blocks.
    pub rule: RuleSpec,
    /// When it was created, in seconds since 1970.
    pub created_secs: u64,
    /// For a domain rule: how many of its addresses are blocked now.
    pub blocked_addresses: u64,
}

impl Request {
    /// Returns the request with its limits clamped to what the service
    /// allows. The service always does this; requests are untrusted.
    pub fn clamped(self) -> Self {
        match self {
            Self::LiveFlows { limit } => Self::LiveFlows {
                limit: limit.min(MAX_ROWS),
            },
            Self::History { hours, limit } => Self::History {
                hours: hours.min(MAX_HOURS),
                limit: limit.min(MAX_ROWS),
            },
            Self::Alerts { hours, limit } => Self::Alerts {
                hours: hours.min(MAX_HOURS),
                limit: limit.min(MAX_ROWS),
            },
            Self::ExportPage { after, limit } => Self::ExportPage {
                after: after.max(0),
                limit: limit.clamp(1, EXPORT_PAGE_ROWS),
            },
            other => other,
        }
    }
}

/// What the service answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Answer to [`Request::Hello`].
    Hello {
        /// The service's [`PROTOCOL_VERSION`].
        protocol: u32,
        /// The service's version, e.g. `0.1.0`.
        version: String,
    },
    /// Answer to [`Request::Status`].
    Status(Status),
    /// Answer to [`Request::LiveFlows`].
    LiveFlows {
        /// The flows, largest first.
        flows: Vec<FlowView>,
    },
    /// Answer to [`Request::History`].
    History {
        /// Per-app totals, largest first.
        apps: Vec<AppTotals>,
    },
    /// Answer to [`Request::ExportPage`].
    ExportPage {
        /// The CSV header line, on the first page only.
        header: Option<String>,
        /// CSV lines, each ending in a line break.
        csv: String,
        /// How many flows the page holds.
        rows: u64,
        /// Where to continue; `None` when the export is complete.
        last: Option<i64>,
    },
    /// Answer to [`Request::DeleteAll`]: everything saved is deleted.
    Deleted {},
    /// Answer to [`Request::ListRules`], [`Request::RemoveRule`] and
    /// [`Request::SetBlockingPaused`].
    Rules {
        /// The rules, oldest first.
        rules: Vec<RuleView>,
        /// Whether blocking is paused.
        paused: bool,
    },
    /// Answer to [`Request::Notices`].
    Notices {
        /// Notices newer than the one asked for, oldest first (at most
        /// [`MAX_NOTICES`]).
        notices: Vec<Notice>,
        /// The newest notice ID, or 0 if there was none yet. Pass it as
        /// `after` next time.
        last: u64,
    },
    /// Answer to [`Request::Alerts`].
    Alerts {
        /// The alerts, newest first.
        alerts: Vec<AlertView>,
    },
    /// Answer to [`Request::DismissAlert`].
    AlertDismissed {},
    /// Answer to [`Request::Profile`] and [`Request::SetGoesAnywhere`].
    Profile {
        /// The profile, or `None` if the program has none (yet).
        profile: Option<ProfileView>,
    },
    /// Answer to [`Request::ResetProfile`]: the profile is learning again.
    ProfileReset {},
    /// Answer to [`Request::SetListUpdates`] and [`Request::CheckListsNow`].
    Lists(ListsView),
    /// Answer to [`Request::SetSaveHistory`]: the choice is saved and in
    /// effect (and, if asked, the saved history is deleted).
    SaveHistory {
        /// Whether connection history is saved now.
        save: bool,
    },
    /// Answer to [`Request::AddRule`].
    RuleAdded {
        /// The new rule's ID (or the existing one's, if it was already
        /// saved).
        id: i64,
        /// Whether the rule was already saved, so nothing new was blocked
        /// (and undoing must not remove the existing rule).
        #[serde(default)]
        already: bool,
    },
    /// The request could not be answered.
    Error {
        /// What went wrong, for people.
        message: String,
    },
}

/// Counters and health of the capture.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// Seconds since the capture started.
    pub uptime_secs: u64,
    /// Events received from Windows.
    pub events: u64,
    /// Events dropped because the service could not keep up.
    pub dropped: u64,
    /// Events that could not be decoded.
    pub unreadable: u64,
    /// Events that claimed to come from the DNS service but did not.
    pub rejected: u64,
    /// Events counted only in a per-app total because the app had too many
    /// flows.
    pub over_limit: u64,
    /// Events that could not be attributed to any process because many
    /// processes flooded the flow table at once (possible evasion).
    pub unattributed: u64,
    /// Flows currently open.
    pub active_flows: u64,
    /// Whether the service itself is refused when it tries to register the
    /// kernel network and process providers' IDs. As SYSTEM it may be
    /// allowed; clients repeat the check from their own, ordinary account
    /// (see `whereabouts_client::kernel_events_protected`).
    pub kernel_events_protected: bool,
    /// Whether finished flows are being saved: the database is open and
    /// the user has not turned history off.
    pub saving: bool,
    /// The user's choice whether connection history is saved; `None` until
    /// they chose (it is saved meanwhile).
    #[serde(default)]
    pub save_history: Option<bool>,
    /// Tracker domains loaded from the offline data.
    pub tracker_domains: u64,
    /// Saved blocking rules.
    #[serde(default)]
    pub block_rules: u64,
    /// Whether blocking is paused.
    #[serde(default)]
    pub blocking_paused: bool,
    /// Whether connections are checked against Spamhaus DROP (only once
    /// this computer has downloaded it).
    #[serde(default)]
    pub drop_list: bool,
    /// List updates.
    #[serde(default)]
    pub lists: ListsView,
    /// Learning each app's usual behaviour: `starting` (still reading the
    /// saved history), `ready`, or `paused: ` and what went wrong (it is
    /// tried again later). `None` when nothing can be saved, so nothing is
    /// learned.
    #[serde(default)]
    pub behaviour_learning: Option<String>,
}

/// List updates: the user's switches and what was downloaded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListsView {
    /// Whereabouts' signed data updates; `None` until the user chose.
    pub data_updates: Option<bool>,
    /// Spamhaus' DROP list; `None` until the user chose.
    pub drop_updates: Option<bool>,
    /// When the data in use was built, if it came from an update.
    pub data_version: Option<String>,
    /// When data updates were last checked (seconds since 1970).
    pub data_checked_secs: Option<u64>,
    /// When Spamhaus DROP was last downloaded (seconds since 1970).
    pub drop_fetched_secs: Option<u64>,
    /// What went wrong last time, if anything.
    pub problem: Option<String>,
    /// Whether a check is running.
    pub checking: bool,
}

/// How far a flow's domain name can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainTrust {
    /// Confirmed by the Windows DNS service.
    Verified,
    /// Reported only by the app itself, so it could be false. Shown with `?`.
    AppReported,
    /// Guessed from another app's lookup of the same address. Shown with `*`.
    Guessed,
}

impl DomainTrust {
    /// The marker shown after the domain name: nothing, `?` or `*`.
    pub fn marker(self) -> &'static str {
        match self {
            Self::Verified => "",
            Self::AppReported => "?",
            Self::Guessed => "*",
        }
    }
}

/// One flow, ready to display.
///
/// Trust levels are separate fields rather than markers in the text, so a
/// display that shortens the text cannot cut them off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowView {
    /// Process ID.
    pub pid: u32,
    /// Executable file name.
    pub app: String,
    /// The program's full path, when known and at most [`MAX_FLOW_PATH`]
    /// characters long (so the app can offer to block it).
    #[serde(default)]
    pub path: Option<String>,
    /// Publisher: the signer (e.g. "Google LLC"), "UNSIGNED", "INVALID
    /// SIGNATURE", "…" while being checked, or "-" if there is no program
    /// file.
    pub publisher: String,
    /// `false` when the program file was checked by path only and could not
    /// be confirmed as the file the process ran (shown with `?`).
    pub publisher_confirmed: bool,
    /// "TCP" or "UDP".
    pub protocol: String,
    /// Domain name, without a trust marker.
    pub domain: Option<String>,
    /// How far `domain` can be trusted.
    pub domain_trust: Option<DomainTrust>,
    /// The name `domain` points to (a CNAME alias) that revealed the tracker
    /// or company behind it, when `domain` alone did not.
    #[serde(default)]
    pub via: Option<String>,
    /// Company or network owner.
    pub owner: Option<String>,
    /// Two-letter country code.
    pub country: Option<String>,
    /// Remote address and port.
    pub remote: String,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
    /// Whether the flow is still open.
    pub active: bool,
    /// Made by the app's web content (a WebView2 process the app started):
    /// `app`, `path` and `publisher` are the app's.
    #[serde(default)]
    pub web_content: bool,
}

/// Saved totals for one app: one program file, told apart by its full
/// path (or by its name when no path was saved).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppTotals {
    /// Executable file name.
    pub app: String,
    /// Full path of the program, if saved. Missing from older services,
    /// which totalled programs by file name.
    #[serde(default)]
    pub path: Option<String>,
    /// Publisher, if signed.
    pub publisher: Option<String>,
    /// Number of flows.
    pub flows: u64,
    /// Number of different destinations.
    pub destinations: u64,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
}

/// Writes one length-prefixed JSON message.
pub fn write_message<T: Serialize>(out: &mut impl Write, message: &T) -> io::Result<()> {
    let body = serde_json::to_vec(message).map_err(io::Error::other)?;
    if body.len() > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let len = u32::try_from(body.len()).map_err(io::Error::other)?;
    out.write_all(&len.to_le_bytes())?;
    out.write_all(&body)?;
    out.flush()
}

/// Reads one length-prefixed JSON message. Refuses messages larger than
/// [`MAX_MESSAGE`] before reading their body.
pub fn read_message<T: DeserializeOwned>(input: &mut impl Read) -> io::Result<T> {
    let mut len = [0u8; 4];
    input.read_exact(&mut len)?;
    let len = usize::try_from(u32::from_le_bytes(len)).map_err(io::Error::other)?;
    if len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message of {len} bytes is larger than allowed"),
        ));
    }
    let mut body = vec![0u8; len];
    input.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn round_trip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(message: T) {
        let mut buffer = Vec::new();
        write_message(&mut buffer, &message).unwrap();
        let back: T = read_message(&mut Cursor::new(buffer)).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn requests_and_responses_round_trip() {
        round_trip(Request::Hello {
            protocol: PROTOCOL_VERSION,
        });
        round_trip(Request::History {
            hours: 24,
            limit: 20,
        });
        round_trip(Response::Status(Status {
            events: 42,
            saving: true,
            ..Status::default()
        }));
        round_trip(Response::LiveFlows {
            flows: vec![FlowView {
                pid: 7,
                app: String::from("curl.exe"),
                path: Some(String::from(r"C:\Windows\System32\curl.exe")),
                publisher: String::from("Microsoft Windows"),
                publisher_confirmed: true,
                protocol: String::from("TCP"),
                domain: Some(String::from("example.com")),
                domain_trust: Some(DomainTrust::AppReported),
                via: None,
                owner: None,
                country: Some(String::from("US")),
                remote: String::from("[2606:4700::1]:443"),
                bytes_sent: 659,
                bytes_received: 5800,
                active: false,
                web_content: true,
            }],
        });
    }

    #[test]
    fn oversized_messages_are_refused_before_reading_them() {
        let mut input = Cursor::new(((MAX_MESSAGE + 1) as u32).to_le_bytes().to_vec());
        let error = read_message::<Request>(&mut input).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn unknown_requests_and_fields_are_refused() {
        for json in [
            r#"{"type":"run_sql","query":"DROP TABLE flows"}"#,
            r#"{"type":"status","extra":1}"#,
            r#"not json"#,
        ] {
            let mut buffer = (json.len() as u32).to_le_bytes().to_vec();
            buffer.extend_from_slice(json.as_bytes());
            assert!(
                read_message::<Request>(&mut Cursor::new(buffer)).is_err(),
                "{json}"
            );
        }
    }

    #[test]
    fn limits_are_clamped() {
        assert_eq!(
            Request::LiveFlows { limit: 1_000_000 }.clamped(),
            Request::LiveFlows { limit: MAX_ROWS }
        );
        assert_eq!(
            Request::History {
                hours: 100_000,
                limit: 5
            }
            .clamped(),
            Request::History {
                hours: MAX_HOURS,
                limit: 5
            }
        );
    }

    #[test]
    fn export_and_delete_requests_are_bounded() {
        assert_eq!(
            Request::ExportPage {
                after: -5,
                limit: 0
            }
            .clamped(),
            Request::ExportPage { after: 0, limit: 1 }
        );
        assert_eq!(
            Request::ExportPage {
                after: 9,
                limit: u32::MAX
            }
            .clamped(),
            Request::ExportPage {
                after: 9,
                limit: EXPORT_PAGE_ROWS
            }
        );
        round_trip(Request::DeleteAll {
            confirm: String::from(DELETE_ALL_CONFIRMATION),
        });
        round_trip(Response::ExportPage {
            header: Some(String::from("a,b")),
            csv: String::from("1,2\n"),
            rows: 1,
            last: Some(7),
        });
        round_trip(Response::Deleted {});
        round_trip(Request::SetSaveHistory {
            save: false,
            delete_saved: true,
        });
        round_trip(Response::SaveHistory { save: false });
    }

    #[test]
    fn rule_requests_round_trip_and_refuse_unknown_kinds() {
        round_trip(Request::AddRule {
            rule: RuleSpec::Domain {
                name: String::from("tracker.example.com"),
                app: None,
            },
        });
        round_trip(Request::AddRule {
            rule: RuleSpec::Address {
                ip: "2001:db8::1".parse().unwrap(),
                app: Some(String::from(r"C:\Apps\x.exe")),
            },
        });
        round_trip(Response::Rules {
            rules: vec![RuleView {
                id: 3,
                rule: RuleSpec::App {
                    path: String::from(r"C:\Apps\x.exe"),
                },
                created_secs: 1_800_000_000,
                blocked_addresses: 0,
            }],
            paused: true,
        });
        for json in [
            r#"{"type":"add_rule","rule":{"kind":"port","port":80}}"#,
            r#"{"type":"add_rule","rule":{"kind":"app","path":"x","extra":1}}"#,
            r#"{"type":"add_rule","rule":{"kind":"address","ip":"not an ip","app":null}}"#,
        ] {
            let mut buffer = (json.len() as u32).to_le_bytes().to_vec();
            buffer.extend_from_slice(json.as_bytes());
            assert!(
                read_message::<Request>(&mut Cursor::new(buffer)).is_err(),
                "{json}"
            );
        }
    }

    #[test]
    fn alert_messages_round_trip_and_are_bounded() {
        round_trip(Request::DismissAlert { id: 3, allow: true });
        round_trip(Response::Alerts {
            alerts: vec![AlertView {
                id: 3,
                created_secs: 1_800_000_000,
                kind: AlertKind::BadNetwork,
                severity: Severity::High,
                app: Some(String::from("chat.exe")),
                path: Some(String::from(r"C:\Apps\chat.exe")),
                target: Some(String::from("203.0.113.5")),
                detail: Some(String::from("203.0.113.0/24 (SBL1)")),
                dismissed: false,
                can_allow: true,
                reasons: Vec::new(),
                seen_again: 0,
            }],
        });
        assert_eq!(
            Request::Alerts {
                hours: u32::MAX,
                limit: u32::MAX
            }
            .clamped(),
            Request::Alerts {
                hours: MAX_HOURS,
                limit: MAX_ROWS
            }
        );
        assert!(Severity::Critical > Severity::Medium);
    }

    #[test]
    fn alert_view_carries_reasons() {
        let alert = AlertView {
            id: 9,
            created_secs: 1_800_000_000,
            kind: AlertKind::Behaviour,
            severity: Severity::High,
            app: Some(String::from("chat.exe")),
            path: Some(String::from(r"C:\Apps\chat.exe")),
            target: Some(String::from("RU")),
            detail: None,
            dismissed: false,
            can_allow: false,
            reasons: vec![
                ReasonView {
                    signal: String::from("new_country"),
                    value: Some(String::from("RU")),
                    observed: None,
                    usual: None,
                    count: None,
                },
                ReasonView {
                    signal: String::from("upload_spike"),
                    value: None,
                    observed: Some(5e7),
                    usual: Some(1e6),
                    count: Some(3),
                },
            ],
            seen_again: 2,
        };
        round_trip(Response::Alerts {
            alerts: vec![alert.clone()],
        });
        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains(r#""kind":"behaviour""#), "{json}");
        assert!(json.contains(r#""signal":"new_country""#), "{json}");
        // An alert from an older service, without reasons, still reads.
        let old = r#"{"id":1,"created_secs":2,"kind":"tracker","severity":"info","app":null,
            "path":null,"target":null,"detail":null,"dismissed":false,"can_allow":true}"#;
        let old: AlertView = serde_json::from_str(old).unwrap();
        assert!(old.reasons.is_empty());
        assert_eq!(old.seen_again, 0);
    }

    #[test]
    fn profile_messages_round_trip() {
        let path = String::from(r"C:\Apps\chat.exe");
        round_trip(Request::Profile { path: path.clone() });
        round_trip(Request::ResetProfile { path: path.clone() });
        for value in [
            GoesAnywhereChoice::Auto,
            GoesAnywhereChoice::On,
            GoesAnywhereChoice::Off,
        ] {
            round_trip(Request::SetGoesAnywhere {
                path: path.clone(),
                value,
            });
        }
        let mut active_hours = [0.0; 24];
        active_hours[9] = 0.75;
        active_hours[14] = 0.25;
        round_trip(Response::Profile {
            profile: Some(ProfileView {
                path,
                app: String::from("chat.exe"),
                learning: false,
                learning_ends_secs: 1_800_604_800,
                learned_since_secs: 1_800_000_000,
                goes_anywhere: false,
                goes_anywhere_choice: GoesAnywhereChoice::Auto,
                recognised_browser: false,
                sites: vec![ProfileItemView {
                    value: String::from("chat.example"),
                    last_seen_secs: 1_800_700_000,
                    state: String::from("learned"),
                }],
                companies: Vec::new(),
                countries: vec![ProfileItemView {
                    value: String::from("RU"),
                    last_seen_secs: 1_800_700_000,
                    state: String::from("pending"),
                }],
                usual_sent_per_hour: Some(12_000),
                busiest_sent_per_hour: Some(90_000),
                active_hours,
            }),
        });
        round_trip(Response::Profile { profile: None });
        round_trip(Response::ProfileReset {});
        let json = r#"{"type":"set_goes_anywhere","path":"x","value":"sometimes"}"#;
        assert!(serde_json::from_str::<Request>(json).is_err());
    }

    #[test]
    fn notices_round_trip() {
        round_trip(Request::Notices { after: 3 });
        round_trip(Response::Notices {
            notices: vec![Notice {
                id: 4,
                at_secs: 1_800_000_000,
                kind: NoticeKind::NewApp {
                    app: String::from("chat.exe"),
                    path: String::from(r"C:\Apps\chat.exe"),
                },
            }],
            last: 4,
        });
    }

    #[test]
    fn a_status_from_an_older_service_still_reads() {
        let old = r#"{"uptime_secs":1,"events":2,"dropped":0,"unreadable":0,"rejected":0,
            "over_limit":0,"unattributed":0,"active_flows":0,"kernel_events_protected":true,
            "saving":true,"tracker_domains":5}"#;
        let status: Status = serde_json::from_str(old).unwrap();
        assert_eq!(status.block_rules, 0);
        assert!(!status.blocking_paused);
    }

    #[test]
    fn history_from_an_older_service_still_reads() {
        let old = r#"{"type":"history","apps":[{"app":"chrome.exe","publisher":null,"flows":1,
            "destinations":1,"bytes_sent":2,"bytes_received":3}]}"#;
        let Response::History { apps } = serde_json::from_str(old).unwrap() else {
            panic!("not a history answer");
        };
        assert_eq!(apps[0].app, "chrome.exe");
        assert_eq!(apps[0].path, None);
    }

    #[test]
    fn truncated_messages_are_errors() {
        let mut buffer = Vec::new();
        write_message(&mut buffer, &Request::Status {}).unwrap();
        buffer.truncate(buffer.len() - 1);
        assert!(read_message::<Request>(&mut Cursor::new(buffer)).is_err());
    }
}
