//! The lab's timeline format: JSON Lines, a header line first, then flow,
//! connection and counter lines (written by `lab timeline`, see
//! `lab/README.md`).
//!
//! Schema 2 adds each flow's signature and publisher, and connection lines
//! (when each connection was opened, for beaconing). Schema 1 files still
//! read: their flows have no signature or publisher, and there are no
//! connection lines.

use serde::Deserialize;

/// The newest timeline schema this program reads.
pub const SCHEMA: u32 = 2;
/// The oldest timeline schema this program still reads.
const OLDEST_SCHEMA: u32 = 1;

/// One flow of a simulated user (times in Unix seconds, simulated time).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FlowRow {
    pub user: String,
    pub day: u32,
    pub app_name: String,
    pub app_path: Option<String>,
    pub app_sha256: Option<String>,
    /// The export's spelling: `signed`, `unsigned`, `invalid` or `unknown`
    /// (schema 2; `None` in schema 1).
    #[serde(default)]
    pub signature: Option<String>,
    /// The signing publisher, for signed programs (schema 2).
    #[serde(default)]
    pub publisher: Option<String>,
    pub protocol: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub domain: Option<String>,
    pub domain_source: Option<String>,
    pub owner: Option<String>,
    pub country: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connections: u32,
    pub scenario: Option<String>,
}

/// The engine's evasion counters at one moment (they only grow in a session).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CounterRow {
    pub user: String,
    pub time: u64,
    pub rejected: u64,
    pub unattributed: u64,
}

/// One connection a program opened (schema 2): from the engine's
/// `--record-connections` file, or a synthetic scenario. Its bytes are in
/// the flow lines.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConnectionRow {
    pub user: String,
    pub app_path: String,
    pub app_name: String,
    /// The confirmed domain, or the remote address when there was none.
    pub destination: String,
    /// When it was opened (Unix seconds, simulated time).
    pub time: u64,
}

/// One timeline line.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Line {
    Header { schema: u32 },
    Flow(Box<FlowRow>),
    Connection(ConnectionRow),
    Counters(CounterRow),
}

impl Line {
    /// When it happened, for ordering.
    pub fn time(&self) -> u64 {
        match self {
            Line::Header { .. } => 0,
            Line::Flow(flow) => flow.first_seen,
            Line::Connection(connection) => connection.time,
            Line::Counters(counters) => counters.time,
        }
    }
}

/// Reads a timeline: checks the header, then returns flows, connections and
/// counters sorted by time (stable, so equal times keep their order).
pub fn parse(text: &str) -> Result<Vec<Line>, String> {
    let mut lines = Vec::new();
    let mut header = false;
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let line: Line = serde_json::from_str(raw)
            .map_err(|error| format!("timeline line {number}: {error}"))?;
        match line {
            Line::Header { schema } if !header => {
                if !(OLDEST_SCHEMA..=SCHEMA).contains(&schema) {
                    return Err(format!(
                        "timeline schema {schema} is not supported (this program reads \
                         {OLDEST_SCHEMA} to {SCHEMA})"
                    ));
                }
                header = true;
            }
            Line::Header { .. } => return Err(format!("timeline line {number}: a second header")),
            _ if !header => {
                return Err(String::from("the timeline must start with a header line"));
            }
            other => lines.push(other),
        }
    }
    if !header {
        return Err(String::from("the timeline must start with a header line"));
    }
    lines.sort_by_key(Line::time);
    Ok(lines)
}
