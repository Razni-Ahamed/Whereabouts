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

use std::io::{self, Read, Write};

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
            other => other,
        }
    }
}

/// What the service answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Whether kernel network and process events are protected from faking.
    pub kernel_events_protected: bool,
    /// Whether finished flows are being saved.
    pub saving: bool,
    /// Tracker domains loaded from the offline data.
    pub tracker_domains: u64,
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
}

/// Saved totals for one app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppTotals {
    /// Executable file name.
    pub app: String,
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
                publisher: String::from("Microsoft Windows"),
                publisher_confirmed: true,
                protocol: String::from("TCP"),
                domain: Some(String::from("example.com")),
                domain_trust: Some(DomainTrust::AppReported),
                owner: None,
                country: Some(String::from("US")),
                remote: String::from("[2606:4700::1]:443"),
                bytes_sent: 659,
                bytes_received: 5800,
                active: false,
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
    fn truncated_messages_are_errors() {
        let mut buffer = Vec::new();
        write_message(&mut buffer, &Request::Status {}).unwrap();
        buffer.truncate(buffer.len() - 1);
        assert!(read_message::<Request>(&mut Cursor::new(buffer)).is_err());
    }
}
