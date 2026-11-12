//! Core data types shared across Whereabouts.
//!
//! These types describe connection *metadata* only. There is deliberately no
//! field for URL paths, query strings, headers or bodies: Whereabouts never
//! reads traffic contents (privacy principle P1).

use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

/// Transport protocol of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

/// Identity of an application.
///
/// A process name alone is not trusted, because any program can name itself
/// `tiktok.exe`. See the design spec, section 5.3.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AppIdentity {
    /// Full path of the executable.
    pub path: String,
    /// Publisher from the Authenticode signature, or `None` if unsigned.
    pub publisher: Option<String>,
    /// SHA-256 hash of the executable, hex-encoded.
    pub sha256: String,
    /// Package family name for MSIX / Microsoft Store apps.
    pub package_family_name: Option<String>,
}

/// One network flow: an app talking to one remote endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    /// The app that owns the connection.
    pub app: AppIdentity,
    /// Remote IP address.
    pub remote_ip: IpAddr,
    /// Remote port.
    pub remote_port: u16,
    /// Transport protocol.
    pub protocol: Protocol,
    /// Domain name, if known from a DNS lookup.
    pub domain: Option<String>,
    /// When the flow was first seen.
    pub started_at: SystemTime,
    /// When the flow ended, or `None` if it is still open.
    pub ended_at: Option<SystemTime>,
    /// Bytes sent by the app.
    pub bytes_sent: u64,
    /// Bytes received by the app.
    pub bytes_received: u64,
    /// Whether the app was in the foreground when the flow started.
    pub foreground: bool,
}

/// What happened on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetEventKind {
    /// An outgoing TCP connection was opened.
    Connect,
    /// An incoming TCP connection was accepted.
    Accept,
    /// Data was sent.
    Send,
    /// Data was received.
    Receive,
    /// A TCP connection was closed.
    Disconnect,
}

/// One raw network event from the capture layer, before aggregation.
///
/// Like [`Flow`], this holds metadata only: who, where, when and how much.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetEvent {
    /// ID of the process that owns the connection.
    pub pid: u32,
    /// Transport protocol.
    pub protocol: Protocol,
    /// What happened.
    pub kind: NetEventKind,
    /// Local address and port.
    pub local: SocketAddr,
    /// Remote address and port.
    pub remote: SocketAddr,
    /// Payload size in bytes for [`NetEventKind::Send`] and
    /// [`NetEventKind::Receive`]; zero for other kinds.
    pub bytes: u64,
    /// When the event happened.
    pub timestamp: SystemTime,
}

impl NetEvent {
    /// Returns `true` if the remote end is this computer (loopback).
    ///
    /// Loopback traffic never leaves the device, so Whereabouts ignores it.
    pub fn is_loopback(&self) -> bool {
        self.remote.ip().to_canonical().is_loopback()
    }
}

/// Anything the capture layer reports.
///
/// Process events let consumers tell apart two processes that had the same
/// ID at different times: a process is identified by its ID *and* its start
/// time. The capture layer never drops process events, unlike network
/// events, which are dropped (and counted) if the consumer falls behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureEvent {
    /// A network event.
    Net(NetEvent),
    /// A process started.
    ProcessStarted {
        /// ID of the new process.
        pid: u32,
        /// Path of its executable, as reported by the operating system
        /// (on Windows, possibly a `\Device\HarddiskVolumeN\...` path).
        image: String,
        /// When the process started.
        timestamp: SystemTime,
    },
    /// A process exited. Its ID may be reused by a later process, so flows
    /// and names tied to this ID must be closed.
    ProcessExited {
        /// ID of the process that exited.
        pid: u32,
        /// When the process exited.
        timestamp: SystemTime,
    },
    /// A process received a successful DNS answer (from the network or the
    /// cache). Used to label its connections with domain names.
    DnsAnswer {
        /// ID of the process that asked.
        pid: u32,
        /// The name the process asked for, normalised (lowercase, no
        /// trailing dot).
        name: String,
        /// CNAME aliases in the answer.
        aliases: Vec<String>,
        /// Addresses in the answer.
        addresses: Vec<IpAddr>,
        /// When the answer arrived.
        timestamp: SystemTime,
    },
}
