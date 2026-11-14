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

/// Result of checking an executable's code signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Signature {
    /// A valid signature that chains to a trusted root.
    Signed {
        /// The signer's name from the certificate, e.g. "Microsoft Windows".
        publisher: String,
        /// `true` if the file is signed through a Windows security catalog
        /// (common for files that ship with Windows) rather than with a
        /// signature embedded in the file.
        via_catalog: bool,
    },
    /// No signature at all.
    Unsigned,
    /// A signature is present but is not valid or not trusted, for example
    /// because the file was changed after signing.
    Invalid {
        /// The Windows error code (an `HRESULT`).
        code: u32,
    },
    /// The signature could not be checked, for example because the file
    /// could not be read.
    Unknown,
}

/// Identity of an application.
///
/// A process name alone is not trusted, because any program can name itself
/// `tiktok.exe`. The signature and file hash identify what the program
/// really is. See the design spec, section 5.3.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AppIdentity {
    /// Full path of the executable.
    pub path: String,
    /// Result of checking the code signature.
    pub signature: Signature,
    /// SHA-256 hash of the executable, hex-encoded, if it could be read and
    /// is not too large to hash.
    pub sha256: Option<String>,
    /// Size of the executable in bytes, if it could be read.
    pub size: Option<u64>,
    /// Package family name for MSIX / Microsoft Store apps.
    pub package_family_name: Option<String>,
    /// `true` if the file checked was confirmed to be the file the process
    /// was running (by the kernel's record, while the file was locked).
    /// `false` if it was checked by path only, for example because the
    /// process had already exited; the result could then be for a different
    /// file than the one that ran.
    pub confirmed_running: bool,
}

impl AppIdentity {
    /// Short text for the publisher, for display: the signer's name, or a
    /// warning if the program is unsigned or its signature is not valid.
    pub fn publisher_text(&self) -> String {
        match &self.signature {
            Signature::Signed { publisher, .. } => publisher.clone(),
            Signature::Unsigned => String::from("UNSIGNED"),
            Signature::Invalid { .. } => String::from("INVALID SIGNATURE"),
            Signature::Unknown => String::from("(not checked)"),
        }
    }
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
    /// The Windows DNS service resolved a name. Unlike
    /// [`CaptureEvent::DnsAnswer`], this comes from the DNS service's own
    /// process, which ordinary programs cannot impersonate, so it is used to
    /// verify what apps report.
    DnsConfirmed {
        /// The name that was resolved, normalised.
        name: String,
        /// Addresses in the answer.
        addresses: Vec<IpAddr>,
        /// When the answer arrived.
        timestamp: SystemTime,
    },
    /// A process reported a successful DNS answer (from the network or the
    /// cache). Used to label its connections with domain names. The process
    /// itself logs this, so it can be faked; see `core::dns` for how it is
    /// verified.
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
