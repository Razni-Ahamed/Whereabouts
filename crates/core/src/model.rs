//! Core data types shared across Whereabouts.
//!
//! These types describe connection *metadata* only. There is deliberately no
//! field for URL paths, query strings, headers or bodies: Whereabouts never
//! reads traffic contents (privacy principle P1).

use std::net::IpAddr;
use std::time::SystemTime;

/// Transport protocol of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
