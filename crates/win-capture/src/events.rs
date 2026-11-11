//! Decoding of `Microsoft-Windows-Kernel-Network` ETW events.
//!
//! This module is pure logic with no Windows calls, so it can be unit-tested
//! anywhere. The facts encoded here were checked against real events on
//! Windows 11 (see `examples/etw_probe.rs`):
//!
//! - The owning process is in the event's `PID` field. The event *header*
//!   process ID is usually 4 (System) and must not be used.
//! - Ports are stored in network byte order (big-endian).
//! - TCP events and UDP *send* events store the remote end in
//!   `daddr`/`dport`. UDP *receive* events store it in `saddr`/`sport`,
//!   because UDP events describe the packet, not the connection.
//! - Event IDs 18 and 34 ("protocol copied data on behalf of user") repeat
//!   data that receive events already counted, so they are not captured.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use whereabouts_core::model::{NetEvent, NetEventKind, Protocol};

/// GUID of the `Microsoft-Windows-Kernel-Network` ETW provider.
pub const KERNEL_NETWORK_PROVIDER: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";

/// Event IDs that Whereabouts captures (IPv4 and IPv6 variants).
pub const CAPTURED_EVENT_IDS: [u16; 14] = [
    10, 26, // TCP send
    11, 27, // TCP receive
    12, 28, // TCP connect
    13, 29, // TCP disconnect
    15, 31, // TCP accept
    42, 58, // UDP send
    43, 59, // UDP receive
];

/// How to decode one kind of event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventSpec {
    /// Transport protocol.
    pub protocol: Protocol,
    /// What the event means.
    pub kind: NetEventKind,
    /// `true` if the remote end is in `saddr`/`sport` instead of
    /// `daddr`/`dport`.
    pub remote_is_source: bool,
}

/// Returns how to decode `event_id`, or `None` if Whereabouts ignores it.
pub fn classify(event_id: u16) -> Option<EventSpec> {
    let tcp = |kind| EventSpec {
        protocol: Protocol::Tcp,
        kind,
        remote_is_source: false,
    };
    let spec = match event_id {
        10 | 26 => tcp(NetEventKind::Send),
        11 | 27 => tcp(NetEventKind::Receive),
        12 | 28 => tcp(NetEventKind::Connect),
        13 | 29 => tcp(NetEventKind::Disconnect),
        15 | 31 => tcp(NetEventKind::Accept),
        42 | 58 => EventSpec {
            protocol: Protocol::Udp,
            kind: NetEventKind::Send,
            remote_is_source: false,
        },
        43 | 59 => EventSpec {
            protocol: Protocol::Udp,
            kind: NetEventKind::Receive,
            remote_is_source: true,
        },
        _ => return None,
    };
    Some(spec)
}

/// Field values read from one event, exactly as stored by ETW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawFields {
    /// `PID`: the process that owns the connection.
    pub pid: u32,
    /// `size`: payload size in bytes.
    pub size: u32,
    /// `daddr`: destination address.
    pub daddr: IpAddr,
    /// `saddr`: source address.
    pub saddr: IpAddr,
    /// `dport`: destination port, in network byte order.
    pub dport_raw: u16,
    /// `sport`: source port, in network byte order.
    pub sport_raw: u16,
}

/// Builds a [`NetEvent`] from raw ETW fields.
pub fn to_net_event(spec: EventSpec, raw: &RawFields, timestamp: SystemTime) -> NetEvent {
    let destination = SocketAddr::new(raw.daddr, u16::from_be(raw.dport_raw));
    let source = SocketAddr::new(raw.saddr, u16::from_be(raw.sport_raw));
    let (local, remote) = if spec.remote_is_source {
        (destination, source)
    } else {
        (source, destination)
    };
    let bytes = match spec.kind {
        NetEventKind::Send | NetEventKind::Receive => u64::from(raw.size),
        NetEventKind::Connect | NetEventKind::Accept | NetEventKind::Disconnect => 0,
    };
    NetEvent {
        pid: raw.pid,
        protocol: spec.protocol,
        kind: spec.kind,
        local,
        remote,
        bytes,
        timestamp,
    }
}

/// Windows FILETIME value of 1970-01-01T00:00:00Z (100 ns units since 1601).
const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

/// Converts an ETW timestamp (a Windows FILETIME) to [`SystemTime`].
///
/// Times before 1970 are clamped to the Unix epoch.
pub fn filetime_to_system_time(filetime: i64) -> SystemTime {
    let since_unix = u64::try_from(filetime.saturating_sub(FILETIME_UNIX_EPOCH)).unwrap_or(0);
    SystemTime::UNIX_EPOCH + Duration::from_nanos(since_unix.saturating_mul(100))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_V4: &str = "192.168.1.176";
    const REMOTE_V4: &str = "23.55.47.86";

    fn raw(daddr: &str, dport: u16, saddr: &str, sport: u16, size: u32) -> RawFields {
        RawFields {
            pid: 12784,
            size,
            daddr: daddr.parse().unwrap(),
            saddr: saddr.parse().unwrap(),
            // ETW stores ports big-endian; `to_be` produces that layout.
            dport_raw: dport.to_be(),
            sport_raw: sport.to_be(),
        }
    }

    fn ts() -> SystemTime {
        SystemTime::UNIX_EPOCH
    }

    #[test]
    fn every_captured_id_is_classified_and_others_are_ignored() {
        for id in CAPTURED_EVENT_IDS {
            assert!(classify(id).is_some(), "event id {id}");
        }
        for ignored in [14, 16, 17, 18, 30, 32, 33, 34, 0, 999] {
            assert_eq!(classify(ignored), None, "event id {ignored}");
        }
    }

    #[test]
    fn ipv4_and_ipv6_variants_decode_the_same_way() {
        for (v4, v6) in [
            (10, 26),
            (11, 27),
            (12, 28),
            (13, 29),
            (15, 31),
            (42, 58),
            (43, 59),
        ] {
            assert_eq!(classify(v4), classify(v6), "{v4} vs {v6}");
        }
    }

    #[test]
    fn tcp_receive_has_remote_in_destination_fields() {
        // Real event 11: daddr=23.55.47.86:443 (server), saddr=local.
        let spec = classify(11).unwrap();
        let event = to_net_event(spec, &raw(REMOTE_V4, 443, LOCAL_V4, 52182, 3763), ts());
        assert_eq!(event.remote, "23.55.47.86:443".parse().unwrap());
        assert_eq!(event.local, "192.168.1.176:52182".parse().unwrap());
        assert_eq!(event.kind, NetEventKind::Receive);
        assert_eq!(event.protocol, Protocol::Tcp);
        assert_eq!(event.bytes, 3763);
        assert_eq!(event.pid, 12784);
    }

    #[test]
    fn udp_send_has_remote_in_destination_fields() {
        // Real event 42: daddr=23.55.47.86:443, saddr=local:49811.
        let spec = classify(42).unwrap();
        let event = to_net_event(spec, &raw(REMOTE_V4, 443, LOCAL_V4, 49811, 1200), ts());
        assert_eq!(event.remote, "23.55.47.86:443".parse().unwrap());
        assert_eq!(event.protocol, Protocol::Udp);
        assert_eq!(event.kind, NetEventKind::Send);
    }

    #[test]
    fn udp_receive_has_remote_in_source_fields() {
        // Real event 43: daddr=local:49811, saddr=23.55.47.86:443.
        let spec = classify(43).unwrap();
        let event = to_net_event(spec, &raw(LOCAL_V4, 49811, REMOTE_V4, 443, 1200), ts());
        assert_eq!(event.remote, "23.55.47.86:443".parse().unwrap());
        assert_eq!(event.local, "192.168.1.176:49811".parse().unwrap());
        assert_eq!(event.kind, NetEventKind::Receive);
    }

    #[test]
    fn connect_events_carry_no_byte_count() {
        let spec = classify(28).unwrap();
        let event = to_net_event(
            spec,
            &raw("2606:4700:10::6814:179a", 443, "::1", 1, 99),
            ts(),
        );
        assert_eq!(event.kind, NetEventKind::Connect);
        assert_eq!(event.bytes, 0);
        assert_eq!(event.remote.port(), 443);
    }

    #[test]
    fn converts_filetime_to_system_time() {
        // Timestamp from a real event on 2026-11-11.
        let time = filetime_to_system_time(134_388_918_266_861_774);
        let since_unix = time.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(since_unix.as_secs(), 1_794_418_226);
        assert_eq!(since_unix.subsec_nanos(), 686_177_400);
    }

    #[test]
    fn filetime_before_1970_is_clamped() {
        assert_eq!(filetime_to_system_time(0), SystemTime::UNIX_EPOCH);
        assert_eq!(filetime_to_system_time(i64::MIN), SystemTime::UNIX_EPOCH);
    }
}
