//! Aggregates raw network events into flows (design spec §5.2).
//!
//! A flow is one process talking to one remote address and port over one
//! protocol. Instead of storing every send and receive, Whereabouts keeps a
//! running total per flow, which is far smaller and reveals no more.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use crate::model::{NetEvent, NetEventKind, Protocol};

/// Default maximum number of flows kept in memory.
///
/// The limit stops a program that opens huge numbers of connections (for
/// example a port scanner) from making Whereabouts use unbounded memory.
pub const DEFAULT_MAX_FLOWS: usize = 50_000;

/// Identifies a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    /// ID of the process that owns the flow.
    pub pid: u32,
    /// Transport protocol.
    pub protocol: Protocol,
    /// Remote address and port.
    pub remote: SocketAddr,
}

/// Running totals for one flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowStats {
    /// Time of the earliest event seen for this flow.
    pub first_seen: SystemTime,
    /// Time of the latest event seen for this flow.
    pub last_seen: SystemTime,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of TCP connections opened or accepted.
    pub connections: u32,
}

impl FlowStats {
    fn new(at: SystemTime) -> Self {
        Self {
            first_seen: at,
            last_seen: at,
            bytes_sent: 0,
            bytes_received: 0,
            connections: 0,
        }
    }

    /// Bytes sent plus bytes received.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent.saturating_add(self.bytes_received)
    }
}

/// In-memory table of active flows.
#[derive(Debug)]
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowStats>,
    max_flows: usize,
    dropped_events: u64,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::with_max_flows(DEFAULT_MAX_FLOWS)
    }
}

impl FlowTable {
    /// Creates an empty table with the [`DEFAULT_MAX_FLOWS`] limit.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty table that holds at most `max_flows` flows.
    pub fn with_max_flows(max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows,
            dropped_events: 0,
        }
    }

    /// Adds one event to its flow.
    ///
    /// Loopback events are ignored. If the table is full, events for new
    /// flows are dropped and counted in [`FlowTable::dropped_events`], while
    /// existing flows keep updating.
    pub fn record(&mut self, event: &NetEvent) {
        if event.is_loopback() {
            return;
        }
        let key = FlowKey {
            pid: event.pid,
            protocol: event.protocol,
            remote: event.remote,
        };
        let len = self.flows.len();
        let stats = match self.flows.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                if len >= self.max_flows {
                    self.dropped_events += 1;
                    return;
                }
                entry.insert(FlowStats::new(event.timestamp))
            }
        };
        stats.first_seen = stats.first_seen.min(event.timestamp);
        stats.last_seen = stats.last_seen.max(event.timestamp);
        match event.kind {
            NetEventKind::Send => stats.bytes_sent = stats.bytes_sent.saturating_add(event.bytes),
            NetEventKind::Receive => {
                stats.bytes_received = stats.bytes_received.saturating_add(event.bytes);
            }
            NetEventKind::Connect | NetEventKind::Accept => {
                stats.connections = stats.connections.saturating_add(1);
            }
            NetEventKind::Disconnect => {}
        }
    }

    /// Returns a copy of all flows, largest total traffic first.
    pub fn snapshot(&self) -> Vec<(FlowKey, FlowStats)> {
        let mut flows: Vec<(FlowKey, FlowStats)> = self
            .flows
            .iter()
            .map(|(key, stats)| (*key, *stats))
            .collect();
        flows.sort_by(|a, b| {
            b.1.total_bytes()
                .cmp(&a.1.total_bytes())
                .then_with(|| a.0.cmp(&b.0))
        });
        flows
    }

    /// Removes and returns every flow with no events for at least `idle`,
    /// measured at `now`. Used to hand finished flows to storage.
    pub fn take_idle(&mut self, now: SystemTime, idle: Duration) -> Vec<(FlowKey, FlowStats)> {
        let mut finished = Vec::new();
        self.flows.retain(|key, stats| {
            let idle_for = now
                .duration_since(stats.last_seen)
                .unwrap_or(Duration::ZERO);
            if idle_for >= idle {
                finished.push((*key, *stats));
                false
            } else {
                true
            }
        });
        finished.sort_by_key(|(key, _)| *key);
        finished
    }

    /// Number of flows in the table.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Returns `true` if the table has no flows.
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Number of events dropped because the table was full.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn event(pid: u32, remote: &str, kind: NetEventKind, bytes: u64, secs: u64) -> NetEvent {
        NetEvent {
            pid,
            protocol: Protocol::Tcp,
            kind,
            local: "192.168.1.10:50000".parse().unwrap(),
            remote: remote.parse().unwrap(),
            bytes,
            timestamp: at(secs),
        }
    }

    const SERVER: &str = "203.0.113.10:443";

    #[test]
    fn sums_sent_and_received_bytes_per_flow() {
        let mut table = FlowTable::new();
        table.record(&event(1, SERVER, NetEventKind::Send, 100, 1));
        table.record(&event(1, SERVER, NetEventKind::Send, 50, 2));
        table.record(&event(1, SERVER, NetEventKind::Receive, 1000, 3));

        let flows = table.snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].1.bytes_sent, 150);
        assert_eq!(flows[0].1.bytes_received, 1000);
        assert_eq!(flows[0].1.total_bytes(), 1150);
    }

    #[test]
    fn different_process_or_port_means_different_flow() {
        let mut table = FlowTable::new();
        table.record(&event(1, SERVER, NetEventKind::Send, 1, 1));
        table.record(&event(2, SERVER, NetEventKind::Send, 1, 1));
        table.record(&event(1, "203.0.113.10:80", NetEventKind::Send, 1, 1));
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn counts_connections_but_not_disconnects() {
        let mut table = FlowTable::new();
        table.record(&event(1, SERVER, NetEventKind::Connect, 0, 1));
        table.record(&event(1, SERVER, NetEventKind::Disconnect, 0, 2));
        table.record(&event(1, SERVER, NetEventKind::Connect, 0, 3));
        assert_eq!(table.snapshot()[0].1.connections, 2);
    }

    #[test]
    fn ignores_loopback_traffic() {
        let mut table = FlowTable::new();
        for remote in ["127.0.0.1:8080", "[::1]:8080", "[::ffff:127.0.0.1]:8080"] {
            table.record(&event(1, remote, NetEventKind::Send, 10, 1));
        }
        assert!(table.is_empty());
    }

    #[test]
    fn tracks_first_and_last_seen_even_out_of_order() {
        let mut table = FlowTable::new();
        table.record(&event(1, SERVER, NetEventKind::Send, 1, 5));
        table.record(&event(1, SERVER, NetEventKind::Send, 1, 2));
        table.record(&event(1, SERVER, NetEventKind::Send, 1, 9));
        let stats = table.snapshot()[0].1;
        assert_eq!(stats.first_seen, at(2));
        assert_eq!(stats.last_seen, at(9));
    }

    #[test]
    fn when_full_drops_new_flows_but_updates_existing_ones() {
        let mut table = FlowTable::with_max_flows(1);
        table.record(&event(1, SERVER, NetEventKind::Send, 10, 1));
        table.record(&event(2, SERVER, NetEventKind::Send, 10, 1));
        table.record(&event(1, SERVER, NetEventKind::Send, 5, 2));

        assert_eq!(table.len(), 1);
        assert_eq!(table.dropped_events(), 1);
        assert_eq!(table.snapshot()[0].1.bytes_sent, 15);
    }

    #[test]
    fn snapshot_is_sorted_by_total_traffic() {
        let mut table = FlowTable::new();
        table.record(&event(1, "198.51.100.1:443", NetEventKind::Send, 10, 1));
        table.record(&event(2, "198.51.100.2:443", NetEventKind::Send, 500, 1));
        table.record(&event(3, "198.51.100.3:443", NetEventKind::Send, 50, 1));
        let pids: Vec<u32> = table.snapshot().iter().map(|(key, _)| key.pid).collect();
        assert_eq!(pids, [2, 3, 1]);
    }

    #[test]
    fn take_idle_removes_only_idle_flows() {
        let mut table = FlowTable::new();
        table.record(&event(1, SERVER, NetEventKind::Send, 1, 10));
        table.record(&event(2, SERVER, NetEventKind::Send, 1, 95));

        let finished = table.take_idle(at(100), Duration::from_secs(60));
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0].0.pid, 1);
        assert_eq!(table.len(), 1);
        assert_eq!(table.snapshot()[0].0.pid, 2);
    }
}
