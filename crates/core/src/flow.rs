//! Aggregates raw network events into flows (design spec §5.2).
//!
//! A flow is one process talking to one remote address and port over one
//! protocol. Instead of storing every send and receive, Whereabouts keeps a
//! running total per flow, which is far smaller and reveals no more.
//!
//! # Limits and evasion
//!
//! Memory is bounded by two limits: a total number of flows, and a number of
//! flows per process. When a process reaches its limit, or the table is
//! full, its extra traffic is not dropped. It is added to one *overflow*
//! flow for that process (see [`FlowKey::overflow`]), so the bytes stay
//! visible and attributed. A process that floods the table with fake
//! connections therefore cannot hide another process's traffic.
//!
//! Overflow flows are limited too. Once that limit is reached, further
//! overflow traffic from processes without an overflow flow goes into one
//! shared flow (see [`FlowKey::is_global_overflow`]), so memory stays
//! bounded even if a program starts thousands of processes.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime};

use crate::model::{NetEvent, NetEventKind, Protocol};

/// Default maximum number of regular flows kept in memory.
pub const DEFAULT_MAX_FLOWS: usize = 50_000;

/// Default maximum number of regular flows per process.
pub const DEFAULT_MAX_FLOWS_PER_PROCESS: usize = 5_000;

/// Default maximum number of overflow flows.
pub const DEFAULT_MAX_OVERFLOW_FLOWS: usize = 10_000;

/// Process ID used for the shared overflow flow. PID 0 is the System Idle
/// Process, which never sends network traffic.
const GLOBAL_OVERFLOW_PID: u32 = 0;

/// The remote address used by overflow flows. Real connections never use
/// address `0.0.0.0` with port 0.
const OVERFLOW_REMOTE: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

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

impl FlowKey {
    /// Key of the overflow flow that collects a process's traffic to "many
    /// destinations" once its flow limit is reached.
    pub fn overflow(pid: u32, protocol: Protocol) -> Self {
        Self {
            pid,
            protocol,
            remote: OVERFLOW_REMOTE,
        }
    }

    /// Returns `true` if this is an overflow flow.
    pub fn is_overflow(&self) -> bool {
        self.remote == OVERFLOW_REMOTE
    }

    /// Returns `true` if this is the overflow flow shared by all processes,
    /// used once the overflow limit is reached.
    pub fn is_global_overflow(&self) -> bool {
        self.is_overflow() && self.pid == GLOBAL_OVERFLOW_PID
    }
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
    /// Creates empty totals for a flow first seen at `at`.
    pub fn new(at: SystemTime) -> Self {
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

    /// Adds one event to these totals. The caller decides which flow the
    /// event belongs to; [`FlowTable::record`] does that for live flows.
    pub fn record(&mut self, event: &NetEvent) {
        self.first_seen = self.first_seen.min(event.timestamp);
        self.last_seen = self.last_seen.max(event.timestamp);
        match event.kind {
            NetEventKind::Send => self.bytes_sent = self.bytes_sent.saturating_add(event.bytes),
            NetEventKind::Receive => {
                self.bytes_received = self.bytes_received.saturating_add(event.bytes);
            }
            NetEventKind::Connect | NetEventKind::Accept => {
                self.connections = self.connections.saturating_add(1);
            }
            NetEventKind::Disconnect => {}
        }
    }
}

/// In-memory table of active flows.
#[derive(Debug)]
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowStats>,
    /// Number of regular (non-overflow) flows per process.
    per_process: HashMap<u32, usize>,
    regular_flows: usize,
    overflow_flows: usize,
    max_flows: usize,
    max_flows_per_process: usize,
    max_overflow_flows: usize,
    overflowed_events: u64,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::with_limits(
            DEFAULT_MAX_FLOWS,
            DEFAULT_MAX_FLOWS_PER_PROCESS,
            DEFAULT_MAX_OVERFLOW_FLOWS,
        )
    }
}

impl FlowTable {
    /// Creates an empty table with the default limits.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty table that holds at most `max_flows` regular flows
    /// in total, `max_flows_per_process` per process, and
    /// `max_overflow_flows` overflow flows (plus at most two shared ones).
    pub fn with_limits(
        max_flows: usize,
        max_flows_per_process: usize,
        max_overflow_flows: usize,
    ) -> Self {
        Self {
            flows: HashMap::new(),
            per_process: HashMap::new(),
            regular_flows: 0,
            overflow_flows: 0,
            max_flows,
            max_flows_per_process,
            max_overflow_flows,
            overflowed_events: 0,
        }
    }

    /// Adds one event to its flow.
    ///
    /// Loopback events are ignored. If the event would start a new flow but
    /// a limit is reached, it is added to the process's overflow flow and
    /// counted in [`FlowTable::overflowed_events`].
    pub fn record(&mut self, event: &NetEvent) {
        if event.is_loopback() {
            return;
        }
        let key = FlowKey {
            pid: event.pid,
            protocol: event.protocol,
            remote: event.remote,
        };
        let process_flows = self.per_process.get(&event.pid).copied().unwrap_or(0);
        let at_limit =
            process_flows >= self.max_flows_per_process || self.regular_flows >= self.max_flows;

        let stats = match self.flows.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) if !at_limit && !key.is_overflow() => {
                *self.per_process.entry(event.pid).or_insert(0) += 1;
                self.regular_flows += 1;
                entry.insert(FlowStats::new(event.timestamp))
            }
            Entry::Vacant(_) => {
                self.overflowed_events += 1;
                let own = FlowKey::overflow(event.pid, event.protocol);
                let overflow_key = if self.flows.contains_key(&own)
                    || self.overflow_flows < self.max_overflow_flows
                {
                    own
                } else {
                    FlowKey::overflow(GLOBAL_OVERFLOW_PID, event.protocol)
                };
                match self.flows.entry(overflow_key) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        self.overflow_flows += 1;
                        entry.insert(FlowStats::new(event.timestamp))
                    }
                }
            }
        };
        stats.record(event);
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
        self.take_where(|_, stats| {
            now.duration_since(stats.last_seen)
                .unwrap_or(Duration::ZERO)
                >= idle
        })
    }

    /// Removes and returns every flow of process `pid`, including its
    /// overflow flows.
    ///
    /// Call this when the process exits. Windows reuses process IDs, so a
    /// later process with the same ID must not inherit these flows.
    pub fn take_process(&mut self, pid: u32) -> Vec<(FlowKey, FlowStats)> {
        self.take_where(|key, _| key.pid == pid)
    }

    fn take_where(
        &mut self,
        mut matches: impl FnMut(&FlowKey, &FlowStats) -> bool,
    ) -> Vec<(FlowKey, FlowStats)> {
        let mut taken: Vec<(FlowKey, FlowStats)> = self
            .flows
            .iter()
            .filter(|(key, stats)| matches(key, stats))
            .map(|(key, stats)| (*key, *stats))
            .collect();
        for (key, _) in &taken {
            self.flows.remove(key);
            if key.is_overflow() {
                self.overflow_flows -= 1;
            } else {
                self.regular_flows -= 1;
                if let Entry::Occupied(mut count) = self.per_process.entry(key.pid) {
                    *count.get_mut() -= 1;
                    if *count.get() == 0 {
                        count.remove();
                    }
                }
            }
        }
        taken.sort_by_key(|(key, _)| *key);
        taken
    }

    /// Number of flows in the table, including overflow flows.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Returns `true` if the table has no flows.
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Number of events added to overflow flows because a limit was reached.
    pub fn overflowed_events(&self) -> u64 {
        self.overflowed_events
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

    fn server(n: u16) -> String {
        format!("203.0.113.10:{n}")
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
    fn flooding_process_cannot_hide_another_process() {
        let mut table = FlowTable::with_limits(100, 3, 100);
        // Process 1 opens 50 connections; only 3 get their own flow.
        for port in 1..=50 {
            table.record(&event(1, &server(port), NetEventKind::Send, 10, 1));
        }
        // Process 2 is unaffected.
        table.record(&event(2, SERVER, NetEventKind::Send, 7, 2));

        let flows = table.snapshot();
        let own = |pid| {
            flows
                .iter()
                .filter(|(k, _)| k.pid == pid && !k.is_overflow())
                .count()
        };
        assert_eq!(own(1), 3);
        assert_eq!(own(2), 1);
        // Nothing is lost: the other 47 sends are in process 1's overflow flow.
        let overflow = flows
            .iter()
            .find(|(k, _)| k.pid == 1 && k.is_overflow())
            .expect("overflow flow exists");
        assert_eq!(overflow.1.bytes_sent, 470);
        assert_eq!(table.overflowed_events(), 47);
    }

    #[test]
    fn full_table_sends_new_flows_to_overflow_and_keeps_updating_existing_ones() {
        let mut table = FlowTable::with_limits(1, 10, 100);
        table.record(&event(1, SERVER, NetEventKind::Send, 10, 1));
        table.record(&event(2, SERVER, NetEventKind::Send, 10, 1));
        table.record(&event(1, SERVER, NetEventKind::Send, 5, 2));

        let flows = table.snapshot();
        let regular = flows.iter().find(|(k, _)| k.pid == 1).unwrap();
        assert_eq!(regular.1.bytes_sent, 15);
        assert!(
            flows
                .iter()
                .any(|(k, s)| k.pid == 2 && k.is_overflow() && s.bytes_sent == 10)
        );
        assert_eq!(table.overflowed_events(), 1);
    }

    #[test]
    fn overflow_flows_are_capped_by_a_shared_bucket() {
        // One regular flow in total and one overflow flow before sharing.
        let mut table = FlowTable::with_limits(1, 1, 1);
        table.record(&event(1, &server(1), NetEventKind::Send, 1, 1)); // regular
        table.record(&event(2, &server(2), NetEventKind::Send, 10, 1)); // own overflow
        for pid in 3..=1000 {
            table.record(&event(pid, &server(3), NetEventKind::Send, 100, 1));
        }

        // 1 regular + 1 per-process overflow + 1 shared overflow, however many processes.
        assert_eq!(table.len(), 3);
        let flows = table.snapshot();
        let shared = flows
            .iter()
            .find(|(k, _)| k.is_global_overflow())
            .expect("shared overflow flow exists");
        assert_eq!(shared.1.bytes_sent, 998 * 100);
        // Process 2 keeps its own overflow flow and stays attributed.
        assert!(
            flows
                .iter()
                .any(|(k, s)| k.pid == 2 && k.is_overflow() && s.bytes_sent == 10)
        );
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

    #[test]
    fn take_process_removes_all_flows_of_that_process() {
        let mut table = FlowTable::with_limits(100, 1, 100);
        table.record(&event(1, &server(1), NetEventKind::Send, 1, 1));
        table.record(&event(1, &server(2), NetEventKind::Send, 1, 1)); // overflow
        table.record(&event(2, SERVER, NetEventKind::Send, 1, 1));

        let taken = table.take_process(1);
        assert_eq!(taken.len(), 2);
        assert!(taken.iter().all(|(k, _)| k.pid == 1));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn removed_flows_free_their_slots_for_reused_process_ids() {
        let mut table = FlowTable::with_limits(100, 1, 100);
        table.record(&event(7, &server(1), NetEventKind::Send, 1, 1));
        table.take_process(7);

        // A new process that reuses ID 7 gets a fresh regular flow.
        table.record(&event(7, &server(2), NetEventKind::Send, 1, 2));
        let flows = table.snapshot();
        assert_eq!(flows.len(), 1);
        assert!(!flows[0].0.is_overflow());
        assert_eq!(flows[0].1.first_seen, at(2));
    }
}
