//! Per-hour traffic meter: turns the running totals of flows into the bytes
//! and connections that are new since the last tick, filed under the hour
//! they were seen in (design spec §6.2).

use std::collections::HashMap;
use std::time::SystemTime;

use whereabouts_core::flow::FlowKey;

use crate::unix_secs;

/// The totals of one open or just-closed flow at one tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSample {
    /// Identifies the flow between ticks.
    pub key: FlowKey,
    /// The app the flow belongs to.
    pub app_key: String,
    /// The confirmed destination name, if known.
    pub destination: Option<String>,
    /// Bytes sent so far.
    pub bytes_sent: u64,
    /// Bytes received so far.
    pub bytes_received: u64,
    /// Connections seen so far.
    pub connections: u32,
}

/// What one flow did since the previous tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    /// The app the flow belongs to.
    pub app_key: String,
    /// The confirmed destination name, if known.
    pub destination: Option<String>,
    /// Hours since the Unix epoch of the tick (`unix_secs / 3600`).
    pub hour: i64,
    /// Bytes sent since the previous tick.
    pub sent: u64,
    /// Bytes received since the previous tick.
    pub received: u64,
    /// Connections opened since the previous tick.
    pub new_connections: u32,
}

/// Compares each flow's totals with those of the previous tick.
#[derive(Debug, Default)]
pub struct Meter {
    /// Totals (sent, received, connections) at the previous tick.
    previous: HashMap<FlowKey, (u64, u64, u32)>,
}

impl Meter {
    /// Returns what each flow did since the last call, at most one [`Delta`]
    /// per flow. A flow seen for the first time counts all of its totals;
    /// a total that shrank counts as 0; flows with nothing new are left out.
    /// Flows missing from `flows` are forgotten. A clock that went back puts
    /// the delta in the hour of `now` (hour 0 before the Unix epoch).
    pub fn sample(&mut self, now: SystemTime, flows: &[FlowSample]) -> Vec<Delta> {
        let hour = i64::try_from(unix_secs(now) / 3600).unwrap_or(i64::MAX);
        let mut current = HashMap::with_capacity(flows.len());
        let mut deltas = Vec::new();
        for flow in flows {
            let (sent, received, connections) =
                self.previous.get(&flow.key).copied().unwrap_or_default();
            let delta = Delta {
                app_key: flow.app_key.clone(),
                destination: flow.destination.clone(),
                hour,
                sent: flow.bytes_sent.saturating_sub(sent),
                received: flow.bytes_received.saturating_sub(received),
                new_connections: flow.connections.saturating_sub(connections),
            };
            current.insert(
                flow.key,
                (flow.bytes_sent, flow.bytes_received, flow.connections),
            );
            if delta.sent > 0 || delta.received > 0 || delta.new_connections > 0 {
                deltas.push(delta);
            }
        }
        self.previous = current;
        deltas
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn flow(sent: u64, received: u64, connections: u32) -> FlowSample {
        FlowSample {
            key: crate::key("198.51.100.1:443"),
            app_key: "chat.exe".to_owned(),
            destination: Some("chat.example".to_owned()),
            bytes_sent: sent,
            bytes_received: received,
            connections,
        }
    }

    #[test]
    fn first_sample_counts_full_totals_then_deltas() {
        let mut meter = Meter::default();
        let first = meter.sample(at(3600), &[flow(100, 20, 1)]);
        assert_eq!((first[0].sent, first[0].received), (100, 20));
        assert_eq!(first[0].new_connections, 1);
        assert_eq!(first[0].destination.as_deref(), Some("chat.example"));
        let second = meter.sample(at(3660), &[flow(150, 20, 1)]);
        assert_eq!(second.len(), 1);
        assert_eq!(
            (
                second[0].sent,
                second[0].received,
                second[0].new_connections
            ),
            (50, 0, 0)
        );
        // Nothing new: nothing returned.
        assert!(meter.sample(at(3720), &[flow(150, 20, 1)]).is_empty());
    }

    #[test]
    fn delta_goes_to_hour_of_now() {
        let mut meter = Meter::default();
        let base = 10 * 3600;
        assert_eq!(meter.sample(at(base + 3599), &[flow(1, 0, 1)])[0].hour, 10);
        assert_eq!(meter.sample(at(base + 3601), &[flow(2, 0, 1)])[0].hour, 11);
    }

    #[test]
    fn meter_survives_clock_going_back() {
        let mut meter = Meter::default();
        meter.sample(at(10 * 3600), &[flow(100, 0, 1)]);
        let back = meter.sample(at(8 * 3600), &[flow(160, 0, 1)]);
        assert_eq!((back[0].hour, back[0].sent), (8, 60));
        // Before the Unix epoch counts as hour 0.
        let early = meter.sample(UNIX_EPOCH - Duration::from_secs(5), &[flow(200, 0, 1)]);
        assert_eq!((early[0].hour, early[0].sent), (0, 40));
    }

    #[test]
    fn shrinking_total_counts_zero() {
        let mut meter = Meter::default();
        meter.sample(at(3600), &[flow(500, 500, 2)]);
        assert!(meter.sample(at(3660), &[flow(100, 100, 1)]).is_empty());
        // The shrunken totals are the new baseline.
        let next = meter.sample(at(3720), &[flow(130, 100, 1)]);
        assert_eq!(next[0].sent, 30);
    }

    #[test]
    fn new_connections_counted_from_connection_count() {
        let mut meter = Meter::default();
        meter.sample(at(3600), &[flow(10, 0, 3)]);
        let next = meter.sample(at(3660), &[flow(10, 0, 5)]);
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].new_connections, 2);
    }

    #[test]
    fn flows_that_disappear_are_forgotten() {
        let mut meter = Meter::default();
        meter.sample(at(3600), &[flow(100, 0, 1)]);
        meter.sample(at(3660), &[]);
        // Seen again: counts as new.
        assert_eq!(meter.sample(at(3720), &[flow(100, 0, 1)])[0].sent, 100);
    }
}
