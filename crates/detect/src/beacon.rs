//! Beacon tracker: spots an app contacting one destination at steady
//! intervals with little data each time, like malware checking in with its
//! server (design spec §6.2). Times are always parameters, never read from
//! the clock.

use std::collections::HashMap;

use whereabouts_core::stats::median;
use whereabouts_store::{Reason, Signal};

use crate::signals::{BEACON_MAX_BYTES, BEACON_MAX_CV, BEACON_MAX_GAP, BEACON_MIN, BEACON_MIN_GAP};

/// How far back (seconds, from the newest time held) connections are kept.
pub const BEACON_WINDOW: u64 = 4 * 3600;
/// Most app and destination pairs tracked; the least recently used goes first.
pub const MAX_TRACKED: usize = 2_000;
/// Most connection times kept per pair.
pub const MAX_TIMES: usize = 64;

/// The recent connections of one app and destination pair.
#[derive(Debug, Default)]
struct Pair {
    /// `(time in seconds, bytes)` of each connection, oldest first.
    connections: Vec<(u64, u64)>,
    /// When the pair was last recorded (a tick counter, for eviction).
    last_used: u64,
}

impl Pair {
    /// Drops times outside the window and beyond the cap, oldest first.
    fn trim(&mut self) {
        let Some(&(newest, _)) = self.connections.last() else {
            return;
        };
        let outside = self
            .connections
            .partition_point(|&(time, _)| time.saturating_add(BEACON_WINDOW) < newest);
        let excess = self.connections.len().saturating_sub(MAX_TIMES);
        let drop = outside.max(excess);
        self.connections.drain(..drop);
    }
}

/// Remembers when each app contacted each destination.
#[derive(Debug, Default)]
pub struct BeaconTracker {
    pairs: HashMap<(String, String), Pair>,
    /// Counts records, to order pairs by last use.
    tick: u64,
}

impl BeaconTracker {
    /// Records `count` connections to `destination` at `at_secs` that moved
    /// `bytes` in total. Several connections in one tick share one time, so
    /// they cannot form a pattern on their own. A record more than
    /// [`BEACON_WINDOW`] behind the newest one held means the clock went
    /// back: the pair's history is cleared and starts again from this record.
    pub fn record(
        &mut self,
        app_key: &str,
        destination: &str,
        at_secs: u64,
        count: u32,
        bytes: u64,
    ) {
        if count == 0 {
            return;
        }
        let key = (app_key.to_owned(), destination.to_owned());
        if !self.pairs.contains_key(&key) && self.pairs.len() >= MAX_TRACKED {
            let oldest = self
                .pairs
                .iter()
                .min_by_key(|(_, pair)| pair.last_used)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.pairs.remove(&oldest);
            }
        }
        self.tick += 1;
        let pair = self.pairs.entry(key).or_default();
        pair.last_used = self.tick;
        if let Some(&(newest, _)) = pair.connections.last()
            && at_secs.saturating_add(BEACON_WINDOW) < newest
        {
            pair.connections.clear();
        }

        // Spread the bytes over the connections; the first takes the remainder.
        let share = bytes / u64::from(count);
        let remainder = bytes % u64::from(count);
        // Keeping more than MAX_TIMES copies would only be trimmed again.
        for index in 0..count.min(MAX_TIMES as u32) {
            let own = share + if index == 0 { remainder } else { 0 };
            // Insert after any entry with the same or an earlier time.
            let at = pair
                .connections
                .partition_point(|&(time, _)| time <= at_secs);
            pair.connections.insert(at, (at_secs, own));
        }
        pair.trim();
    }

    /// Whether this app contacts this destination like a beacon: at least
    /// [`BEACON_MIN`] recent connections, every gap between
    /// [`BEACON_MIN_GAP`] and [`BEACON_MAX_GAP`] seconds, gaps that vary by
    /// at most [`BEACON_MAX_CV`], and at most [`BEACON_MAX_BYTES`] per
    /// connection on average. `observed` is the median gap in seconds and
    /// `count` the connections used.
    pub fn check(&self, app_key: &str, destination: &str) -> Option<Reason> {
        let pair = self
            .pairs
            .get(&(app_key.to_owned(), destination.to_owned()))?;
        let connections = &pair.connections;
        // The longest run of the most recent connections that fits, so an
        // early blip does not hide a pattern that began later.
        (BEACON_MIN..=connections.len())
            .rev()
            .find_map(|used| {
                let recent = &connections[connections.len() - used..];
                beacon_gap(recent).map(|gap| (used, gap))
            })
            .map(|(used, gap)| Reason {
                signal: Signal::Beaconing,
                value: Some(destination.to_owned()),
                observed: Some(gap),
                usual: None,
                count: u32::try_from(used).ok(),
            })
    }
}

/// The median gap in seconds if `connections` (oldest first) look like a
/// beacon, else `None`.
fn beacon_gap(connections: &[(u64, u64)]) -> Option<f64> {
    let bytes: u64 = connections.iter().map(|&(_, b)| b).sum();
    if bytes / (connections.len() as u64) > BEACON_MAX_BYTES {
        return None;
    }
    let gaps: Vec<u64> = connections
        .windows(2)
        .map(|pair| pair[1].0.saturating_sub(pair[0].0))
        .collect();
    if gaps
        .iter()
        .any(|gap| !(BEACON_MIN_GAP..=BEACON_MAX_GAP).contains(gap))
    {
        return None;
    }
    let gaps: Vec<f64> = gaps.iter().map(|&gap| gap as f64).collect();
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    let variance = gaps.iter().map(|gap| (gap - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
    // The mean is at least BEACON_MIN_GAP here, so the division is safe.
    if variance.sqrt() / mean > BEACON_MAX_CV {
        return None;
    }
    median(&gaps)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_800_000_000;

    fn feed(tracker: &mut BeaconTracker, gaps: &[u64], bytes: u64) {
        let mut at = T0;
        tracker.record("app", "c2.example", at, 1, bytes);
        for gap in gaps {
            at += gap;
            tracker.record("app", "c2.example", at, 1, bytes);
        }
    }

    fn pair<'a>(tracker: &'a BeaconTracker, destination: &str) -> &'a Pair {
        &tracker.pairs[&("app".to_owned(), destination.to_owned())]
    }

    #[test]
    fn steady_sixty_second_beacon_detected() {
        let mut tracker = BeaconTracker::default();
        feed(&mut tracker, &[60, 58, 62, 60, 59, 61, 60], 500);
        let reason = tracker.check("app", "c2.example").unwrap();
        assert_eq!(reason.signal, Signal::Beaconing);
        assert_eq!(reason.count, Some(8));
        assert_eq!(reason.value.as_deref(), Some("c2.example"));
        assert!((reason.observed.unwrap() - 60.0).abs() < 1.0);
        assert!(tracker.check("app", "other.example").is_none());
    }

    #[test]
    fn irregular_traffic_not_a_beacon() {
        let mut tracker = BeaconTracker::default();
        feed(&mut tracker, &[5, 300, 12, 900, 40, 61], 500);
        assert!(tracker.check("app", "c2.example").is_none());
    }

    #[test]
    fn big_transfers_not_a_beacon() {
        let mut tracker = BeaconTracker::default();
        feed(&mut tracker, &[60; 7], 1_000_000);
        assert!(tracker.check("app", "c2.example").is_none());
    }

    #[test]
    fn too_few_or_same_tick_connections_are_not_a_beacon() {
        let mut tracker = BeaconTracker::default();
        feed(&mut tracker, &[60; 4], 500);
        assert!(tracker.check("app", "c2.example").is_none());
        tracker.record("many", "x.example", T0, 20, 100);
        assert!(tracker.check("many", "x.example").is_none());
    }

    #[test]
    fn an_early_blip_does_not_hide_a_recent_beacon() {
        let mut tracker = BeaconTracker::default();
        tracker.record("app", "c2.example", T0 - 5, 1, 100);
        feed(&mut tracker, &[60; 6], 500);
        let reason = tracker.check("app", "c2.example").unwrap();
        assert_eq!(reason.count, Some(7));
    }

    #[test]
    fn out_of_order_records_are_sorted_and_far_earlier_ones_restart() {
        let mut tracker = BeaconTracker::default();
        for time in [
            T0,
            T0 + 60,
            T0 + 180,
            T0 + 120,
            T0 + 240,
            T0 + 300,
            T0 + 360,
        ] {
            tracker.record("app", "c2.example", time, 1, 500);
        }
        assert_eq!(tracker.check("app", "c2.example").unwrap().count, Some(7));
        // Far behind the newest time: the clock went back, so start again.
        tracker.record("app", "c2.example", T0 - BEACON_WINDOW, 1, 500);
        assert!(tracker.check("app", "c2.example").is_none());
        assert_eq!(pair(&tracker, "c2.example").connections.len(), 1);
    }

    #[test]
    fn old_times_and_bytes_age_out() {
        let mut tracker = BeaconTracker::default();
        // A big early transfer leaves the window and stops counting.
        tracker.record("app", "d", T0, 1, 10_000_000);
        for i in 0..7 {
            tracker.record("app", "d", T0 + BEACON_WINDOW + 1 + i * 60, 1, 10);
        }
        assert_eq!(pair(&tracker, "d").connections.len(), 7);
        assert!(tracker.check("app", "d").is_some());
        for i in 0..100 {
            tracker.record("app", "d", T0 + BEACON_WINDOW + 500 + i, 1, 1);
        }
        assert_eq!(pair(&tracker, "d").connections.len(), MAX_TIMES);
    }

    #[test]
    fn huge_count_stays_bounded() {
        let mut tracker = BeaconTracker::default();
        tracker.record("app", "d", T0, 1_000_000, 5_000);
        assert_eq!(pair(&tracker, "d").connections.len(), MAX_TIMES);
    }

    #[test]
    fn clock_going_back_starts_the_pair_again() {
        let mut tracker = BeaconTracker::default();
        feed(&mut tracker, &[60; 7], 500);
        assert!(tracker.check("app", "c2.example").is_some());
        // The clock jumps back 5 hours; a new steady pattern follows.
        let mut at = T0 - 5 * 3600;
        for _ in 0..8 {
            tracker.record("app", "c2.example", at, 1, 500);
            at += 60;
        }
        let reason = tracker.check("app", "c2.example").unwrap();
        assert_eq!(reason.count, Some(8));
    }

    #[test]
    fn tracker_is_bounded() {
        let mut tracker = BeaconTracker::default();
        for i in 0..=MAX_TRACKED {
            tracker.record("app", &format!("host{i}.example"), T0 + i as u64, 1, 1);
        }
        assert_eq!(tracker.pairs.len(), MAX_TRACKED);
        assert!(
            !tracker
                .pairs
                .contains_key(&("app".to_owned(), "host0.example".to_owned()))
        );
        assert!(
            tracker
                .pairs
                .contains_key(&("app".to_owned(), "host1.example".to_owned()))
        );
    }
}
