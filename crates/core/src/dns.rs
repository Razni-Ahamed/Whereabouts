//! Remembers which domain name each process looked up for each address, so
//! its connections can be labelled (design spec §5.4).
//!
//! A label is **direct** when the same process looked the address up. If not
//! (for example, the app reuses an address another app resolved, or uses its
//! own DNS-over-HTTPS), the most recent lookup of that address by *any*
//! process is used and the label is marked **inferred**, because one address
//! can serve many domains.
//!
//! Like [`crate::flow::FlowTable`], memory is bounded: per process and in
//! total. Answers beyond the limits are counted, not stored. Everything here
//! lives in memory only.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// How long a DNS answer is used for labelling after it was seen.
///
/// Windows does not report the record's TTL in the event, and apps often
/// keep using an address for a while, so a fixed, generous lifetime is used.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// Default maximum number of remembered addresses per process.
pub const DEFAULT_MAX_PER_PROCESS: usize = 10_000;

/// Default maximum number of remembered addresses in total.
pub const DEFAULT_MAX_TOTAL: usize = 200_000;

/// A domain name attached to a connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainLabel {
    /// The name that was looked up, e.g. `www.example.com`.
    pub name: Arc<str>,
    /// `true` if another process made the lookup, so the label is a guess.
    pub inferred: bool,
}

#[derive(Debug, Clone)]
struct Answer {
    name: Arc<str>,
    at: SystemTime,
}

/// Map of DNS answers per process and per address.
#[derive(Debug)]
pub struct DnsMap {
    by_process: HashMap<u32, HashMap<IpAddr, Answer>>,
    by_address: HashMap<IpAddr, Answer>,
    process_entries: usize,
    lifetime: Duration,
    max_per_process: usize,
    max_total: usize,
    dropped_answers: u64,
}

impl Default for DnsMap {
    fn default() -> Self {
        Self::with_limits(DEFAULT_LIFETIME, DEFAULT_MAX_PER_PROCESS, DEFAULT_MAX_TOTAL)
    }
}

impl DnsMap {
    /// Creates an empty map with the default limits.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty map that keeps answers for `lifetime`, at most
    /// `max_per_process` addresses per process and `max_total` in total.
    pub fn with_limits(lifetime: Duration, max_per_process: usize, max_total: usize) -> Self {
        Self {
            by_process: HashMap::new(),
            by_address: HashMap::new(),
            process_entries: 0,
            lifetime,
            max_per_process,
            max_total,
            dropped_answers: 0,
        }
    }

    /// Records that process `pid` looked up `name` and got `addresses`.
    ///
    /// A newer answer for the same process and address replaces the older
    /// one. Addresses beyond the limits are counted in
    /// [`DnsMap::dropped_answers`].
    pub fn record(&mut self, pid: u32, name: &str, addresses: &[IpAddr], at: SystemTime) {
        let name: Arc<str> = Arc::from(name);
        for address in addresses.iter().map(IpAddr::to_canonical) {
            let answer = Answer {
                name: Arc::clone(&name),
                at,
            };

            let total_full = self.process_entries >= self.max_total;
            let entries = self.by_process.entry(pid).or_default();
            if let Some(existing) = entries.get_mut(&address) {
                *existing = answer.clone();
            } else if entries.len() < self.max_per_process && !total_full {
                entries.insert(address, answer.clone());
                self.process_entries += 1;
            } else {
                self.dropped_answers += 1;
            }
            if entries.is_empty() {
                self.by_process.remove(&pid);
            }

            if self.by_address.len() < self.max_total || self.by_address.contains_key(&address) {
                self.by_address.insert(address, answer);
            }
        }
    }

    /// Returns the label for a connection from `pid` to `address` at `at`,
    /// or `None` if no fresh answer is known.
    pub fn lookup(&self, pid: u32, address: IpAddr, at: SystemTime) -> Option<DomainLabel> {
        let address = address.to_canonical();
        let fresh = |answer: &&Answer| self.is_fresh(answer, at);
        if let Some(answer) = self
            .by_process
            .get(&pid)
            .and_then(|entries| entries.get(&address))
            .filter(fresh)
        {
            return Some(DomainLabel {
                name: Arc::clone(&answer.name),
                inferred: false,
            });
        }
        self.by_address
            .get(&address)
            .filter(fresh)
            .map(|answer| DomainLabel {
                name: Arc::clone(&answer.name),
                inferred: true,
            })
    }

    /// Forgets the lookups of process `pid`. Call this when it exits:
    /// Windows reuses process IDs, and a new process must not inherit them.
    ///
    /// Its answers stay available for *inferred* labels until they expire.
    pub fn forget_process(&mut self, pid: u32) {
        if let Some(entries) = self.by_process.remove(&pid) {
            self.process_entries -= entries.len();
        }
    }

    /// Removes answers older than the lifetime, measured at `now`.
    pub fn expire(&mut self, now: SystemTime) {
        let lifetime = self.lifetime;
        let fresh = |answer: &Answer| age(answer, now) < lifetime;
        for entries in self.by_process.values_mut() {
            entries.retain(|_, answer| fresh(answer));
        }
        self.by_process.retain(|_, entries| !entries.is_empty());
        self.process_entries = self.by_process.values().map(HashMap::len).sum();
        self.by_address.retain(|_, answer| fresh(answer));
    }

    /// Number of remembered (process, address) pairs.
    pub fn len(&self) -> usize {
        self.process_entries
    }

    /// Returns `true` if no answers are remembered.
    pub fn is_empty(&self) -> bool {
        self.process_entries == 0 && self.by_address.is_empty()
    }

    /// Number of answers not stored because a limit was reached.
    pub fn dropped_answers(&self) -> u64 {
        self.dropped_answers
    }

    fn is_fresh(&self, answer: &Answer, at: SystemTime) -> bool {
        age(answer, at) < self.lifetime
    }
}

/// Age of `answer` at `now`; zero if the answer is in the future.
fn age(answer: &Answer, now: SystemTime) -> Duration {
    now.duration_since(answer.at).unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn name(label: Option<DomainLabel>) -> Option<(String, bool)> {
        label.map(|l| (l.name.to_string(), l.inferred))
    }

    #[test]
    fn labels_connections_of_the_process_that_looked_up() {
        let mut map = DnsMap::new();
        map.record(
            7,
            "example.com",
            &[ip("104.20.23.154"), ip("2606:4700:10::6814:179a")],
            at(0),
        );
        assert_eq!(
            name(map.lookup(7, ip("104.20.23.154"), at(1))),
            Some((String::from("example.com"), false))
        );
        assert_eq!(
            name(map.lookup(7, ip("2606:4700:10::6814:179a"), at(1))),
            Some((String::from("example.com"), false))
        );
        assert_eq!(map.lookup(7, ip("198.51.100.1"), at(1)), None);
    }

    #[test]
    fn other_processes_get_an_inferred_label() {
        let mut map = DnsMap::new();
        map.record(7, "example.com", &[ip("104.20.23.154")], at(0));
        assert_eq!(
            name(map.lookup(8, ip("104.20.23.154"), at(1))),
            Some((String::from("example.com"), true))
        );
    }

    #[test]
    fn matches_ipv4_mapped_ipv6_addresses() {
        let mut map = DnsMap::new();
        map.record(7, "example.com", &[ip("::ffff:1.2.3.4")], at(0));
        assert!(map.lookup(7, ip("1.2.3.4"), at(1)).is_some());
        map.record(7, "other.example", &[ip("5.6.7.8")], at(0));
        assert!(map.lookup(7, ip("::ffff:5.6.7.8"), at(1)).is_some());
    }

    #[test]
    fn newest_answer_wins_for_the_same_address() {
        let mut map = DnsMap::new();
        map.record(7, "old.example", &[ip("1.2.3.4")], at(0));
        map.record(7, "new.example", &[ip("1.2.3.4")], at(5));
        assert_eq!(
            name(map.lookup(7, ip("1.2.3.4"), at(6))),
            Some((String::from("new.example"), false))
        );
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn answers_expire() {
        let lifetime = Duration::from_secs(60);
        let mut map = DnsMap::with_limits(lifetime, 100, 100);
        map.record(7, "example.com", &[ip("1.2.3.4")], at(0));
        assert!(map.lookup(7, ip("1.2.3.4"), at(59)).is_some());
        assert!(map.lookup(7, ip("1.2.3.4"), at(60)).is_none());

        map.expire(at(61));
        assert!(map.is_empty());
    }

    #[test]
    fn forgetting_a_process_keeps_only_inferred_labels() {
        let mut map = DnsMap::new();
        map.record(7, "example.com", &[ip("1.2.3.4")], at(0));
        map.forget_process(7);
        assert_eq!(map.len(), 0);
        // A new process reusing ID 7 does not get a direct label.
        assert_eq!(
            name(map.lookup(7, ip("1.2.3.4"), at(1))),
            Some((String::from("example.com"), true))
        );
    }

    #[test]
    fn one_process_cannot_fill_the_map_for_others() {
        let mut map = DnsMap::with_limits(DEFAULT_LIFETIME, 3, 100);
        let flood: Vec<IpAddr> = (0..50).map(|i| ip(&format!("10.0.0.{i}"))).collect();
        map.record(1, "flood.example", &flood, at(0));
        assert_eq!(map.len(), 3);
        assert_eq!(map.dropped_answers(), 47);

        map.record(2, "example.com", &[ip("1.2.3.4")], at(0));
        assert_eq!(
            name(map.lookup(2, ip("1.2.3.4"), at(1))),
            Some((String::from("example.com"), false))
        );
    }

    #[test]
    fn total_limit_is_respected() {
        let mut map = DnsMap::with_limits(DEFAULT_LIFETIME, 100, 2);
        for pid in 1..=5 {
            map.record(pid, "x.example", &[ip(&format!("10.0.0.{pid}"))], at(0));
        }
        assert_eq!(map.len(), 2);
        assert_eq!(map.dropped_answers(), 3);
    }
}
