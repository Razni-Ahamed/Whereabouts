//! Remembers which domain name each process looked up for each address, so
//! its connections can be labelled (design spec §5.4).
//!
//! # Trust
//!
//! There are two sources of DNS information, and they are not equally
//! trustworthy:
//!
//! - **App answers** say "process P looked up name N and got address A".
//!   They are logged inside the app, so the app can fake them, for example
//!   to make its connection look like `windowsupdate.microsoft.com`.
//! - **Confirmed answers** say "the Windows DNS service resolved N to A".
//!   They come from the DNS service's own process, which an ordinary program
//!   cannot impersonate.
//!
//! A label is therefore:
//!
//! - [`LabelSource::Verified`] when the app's answer is backed by a
//!   confirmed answer for the same name and address;
//! - [`LabelSource::Unverified`] when only the app says so (it may be a
//!   lie, or the lookup was answered from the cache before Whereabouts
//!   started);
//! - [`LabelSource::Inferred`] when the process made no lookup for the
//!   address but the DNS service resolved it for some name. Only confirmed
//!   answers are used for this, so one app cannot plant labels on another
//!   app's connections.
//!
//! # Limits
//!
//! App answers are bounded per process and in total; answers beyond the
//! limits are counted, not stored. Confirmed answers are bounded in total;
//! when full, the oldest are evicted so new lookups are always recorded.
//! Everything here lives in memory only.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// How long a DNS answer is used for labelling after it was seen.
///
/// Windows does not report the record's TTL in the event, and apps often
/// keep using an address for a while, so a fixed, generous lifetime is used.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// Default maximum number of remembered app answers per process.
pub const DEFAULT_MAX_PER_PROCESS: usize = 10_000;

/// Default maximum number of remembered app answers in total.
pub const DEFAULT_MAX_TOTAL: usize = 200_000;

/// Default maximum number of addresses with confirmed answers.
pub const DEFAULT_MAX_CONFIRMED: usize = 200_000;

/// Most names remembered per confirmed address. Content delivery networks
/// serve many names from one address.
const MAX_NAMES_PER_ADDRESS: usize = 8;

/// How much a label can be trusted. Ordered from least to most trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LabelSource {
    /// The process made no lookup for this address; the name is the most
    /// recent one the DNS service resolved to it.
    Inferred,
    /// Only the app itself reported this lookup.
    Unverified,
    /// The app's lookup is confirmed by the Windows DNS service.
    Verified,
}

/// A domain name attached to a connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainLabel {
    /// The name that was looked up, e.g. `www.example.com`.
    pub name: Arc<str>,
    /// How much the label can be trusted.
    pub source: LabelSource,
}

#[derive(Debug, Clone)]
struct Answer {
    name: Arc<str>,
    at: SystemTime,
}

#[derive(Debug)]
struct Confirmed {
    /// Names resolved to this address, oldest first.
    names: Vec<Arc<str>>,
    at: SystemTime,
}

/// Map of DNS answers per process and per address.
#[derive(Debug)]
pub struct DnsMap {
    asked: HashMap<u32, HashMap<IpAddr, Answer>>,
    asked_entries: usize,
    confirmed: HashMap<IpAddr, Confirmed>,
    /// Insertion order of confirmed updates, for evicting the oldest. May
    /// hold stale entries, which are skipped and periodically compacted.
    confirmed_order: VecDeque<(IpAddr, SystemTime)>,
    lifetime: Duration,
    max_per_process: usize,
    max_total: usize,
    max_confirmed: usize,
    dropped_answers: u64,
}

impl Default for DnsMap {
    fn default() -> Self {
        Self::with_limits(
            DEFAULT_LIFETIME,
            DEFAULT_MAX_PER_PROCESS,
            DEFAULT_MAX_TOTAL,
            DEFAULT_MAX_CONFIRMED,
        )
    }
}

impl DnsMap {
    /// Creates an empty map with the default limits.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty map that keeps answers for `lifetime`, at most
    /// `max_per_process` app answers per process and `max_total` in total,
    /// and confirmed answers for at most `max_confirmed` addresses.
    pub fn with_limits(
        lifetime: Duration,
        max_per_process: usize,
        max_total: usize,
        max_confirmed: usize,
    ) -> Self {
        Self {
            asked: HashMap::new(),
            asked_entries: 0,
            confirmed: HashMap::new(),
            confirmed_order: VecDeque::new(),
            lifetime,
            max_per_process,
            max_total,
            max_confirmed,
            dropped_answers: 0,
        }
    }

    /// Records an app answer: process `pid` says it looked up `name` and
    /// got `addresses`.
    ///
    /// A newer answer for the same process and address replaces the older
    /// one. Addresses beyond the limits are counted in
    /// [`DnsMap::dropped_answers`].
    pub fn record_app_answer(
        &mut self,
        pid: u32,
        name: &str,
        addresses: &[IpAddr],
        at: SystemTime,
    ) {
        let name: Arc<str> = Arc::from(name);
        for address in addresses.iter().map(IpAddr::to_canonical) {
            let answer = Answer {
                name: Arc::clone(&name),
                at,
            };
            let total_full = self.asked_entries >= self.max_total;
            let entries = self.asked.entry(pid).or_default();
            if let Some(existing) = entries.get_mut(&address) {
                *existing = answer;
            } else if entries.len() < self.max_per_process && !total_full {
                entries.insert(address, answer);
                self.asked_entries += 1;
            } else {
                self.dropped_answers += 1;
            }
            if entries.is_empty() {
                self.asked.remove(&pid);
            }
        }
    }

    /// Records a confirmed answer: the Windows DNS service resolved `name`
    /// to `addresses`. Only call this for events from the DNS service's own
    /// process.
    pub fn record_confirmed(&mut self, name: &str, addresses: &[IpAddr], at: SystemTime) {
        let name: Arc<str> = Arc::from(name);
        for address in addresses.iter().map(IpAddr::to_canonical) {
            if let Some(entry) = self.confirmed.get_mut(&address) {
                entry.names.retain(|existing| *existing != name);
                entry.names.push(Arc::clone(&name));
                if entry.names.len() > MAX_NAMES_PER_ADDRESS {
                    entry.names.remove(0);
                }
                entry.at = entry.at.max(at);
            } else {
                while self.confirmed.len() >= self.max_confirmed && self.evict_oldest_confirmed() {}
                if self.confirmed.len() >= self.max_confirmed {
                    continue;
                }
                self.confirmed.insert(
                    address,
                    Confirmed {
                        names: vec![Arc::clone(&name)],
                        at,
                    },
                );
            }
            let latest = self.confirmed[&address].at;
            self.confirmed_order.push_back((address, latest));
        }
        if self.confirmed_order.len() > 2 * self.confirmed.len() + 1024 {
            self.compact_confirmed_order();
        }
    }

    /// Returns the label for a connection from `pid` to `address` at `at`,
    /// or `None` if no fresh answer is known.
    pub fn lookup(&self, pid: u32, address: IpAddr, at: SystemTime) -> Option<DomainLabel> {
        let address = address.to_canonical();
        let confirmed = self
            .confirmed
            .get(&address)
            .filter(|entry| self.is_fresh(entry.at, at));

        let asked = self
            .asked
            .get(&pid)
            .and_then(|entries| entries.get(&address))
            .filter(|answer| self.is_fresh(answer.at, at));
        if let Some(answer) = asked {
            let backed = confirmed.is_some_and(|entry| entry.names.contains(&answer.name));
            return Some(DomainLabel {
                name: Arc::clone(&answer.name),
                source: if backed {
                    LabelSource::Verified
                } else {
                    LabelSource::Unverified
                },
            });
        }

        confirmed
            .and_then(|entry| entry.names.last())
            .map(|name| DomainLabel {
                name: Arc::clone(name),
                source: LabelSource::Inferred,
            })
    }

    /// Forgets the app answers of process `pid`. Call this when it exits:
    /// Windows reuses process IDs, and a new process must not inherit them.
    pub fn forget_process(&mut self, pid: u32) {
        if let Some(entries) = self.asked.remove(&pid) {
            self.asked_entries -= entries.len();
        }
    }

    /// Removes answers older than the lifetime, measured at `now`.
    pub fn expire(&mut self, now: SystemTime) {
        let lifetime = self.lifetime;
        let fresh = |seen: SystemTime| age(seen, now) < lifetime;
        for entries in self.asked.values_mut() {
            entries.retain(|_, answer| fresh(answer.at));
        }
        self.asked.retain(|_, entries| !entries.is_empty());
        self.asked_entries = self.asked.values().map(HashMap::len).sum();
        self.confirmed.retain(|_, entry| fresh(entry.at));
        self.compact_confirmed_order();
    }

    /// Number of remembered app answers (process, address pairs).
    pub fn len(&self) -> usize {
        self.asked_entries
    }

    /// Number of addresses with confirmed answers.
    pub fn confirmed_len(&self) -> usize {
        self.confirmed.len()
    }

    /// Returns `true` if nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.asked_entries == 0 && self.confirmed.is_empty()
    }

    /// Number of app answers not stored because a limit was reached.
    pub fn dropped_answers(&self) -> u64 {
        self.dropped_answers
    }

    fn is_fresh(&self, seen: SystemTime, at: SystemTime) -> bool {
        age(seen, at) < self.lifetime
    }

    /// Removes the confirmed address updated longest ago. Returns `false`
    /// if there was nothing to remove.
    fn evict_oldest_confirmed(&mut self) -> bool {
        while let Some((address, at)) = self.confirmed_order.pop_front() {
            // Skip stale order entries: the address was updated later or
            // already removed.
            if self
                .confirmed
                .get(&address)
                .is_some_and(|entry| entry.at == at)
            {
                self.confirmed.remove(&address);
                return true;
            }
        }
        false
    }

    fn compact_confirmed_order(&mut self) {
        let confirmed = &self.confirmed;
        let mut seen = std::collections::HashSet::new();
        // Keep only the latest order entry per address, in order.
        let mut kept: Vec<(IpAddr, SystemTime)> = self
            .confirmed_order
            .iter()
            .rev()
            .filter(|(address, at)| {
                confirmed.get(address).is_some_and(|entry| entry.at == *at) && seen.insert(*address)
            })
            .copied()
            .collect();
        kept.reverse();
        self.confirmed_order = kept.into();
    }
}

/// Age of something seen at `seen`, measured at `now`; zero if in the future.
fn age(seen: SystemTime, now: SystemTime) -> Duration {
    now.duration_since(seen).unwrap_or(Duration::ZERO)
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

    fn label(map: &DnsMap, pid: u32, address: &str, secs: u64) -> Option<(String, LabelSource)> {
        map.lookup(pid, ip(address), at(secs))
            .map(|l| (l.name.to_string(), l.source))
    }

    fn some(name: &str, source: LabelSource) -> Option<(String, LabelSource)> {
        Some((String::from(name), source))
    }

    #[test]
    fn app_answer_backed_by_the_dns_service_is_verified() {
        let mut map = DnsMap::new();
        map.record_confirmed("example.com", &[ip("104.20.23.154")], at(0));
        map.record_app_answer(7, "example.com", &[ip("104.20.23.154")], at(0));
        assert_eq!(
            label(&map, 7, "104.20.23.154", 1),
            some("example.com", LabelSource::Verified)
        );
    }

    #[test]
    fn app_answer_alone_is_unverified() {
        // E.g. answered from the cache before Whereabouts started.
        let mut map = DnsMap::new();
        map.record_app_answer(7, "example.com", &[ip("104.20.23.154")], at(0));
        assert_eq!(
            label(&map, 7, "104.20.23.154", 1),
            some("example.com", LabelSource::Unverified)
        );
    }

    #[test]
    fn a_forged_app_answer_is_not_verified() {
        // The DNS service resolved evil.example to this address, but the app
        // claims it is windowsupdate.microsoft.com.
        let mut map = DnsMap::new();
        map.record_confirmed("evil.example", &[ip("198.51.100.66")], at(0));
        map.record_app_answer(
            7,
            "windowsupdate.microsoft.com",
            &[ip("198.51.100.66")],
            at(0),
        );
        assert_eq!(
            label(&map, 7, "198.51.100.66", 1),
            some("windowsupdate.microsoft.com", LabelSource::Unverified)
        );
    }

    #[test]
    fn app_answers_never_label_other_processes() {
        let mut map = DnsMap::new();
        map.record_app_answer(7, "planted.example", &[ip("1.2.3.4")], at(0));
        assert_eq!(label(&map, 8, "1.2.3.4", 1), None);
    }

    #[test]
    fn confirmed_answers_give_inferred_labels_to_other_processes() {
        let mut map = DnsMap::new();
        map.record_confirmed("example.com", &[ip("1.2.3.4")], at(0));
        assert_eq!(
            label(&map, 8, "1.2.3.4", 1),
            some("example.com", LabelSource::Inferred)
        );
    }

    #[test]
    fn shared_addresses_verify_any_of_their_names() {
        let mut map = DnsMap::new();
        map.record_confirmed("a.example", &[ip("1.2.3.4")], at(0));
        map.record_confirmed("b.example", &[ip("1.2.3.4")], at(1));
        map.record_app_answer(7, "a.example", &[ip("1.2.3.4")], at(1));
        assert_eq!(
            label(&map, 7, "1.2.3.4", 2),
            some("a.example", LabelSource::Verified)
        );
        // The inferred label is the most recent name.
        assert_eq!(
            label(&map, 8, "1.2.3.4", 2),
            some("b.example", LabelSource::Inferred)
        );
    }

    #[test]
    fn matches_ipv4_mapped_ipv6_addresses() {
        let mut map = DnsMap::new();
        map.record_confirmed("example.com", &[ip("::ffff:1.2.3.4")], at(0));
        map.record_app_answer(7, "example.com", &[ip("1.2.3.4")], at(0));
        assert_eq!(
            label(&map, 7, "::ffff:1.2.3.4", 1),
            some("example.com", LabelSource::Verified)
        );
    }

    #[test]
    fn answers_expire() {
        let lifetime = Duration::from_secs(60);
        let mut map = DnsMap::with_limits(lifetime, 100, 100, 100);
        map.record_confirmed("example.com", &[ip("1.2.3.4")], at(0));
        map.record_app_answer(7, "example.com", &[ip("1.2.3.4")], at(0));
        assert!(label(&map, 7, "1.2.3.4", 59).is_some());
        assert_eq!(label(&map, 7, "1.2.3.4", 60), None);

        map.expire(at(61));
        assert!(map.is_empty());
    }

    #[test]
    fn forgetting_a_process_drops_its_app_answers() {
        let mut map = DnsMap::new();
        map.record_confirmed("example.com", &[ip("1.2.3.4")], at(0));
        map.record_app_answer(7, "example.com", &[ip("1.2.3.4")], at(0));
        map.forget_process(7);
        assert_eq!(map.len(), 0);
        // A new process reusing ID 7 only gets the inferred label.
        assert_eq!(
            label(&map, 7, "1.2.3.4", 1),
            some("example.com", LabelSource::Inferred)
        );
    }

    #[test]
    fn one_process_cannot_fill_app_answers_for_others() {
        let mut map = DnsMap::with_limits(DEFAULT_LIFETIME, 3, 100, 100);
        let flood: Vec<IpAddr> = (0..50).map(|i| ip(&format!("10.0.0.{i}"))).collect();
        map.record_app_answer(1, "flood.example", &flood, at(0));
        assert_eq!(map.len(), 3);
        assert_eq!(map.dropped_answers(), 47);

        map.record_app_answer(2, "example.com", &[ip("1.2.3.4")], at(0));
        assert_eq!(
            label(&map, 2, "1.2.3.4", 1),
            some("example.com", LabelSource::Unverified)
        );
    }

    #[test]
    fn total_app_answer_limit_is_respected() {
        let mut map = DnsMap::with_limits(DEFAULT_LIFETIME, 100, 2, 100);
        for pid in 1..=5 {
            map.record_app_answer(pid, "x.example", &[ip(&format!("10.0.0.{pid}"))], at(0));
        }
        assert_eq!(map.len(), 2);
        assert_eq!(map.dropped_answers(), 3);
    }

    #[test]
    fn full_confirmed_map_evicts_the_oldest_and_keeps_new_lookups() {
        let mut map = DnsMap::with_limits(DEFAULT_LIFETIME, 100, 100, 3);
        for i in 0..10u64 {
            map.record_confirmed("x.example", &[ip(&format!("10.0.0.{i}"))], at(i));
        }
        assert_eq!(map.confirmed_len(), 3);
        // The three newest remain.
        for i in 7..10 {
            assert!(
                label(&map, 1, &format!("10.0.0.{i}"), 10).is_some(),
                "10.0.0.{i}"
            );
        }
        assert_eq!(label(&map, 1, "10.0.0.0", 10), None);
    }

    #[test]
    fn refreshed_addresses_are_not_evicted_first() {
        let mut map = DnsMap::with_limits(DEFAULT_LIFETIME, 100, 100, 2);
        map.record_confirmed("a.example", &[ip("10.0.0.1")], at(0));
        map.record_confirmed("b.example", &[ip("10.0.0.2")], at(1));
        map.record_confirmed("a.example", &[ip("10.0.0.1")], at(2)); // refresh
        map.record_confirmed("c.example", &[ip("10.0.0.3")], at(3)); // evicts b
        assert!(label(&map, 1, "10.0.0.1", 4).is_some());
        assert_eq!(label(&map, 1, "10.0.0.2", 4), None);
        assert!(label(&map, 1, "10.0.0.3", 4).is_some());
    }

    #[test]
    fn names_per_address_are_capped() {
        let mut map = DnsMap::new();
        for i in 0..20 {
            map.record_confirmed(&format!("n{i}.example"), &[ip("1.2.3.4")], at(0));
        }
        map.record_app_answer(7, "n0.example", &[ip("1.2.3.4")], at(0));
        // n0 was pushed out by newer names, so the app's claim is not backed.
        assert_eq!(
            label(&map, 7, "1.2.3.4", 1),
            some("n0.example", LabelSource::Unverified)
        );
        map.record_app_answer(8, "n19.example", &[ip("1.2.3.4")], at(0));
        assert_eq!(
            label(&map, 8, "1.2.3.4", 1),
            some("n19.example", LabelSource::Verified)
        );
    }
}
