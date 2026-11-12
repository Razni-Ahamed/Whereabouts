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
//! - [`LabelSource::Verified`] when the Windows DNS service resolved the
//!   *same name* the app reported to the *same address*. This proves the app
//!   did not invent the pair. It does not prove who runs the server: DNS
//!   itself can be lied to (for example by a malicious DNS server).
//! - [`LabelSource::Unverified`] when only the app says so (it may be a
//!   lie, or the lookup was answered from the cache before Whereabouts
//!   started).
//! - [`LabelSource::Inferred`] when the process made no lookup for the
//!   address but the DNS service resolved some name to it. Only confirmed
//!   answers are used for this, so one app cannot plant labels on another
//!   app's connections. It is a guess: one address can serve many names.
//!
//! Confirmations are kept **by name**, and an app answer is checked against
//! them when it arrives; the result is stored with the answer. So a later
//! flood of lookups cannot undo a verification, and an attacker who points
//! their own domain at a popular address cannot verify a different name.
//! The per-address list used for inferred labels keeps the *first* names it
//! sees; newer names never push older ones out.
//!
//! # Limits
//!
//! App answers are bounded per process and in total; answers beyond the
//! limits are counted, not stored. Confirmations are bounded in total; when
//! full, the least recently confirmed are evicted, so new lookups are always
//! recorded. Everything here lives in memory only.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
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

/// Default maximum number of names and of addresses with confirmations.
pub const DEFAULT_MAX_CONFIRMED: usize = 200_000;

/// Most names remembered per address for inferred labels. Content delivery
/// networks serve many names from one address.
const MAX_NAMES_PER_ADDRESS: usize = 8;

/// Most addresses remembered per confirmed name.
const MAX_ADDRESSES_PER_NAME: usize = 64;

/// How much a label can be trusted. Ordered from least to most trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LabelSource {
    /// The process made no lookup for this address; the name is one the DNS
    /// service resolved to it.
    Inferred,
    /// Only the app itself reported this lookup.
    Unverified,
    /// The Windows DNS service resolved the app's name to this address.
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
    /// Whether a confirmation existed when the answer arrived.
    verified: bool,
}

/// A bounded map that evicts the least recently updated entry when full.
#[derive(Debug)]
struct Recent<K, V> {
    map: HashMap<K, (V, SystemTime)>,
    /// Update order, oldest first. May hold stale entries, which are skipped
    /// on eviction and removed by compaction.
    order: VecDeque<(K, SystemTime)>,
    max: usize,
}

impl<K: Hash + Eq + Clone, V> Recent<K, V> {
    fn new(max: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            max,
        }
    }

    fn get(&self, key: &K) -> Option<(&V, SystemTime)> {
        self.map.get(key).map(|(value, at)| (value, *at))
    }

    /// Updates `key` with `update`, or inserts `make()` if it is absent,
    /// evicting the least recently updated entries if the map is full.
    fn upsert(
        &mut self,
        key: K,
        at: SystemTime,
        make: impl FnOnce() -> V,
        update: impl FnOnce(&mut V),
    ) {
        let latest = if let Some((value, seen)) = self.map.get_mut(&key) {
            update(value);
            *seen = (*seen).max(at);
            *seen
        } else {
            while self.map.len() >= self.max && self.evict_oldest() {}
            if self.map.len() >= self.max {
                return;
            }
            self.map.insert(key.clone(), (make(), at));
            at
        };
        self.order.push_back((key, latest));
        if self.order.len() > 2 * self.map.len() + 1024 {
            self.compact();
        }
    }

    fn evict_oldest(&mut self) -> bool {
        while let Some((key, at)) = self.order.pop_front() {
            if self.map.get(&key).is_some_and(|(_, seen)| *seen == at) {
                self.map.remove(&key);
                return true;
            }
        }
        false
    }

    /// Keeps only the latest order entry per key.
    fn compact(&mut self) {
        let map = &self.map;
        let mut seen = HashSet::new();
        let mut kept: Vec<(K, SystemTime)> = self
            .order
            .iter()
            .rev()
            .filter(|(key, at)| {
                map.get(key).is_some_and(|(_, latest)| latest == at) && seen.insert(key.clone())
            })
            .cloned()
            .collect();
        kept.reverse();
        self.order = kept.into();
    }

    fn retain_fresh(&mut self, now: SystemTime, lifetime: Duration) {
        self.map.retain(|_, (_, at)| age(*at, now) < lifetime);
        self.compact();
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

/// Map of DNS answers per process, with confirmations per name and address.
#[derive(Debug)]
pub struct DnsMap {
    asked: HashMap<u32, HashMap<IpAddr, Answer>>,
    asked_entries: usize,
    /// Name -> addresses the DNS service resolved it to.
    by_name: Recent<Arc<str>, HashSet<IpAddr>>,
    /// Address -> names the DNS service resolved to it (first ones kept),
    /// each with when it was last confirmed.
    by_address: Recent<IpAddr, Vec<(Arc<str>, SystemTime)>>,
    lifetime: Duration,
    max_per_process: usize,
    max_total: usize,
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
    /// and confirmations for at most `max_confirmed` names and addresses.
    pub fn with_limits(
        lifetime: Duration,
        max_per_process: usize,
        max_total: usize,
        max_confirmed: usize,
    ) -> Self {
        Self {
            asked: HashMap::new(),
            asked_entries: 0,
            by_name: Recent::new(max_confirmed),
            by_address: Recent::new(max_confirmed),
            lifetime,
            max_per_process,
            max_total,
            dropped_answers: 0,
        }
    }

    /// Records an app answer: process `pid` says it looked up `name` and
    /// got `addresses`. Each address is checked against the confirmations
    /// now, and the result is kept with the answer.
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
                verified: self.is_confirmed(&name, address, at),
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
        let addresses: Vec<IpAddr> = addresses.iter().map(IpAddr::to_canonical).collect();

        let initial: HashSet<IpAddr> = addresses
            .iter()
            .copied()
            .take(MAX_ADDRESSES_PER_NAME)
            .collect();
        self.by_name.upsert(
            Arc::clone(&name),
            at,
            || initial,
            |known| {
                for address in &addresses {
                    if known.len() >= MAX_ADDRESSES_PER_NAME {
                        break;
                    }
                    known.insert(*address);
                }
            },
        );

        for address in addresses {
            self.by_address.upsert(
                address,
                at,
                || vec![(Arc::clone(&name), at)],
                |names| {
                    if let Some(entry) = names.iter_mut().find(|(known, _)| *known == name) {
                        entry.1 = entry.1.max(at);
                    } else if names.len() < MAX_NAMES_PER_ADDRESS {
                        names.push((Arc::clone(&name), at));
                    }
                    // Otherwise the new name is ignored: earlier names are
                    // never pushed out by later ones.
                },
            );
        }
    }

    /// Returns the label for a connection from `pid` to `address` at `at`,
    /// or `None` if no fresh answer is known.
    pub fn lookup(&self, pid: u32, address: IpAddr, at: SystemTime) -> Option<DomainLabel> {
        let address = address.to_canonical();
        let asked = self
            .asked
            .get(&pid)
            .and_then(|entries| entries.get(&address))
            .filter(|answer| self.is_fresh(answer.at, at));
        if let Some(answer) = asked {
            // The confirmation may also arrive just after the app's answer.
            let verified = answer.verified || self.is_confirmed(&answer.name, address, at);
            return Some(DomainLabel {
                name: Arc::clone(&answer.name),
                source: if verified {
                    LabelSource::Verified
                } else {
                    LabelSource::Unverified
                },
            });
        }

        let (names, seen) = self.by_address.get(&address)?;
        if !self.is_fresh(seen, at) {
            return None;
        }
        names
            .iter()
            .max_by_key(|(_, confirmed_at)| *confirmed_at)
            .map(|(name, _)| DomainLabel {
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
        for entries in self.asked.values_mut() {
            entries.retain(|_, answer| age(answer.at, now) < lifetime);
        }
        self.asked.retain(|_, entries| !entries.is_empty());
        self.asked_entries = self.asked.values().map(HashMap::len).sum();
        self.by_name.retain_fresh(now, lifetime);
        self.by_address.retain_fresh(now, lifetime);
    }

    /// Number of remembered app answers (process, address pairs).
    pub fn len(&self) -> usize {
        self.asked_entries
    }

    /// Number of names with confirmations.
    pub fn confirmed_len(&self) -> usize {
        self.by_name.len()
    }

    /// Returns `true` if nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.asked_entries == 0 && self.by_name.len() == 0 && self.by_address.len() == 0
    }

    /// Number of app answers not stored because a limit was reached.
    pub fn dropped_answers(&self) -> u64 {
        self.dropped_answers
    }

    /// Whether the DNS service recently resolved `name` to `address`.
    fn is_confirmed(&self, name: &Arc<str>, address: IpAddr, at: SystemTime) -> bool {
        self.by_name.get(name).is_some_and(|(addresses, seen)| {
            self.is_fresh(seen, at) && addresses.contains(&address)
        })
    }

    fn is_fresh(&self, seen: SystemTime, at: SystemTime) -> bool {
        age(seen, at) < self.lifetime
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
    fn confirmation_arriving_just_after_the_app_answer_still_verifies() {
        let mut map = DnsMap::new();
        map.record_app_answer(7, "example.com", &[ip("104.20.23.154")], at(0));
        map.record_confirmed("example.com", &[ip("104.20.23.154")], at(0));
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
    fn pointing_another_name_at_an_address_does_not_verify_a_claim() {
        // An attacker's own domain resolves to example.com's address. That
        // must not verify an app's claim that the address is some third name.
        let mut map = DnsMap::new();
        map.record_confirmed("attacker.example", &[ip("104.20.23.154")], at(0));
        map.record_app_answer(7, "bank.example", &[ip("104.20.23.154")], at(0));
        assert_eq!(
            label(&map, 7, "104.20.23.154", 1),
            some("bank.example", LabelSource::Unverified)
        );
    }

    #[test]
    fn a_flood_of_names_cannot_undo_an_earlier_verification() {
        let mut map = DnsMap::with_limits(DEFAULT_LIFETIME, 100, 100, 5);
        map.record_confirmed("example.com", &[ip("104.20.23.154")], at(0));
        map.record_app_answer(7, "example.com", &[ip("104.20.23.154")], at(0));
        // The attacker's lookups evict example.com's confirmation...
        for i in 0..50 {
            map.record_confirmed(
                &format!("a{i}.attacker.example"),
                &[ip("104.20.23.154")],
                at(1),
            );
        }
        assert_eq!(map.confirmed_len(), 5);
        // ...but the verification was recorded with the app's answer.
        assert_eq!(
            label(&map, 7, "104.20.23.154", 2),
            some("example.com", LabelSource::Verified)
        );
    }

    #[test]
    fn later_names_never_push_earlier_ones_out_of_an_address() {
        let mut map = DnsMap::new();
        map.record_confirmed("example.com", &[ip("1.2.3.4")], at(0));
        for i in 0..20 {
            map.record_confirmed(&format!("n{i}.attacker.example"), &[ip("1.2.3.4")], at(1));
        }
        // The first names, including example.com, are kept.
        let (names, _) = map.by_address.get(&ip("1.2.3.4")).unwrap();
        assert_eq!(names.len(), MAX_NAMES_PER_ADDRESS);
        assert!(names.iter().any(|(name, _)| &**name == "example.com"));
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
    fn shared_addresses_verify_each_of_their_names() {
        let mut map = DnsMap::new();
        map.record_confirmed("a.example", &[ip("1.2.3.4")], at(0));
        map.record_confirmed("b.example", &[ip("1.2.3.4")], at(1));
        map.record_app_answer(7, "a.example", &[ip("1.2.3.4")], at(1));
        assert_eq!(
            label(&map, 7, "1.2.3.4", 2),
            some("a.example", LabelSource::Verified)
        );
        // The inferred label is the most recently confirmed name.
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
    fn full_confirmation_maps_evict_the_least_recently_confirmed() {
        let mut map = DnsMap::with_limits(DEFAULT_LIFETIME, 100, 100, 3);
        for i in 0..10u64 {
            map.record_confirmed(
                &format!("n{i}.example"),
                &[ip(&format!("10.0.0.{i}"))],
                at(i),
            );
        }
        assert_eq!(map.confirmed_len(), 3);
        for i in 7..10 {
            assert!(
                label(&map, 1, &format!("10.0.0.{i}"), 10).is_some(),
                "10.0.0.{i}"
            );
        }
        assert_eq!(label(&map, 1, "10.0.0.0", 10), None);
    }

    #[test]
    fn refreshed_confirmations_are_not_evicted_first() {
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
    fn addresses_per_name_are_capped() {
        let mut map = DnsMap::new();
        let many: Vec<IpAddr> = (0..200u32)
            .map(|i| ip(&format!("10.0.{}.{}", i / 250, i % 250)))
            .collect();
        map.record_confirmed("big.example", &many, at(0));
        let (addresses, _) = map.by_name.get(&Arc::from("big.example")).unwrap();
        assert_eq!(addresses.len(), MAX_ADDRESSES_PER_NAME);
    }
}
