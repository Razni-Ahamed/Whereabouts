//! Spamhaus DROP ("Don't Route Or Peer"): IP ranges that Spamhaus says are
//! run by criminals or hijacked (malware hosting, botnet control, spam).
//!
//! Spamhaus does not allow the list to be redistributed, so Whereabouts
//! never bundles it: each computer downloads it from Spamhaus itself (v0.2,
//! N6) into Whereabouts' data folder, and this module reads that copy.
//! Files: `drop_v4.json` and `drop_v6.json`, one JSON object per line, e.g.
//! `{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}`, ending with a
//! metadata line.

use std::io;
use std::net::IpAddr;
use std::path::Path;

/// Credit Spamhaus asks for when DROP is used in a product.
pub const DROP_ATTRIBUTION: &str =
    "Network block list: Spamhaus DROP (https://www.spamhaus.org/drop/), The Spamhaus Project.";

/// Largest DROP file read; the real ones are well under 1 MB.
const MAX_FILE: u64 = 16 * 1024 * 1024;

/// One DROP listing that an address falls in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropEntry {
    /// The listed range, e.g. `1.10.16.0/20`.
    pub cidr: String,
    /// Spamhaus' reference for it, e.g. `SBL256894`.
    pub sblid: String,
}

/// The DROP ranges, sorted for lookups.
#[derive(Debug, Default, Clone)]
pub struct DropList {
    v4: Vec<(u32, u32, DropEntry)>,
    v6: Vec<(u128, u128, DropEntry)>,
}

impl DropList {
    /// Reads `drop_v4.json` and `drop_v6.json` from `dir`. `None` if
    /// neither exists (the list was never downloaded).
    pub fn load(dir: &Path) -> io::Result<Option<Self>> {
        let read = |name: &str| -> io::Result<Option<String>> {
            let path = dir.join(name);
            match std::fs::metadata(&path) {
                Ok(meta) if meta.len() > MAX_FILE => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is too large", path.display()),
                )),
                Ok(_) => std::fs::read_to_string(&path).map(Some),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        };
        let (v4, v6) = (read("drop_v4.json")?, read("drop_v6.json")?);
        if v4.is_none() && v6.is_none() {
            return Ok(None);
        }
        Ok(Some(Self::parse(
            v4.as_deref().unwrap_or(""),
            v6.as_deref().unwrap_or(""),
        )))
    }

    /// Parses the two files' contents. Lines that are not valid ranges
    /// (such as the metadata line) are skipped.
    pub fn parse(v4: &str, v6: &str) -> Self {
        let mut list = Self::default();
        for line in v4.lines().chain(v6.lines()) {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let (Some(cidr), sblid) = (
                value.get("cidr").and_then(|v| v.as_str()),
                value.get("sblid").and_then(|v| v.as_str()).unwrap_or(""),
            ) else {
                continue;
            };
            let entry = |cidr: &str| DropEntry {
                cidr: cidr.to_owned(),
                sblid: sblid.chars().take(32).collect(),
            };
            match parse_cidr(cidr) {
                Some(Range::V4(start, end)) => list.v4.push((start, end, entry(cidr))),
                Some(Range::V6(start, end)) => list.v6.push((start, end, entry(cidr))),
                None => {}
            }
        }
        list.v4.sort_by_key(|(start, ..)| *start);
        list.v6.sort_by_key(|(start, ..)| *start);
        list
    }

    /// The listing `ip` falls in, if any.
    pub fn lookup(&self, ip: IpAddr) -> Option<&DropEntry> {
        match ip.to_canonical() {
            IpAddr::V4(ip) => find(&self.v4, u32::from(ip)),
            IpAddr::V6(ip) => find(&self.v6, u128::from(ip)),
        }
    }

    /// Number of ranges.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Whether there are no ranges.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The range containing `value` among ranges sorted by start. Ranges may
/// overlap, so earlier ones are checked too while they could still reach.
fn find<T: Ord + Copy>(ranges: &[(T, T, DropEntry)], value: T) -> Option<&DropEntry> {
    let after = ranges.partition_point(|(start, ..)| *start <= value);
    ranges[..after]
        .iter()
        .rev()
        .take(64)
        .find(|(_, end, _)| *end >= value)
        .map(|(_, _, entry)| entry)
}

enum Range {
    V4(u32, u32),
    V6(u128, u128),
}

fn parse_cidr(cidr: &str) -> Option<Range> {
    let (address, prefix) = cidr.split_once('/')?;
    let prefix: u32 = prefix.parse().ok()?;
    match address.parse::<IpAddr>().ok()? {
        IpAddr::V4(ip) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let start = u32::from(ip) & mask;
            Some(Range::V4(start, start | !mask))
        }
        IpAddr::V6(ip) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let start = u128::from(ip) & mask;
            Some(Range::V6(start, start | !mask))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: &str = r#"{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"203.0.113.0/24","sblid":"SBL1","rir":"test"}
{"cidr":"not a range","sblid":"SBL2"}
{"type":"metadata","timestamp":1800000000,"size":3,"records":2,"copyright":"(c) Spamhaus"}"#;
    const V6: &str = r#"{"cidr":"2001:db8:100::/40","sblid":"SBL3","rir":"test"}"#;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn addresses_in_listed_ranges_are_found() {
        let list = DropList::parse(V4, V6);
        assert_eq!(list.len(), 3);
        assert_eq!(list.lookup(ip("1.10.16.0")).unwrap().sblid, "SBL256894");
        assert_eq!(list.lookup(ip("1.10.31.255")).unwrap().cidr, "1.10.16.0/20");
        assert!(list.lookup(ip("1.10.32.0")).is_none());
        assert!(list.lookup(ip("1.10.15.255")).is_none());
        assert_eq!(list.lookup(ip("203.0.113.77")).unwrap().sblid, "SBL1");
        assert_eq!(
            list.lookup(ip("::ffff:203.0.113.77")).unwrap().sblid,
            "SBL1"
        );
        assert_eq!(list.lookup(ip("2001:db8:1ff::1")).unwrap().sblid, "SBL3");
        assert!(list.lookup(ip("2001:db8:200::1")).is_none());
        assert!(list.lookup(ip("8.8.8.8")).is_none());
    }

    #[test]
    fn overlapping_ranges_are_still_found() {
        let v4 = r#"{"cidr":"10.0.0.0/8","sblid":"WIDE"}
{"cidr":"10.1.0.0/16","sblid":"NARROW"}"#;
        let list = DropList::parse(v4, "");
        assert_eq!(list.lookup(ip("10.200.0.1")).unwrap().sblid, "WIDE");
        assert!(list.lookup(ip("10.1.2.3")).is_some());
    }

    #[test]
    fn a_missing_list_is_none() {
        let dir = std::env::temp_dir().join(format!("wa-drop-none-{}", std::process::id()));
        assert!(DropList::load(&dir).unwrap().is_none());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("drop_v4.json"), V4).unwrap();
        assert_eq!(DropList::load(&dir).unwrap().unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
