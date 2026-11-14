//! Country and network owner of IP addresses, from DB-IP Lite databases
//! (CC BY 4.0, <https://db-ip.com>), read from local files only.

use std::net::IpAddr;
use std::path::Path;

use maxminddb::Reader;
use maxminddb::geoip2::{Asn, Country};

/// Where an address is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// This computer or the local network (private, link-local, ...).
    Local,
    /// A multicast or broadcast address.
    Multicast,
    /// The internet.
    Internet,
}

/// What is known about an IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpInfo {
    /// Where the address is.
    pub scope: Scope,
    /// Two-letter ISO country code, e.g. "US".
    pub country: Option<String>,
    /// Name of the organisation that runs the network, e.g. "Google LLC".
    pub network: Option<String>,
    /// Autonomous system number of that network.
    pub asn: Option<u32>,
}

/// Longest network owner name kept.
const MAX_NETWORK_NAME: usize = 80;

/// Returns where `ip` is, without any database.
pub fn scope(ip: IpAddr) -> Scope {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let shared = v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64; // 100.64.0.0/10
            if v4.is_multicast() || v4.is_broadcast() {
                Scope::Multicast
            } else if v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || shared
            {
                Scope::Local
            } else {
                Scope::Internet
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_multicast() {
                Scope::Multicast
            } else if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
            {
                Scope::Local
            } else {
                Scope::Internet
            }
        }
    }
}

/// The DB-IP databases, if present.
#[derive(Debug, Default)]
pub struct GeoDatabases {
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

impl GeoDatabases {
    /// Opens `dbip-country-lite.mmdb` and `dbip-asn-lite.mmdb` in
    /// `data_dir`. Missing or unreadable files are skipped; their names are
    /// returned so the caller can say what is missing.
    pub fn open(data_dir: &Path) -> (Self, Vec<String>) {
        let mut missing = Vec::new();
        let mut open = |file: &str| match Reader::open_readfile(data_dir.join(file)) {
            Ok(reader) => Some(reader),
            Err(_) => {
                missing.push(file.to_owned());
                None
            }
        };
        let databases = Self {
            country: open("dbip-country-lite.mmdb"),
            asn: open("dbip-asn-lite.mmdb"),
        };
        (databases, missing)
    }

    /// Looks `ip` up. Local and multicast addresses are not looked up.
    pub fn lookup(&self, ip: IpAddr) -> IpInfo {
        let ip = ip.to_canonical();
        let scope = scope(ip);
        let mut info = IpInfo {
            scope,
            country: None,
            network: None,
            asn: None,
        };
        if scope != Scope::Internet {
            return info;
        }
        if let Some(reader) = &self.country {
            info.country = reader
                .lookup(ip)
                .ok()
                .and_then(|found| found.decode::<Country>().ok().flatten())
                .and_then(|record| record.country.iso_code.map(str::to_owned))
                .filter(|code| code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase()));
        }
        if let Some(reader) = &self.asn {
            if let Some(record) = reader
                .lookup(ip)
                .ok()
                .and_then(|found| found.decode::<Asn>().ok().flatten())
            {
                info.asn = record.autonomous_system_number;
                info.network = record.autonomous_system_organization.map(clean_name);
            }
        }
        info
    }

    /// Returns `true` if neither database is loaded.
    pub fn is_empty(&self) -> bool {
        self.country.is_none() && self.asn.is_none()
    }
}

/// Removes control characters (which could disturb a terminal) and limits
/// the length of a name from a database.
fn clean_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .take(MAX_NETWORK_NAME)
        .collect::<String>()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classifies_local_and_multicast_addresses() {
        for local in [
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:192.168.1.1",
        ] {
            assert_eq!(scope(ip(local)), Scope::Local, "{local}");
        }
        for multicast in ["239.255.255.250", "255.255.255.255", "ff02::1"] {
            assert_eq!(scope(ip(multicast)), Scope::Multicast, "{multicast}");
        }
        for internet in ["8.8.8.8", "100.128.0.1", "2606:4700:10::6814:179a"] {
            assert_eq!(scope(ip(internet)), Scope::Internet, "{internet}");
        }
    }

    #[test]
    fn missing_databases_are_reported_not_fatal() {
        let (databases, missing) = GeoDatabases::open(Path::new(r"C:\no\such\folder"));
        assert!(databases.is_empty());
        assert_eq!(missing.len(), 2);
        let info = databases.lookup(ip("8.8.8.8"));
        assert_eq!(info.scope, Scope::Internet);
        assert_eq!(info.country, None);
    }

    #[test]
    fn names_from_databases_are_cleaned() {
        assert_eq!(clean_name("Evil\u{1b}[2J Corp\n"), "Evil[2J Corp");
        assert_eq!(clean_name(&"x".repeat(200)).len(), MAX_NETWORK_NAME);
    }
}
