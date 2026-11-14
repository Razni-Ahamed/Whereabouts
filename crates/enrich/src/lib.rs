//! Offline enrichment for Whereabouts (design spec §5.5).
//!
//! Turns raw connection metadata into something people can read: the
//! registrable domain (via the Public Suffix List), whether a domain is a
//! known tracker (EasyPrivacy), the company behind tracking and analytics
//! services (Whereabouts' own list), and the country and network owner of
//! an IP address (DB-IP Lite).
//!
//! Every lookup uses data on this computer. This crate makes no network
//! requests (privacy principle P6). The DB-IP and EasyPrivacy files are
//! downloaded at build time by `scripts/update-data.ps1`; if they are
//! missing, the related information is simply left out.

#![forbid(unsafe_code)]

pub mod companies;
pub mod geo;
pub mod trackers;

use std::net::IpAddr;
use std::path::Path;

pub use companies::{Category, Company, CompanyList};
pub use geo::{GeoDatabases, IpInfo, Scope};
pub use trackers::TrackerList;

/// File name of the EasyPrivacy list in the data folder.
pub const EASYPRIVACY_FILE: &str = "easyprivacy.txt";

/// Credits required by the data licences, to show to users.
pub const ATTRIBUTION: &str = "IP geolocation by DB-IP (https://db-ip.com, CC BY 4.0). \
     Tracker list: EasyPrivacy by the EasyList authors (https://easylist.to, GPL-3.0). \
     Domain suffixes: Public Suffix List (https://publicsuffix.org, MPL-2.0).";

/// What is known about a domain name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainInfo {
    /// The registrable domain, e.g. `tiktokcdn.com` for `v16.tiktokcdn.com`.
    pub registrable: Option<String>,
    /// Whether EasyPrivacy lists it as a tracker.
    pub tracker: bool,
    /// The company and kind of service, if Whereabouts' list knows it.
    pub company: Option<Company>,
}

/// All offline lookups together.
#[derive(Debug, Default)]
pub struct Enricher {
    trackers: TrackerList,
    companies: CompanyList,
    geo: GeoDatabases,
}

/// What [`Enricher::load`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadReport {
    /// Number of tracker domains loaded.
    pub tracker_domains: usize,
    /// Number of company domains loaded.
    pub company_domains: usize,
    /// Data files that were missing or unreadable.
    pub missing: Vec<String>,
}

impl Enricher {
    /// Loads the built-in company list and whatever data files exist in
    /// `data_dir`.
    pub fn load(data_dir: &Path) -> (Self, LoadReport) {
        let mut missing = Vec::new();
        let trackers = match std::fs::read_to_string(data_dir.join(EASYPRIVACY_FILE)) {
            Ok(text) => TrackerList::parse(&text),
            Err(_) => {
                missing.push(EASYPRIVACY_FILE.to_owned());
                TrackerList::default()
            }
        };
        let (geo, mut geo_missing) = GeoDatabases::open(data_dir);
        missing.append(&mut geo_missing);
        let enricher = Self {
            trackers,
            companies: CompanyList::built_in(),
            geo,
        };
        let report = LoadReport {
            tracker_domains: enricher.trackers.len(),
            company_domains: enricher.companies.len(),
            missing,
        };
        (enricher, report)
    }

    /// Creates an enricher from parts, for tests.
    pub fn from_parts(trackers: TrackerList, companies: CompanyList, geo: GeoDatabases) -> Self {
        Self {
            trackers,
            companies,
            geo,
        }
    }

    /// Looks up a domain name.
    pub fn domain(&self, name: &str) -> DomainInfo {
        DomainInfo {
            registrable: registrable_domain(name),
            tracker: self.trackers.is_tracker(name),
            company: self.companies.lookup(name).cloned(),
        }
    }

    /// Looks up an IP address.
    pub fn ip(&self, ip: IpAddr) -> IpInfo {
        self.geo.lookup(ip)
    }
}

/// Returns the registrable domain ("eTLD+1") of `name`, using the Public
/// Suffix List: `v16.tiktokcdn.com` gives `tiktokcdn.com`, and
/// `a.b.example.co.uk` gives `example.co.uk`.
pub fn registrable_domain(name: &str) -> Option<String> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&name).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_registrable_domains() {
        assert_eq!(
            registrable_domain("v16.tiktokcdn.com").as_deref(),
            Some("tiktokcdn.com")
        );
        assert_eq!(
            registrable_domain("a.b.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable_domain("Example.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(registrable_domain("com"), None);
    }

    #[test]
    fn combines_tracker_and_company_information() {
        let trackers = TrackerList::parse("||google-analytics.com^\n||unknown-tracker.example^\n");
        let enricher =
            Enricher::from_parts(trackers, CompanyList::built_in(), GeoDatabases::default());

        let ga = enricher.domain("www.google-analytics.com");
        assert!(ga.tracker);
        assert_eq!(ga.registrable.as_deref(), Some("google-analytics.com"));
        assert_eq!(ga.company.map(|c| c.name).as_deref(), Some("Google"));

        let unknown = enricher.domain("x.unknown-tracker.example");
        assert!(unknown.tracker);
        assert_eq!(unknown.company, None);

        let plain = enricher.domain("example.com");
        assert!(!plain.tracker);
        assert_eq!(plain.company, None);
    }

    #[test]
    fn loading_from_an_empty_folder_reports_what_is_missing() {
        let (enricher, report) = Enricher::load(Path::new(r"C:\no\such\folder"));
        assert_eq!(report.tracker_domains, 0);
        assert!(report.company_domains > 50);
        assert_eq!(report.missing.len(), 3);
        assert!(!enricher.domain("doubleclick.net").tracker);
        assert!(enricher.domain("doubleclick.net").company.is_some());
    }
}
