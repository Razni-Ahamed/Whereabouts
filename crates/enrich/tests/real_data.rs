//! Checks against the real downloaded databases. Skipped (with a message)
//! when `scripts/update-data.ps1` has not been run.

use std::net::IpAddr;
use std::path::PathBuf;

use whereabouts_enrich::{Enricher, Scope};

fn data_dir() -> PathBuf {
    std::env::var_os("WHEREABOUTS_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../data")))
}

fn load() -> Option<Enricher> {
    let (enricher, report) = Enricher::load(&data_dir());
    if !report.missing.is_empty() {
        eprintln!(
            "skipped: data files missing ({:?}); run scripts/update-data.ps1",
            report.missing
        );
        return None;
    }
    assert!(report.tracker_domains > 30_000, "{report:?}");
    Some(enricher)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn well_known_addresses_get_country_and_owner() {
    let Some(enricher) = load() else { return };

    let google = enricher.ip(ip("8.8.8.8"));
    assert_eq!(google.scope, Scope::Internet);
    assert!(google.country.is_some(), "{google:?}");
    assert!(
        google
            .network
            .as_deref()
            .is_some_and(|n| n.contains("Google")),
        "{google:?}"
    );

    let cloudflare = enricher.ip(ip("2606:4700:4700::1111"));
    assert!(
        cloudflare
            .network
            .as_deref()
            .is_some_and(|n| n.contains("Cloudflare")),
        "{cloudflare:?}"
    );

    let local = enricher.ip(ip("192.168.1.1"));
    assert_eq!(local.scope, Scope::Local);
    assert_eq!(local.network, None);
}

#[test]
fn well_known_trackers_are_recognised() {
    let Some(enricher) = load() else { return };
    assert!(enricher.domain("www.google-analytics.com").tracker);
    assert!(enricher.domain("bat.bing.com").tracker);
    assert!(!enricher.domain("example.com").tracker);
}
