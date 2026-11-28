//! The behaviour signals (design spec v0.3, §5): small pure checks that
//! compare what an app does now with its [`Profile`]. They read no store and
//! no clock; the caller passes in everything they need.
//!
//! The numbers below are the lab's starting values. The lab replays real
//! traffic to tune them before a signal ships (release bar U8).

use std::collections::HashMap;

use whereabouts_core::entropy::shannon_entropy;
use whereabouts_core::stats::{MAD_SCALE, mad, median};
use whereabouts_enrich::Enricher;
use whereabouts_store::{ItemKind, Reason, Severity, Signal};

use crate::profile::Profile;

/// How many robust deviations above the usual an hour's upload must be.
pub const UPLOAD_Z: f64 = 6.0;
/// Least bytes sent in an hour for an upload spike.
pub const UPLOAD_MIN_BYTES: u64 = 10_000_000;
/// Active hours a profile needs before upload and time signals work.
pub const UPLOAD_MIN_HOURS: usize = 24;
/// Least share of bytes received for an app to count as a download app.
pub const RATIO_DOWNLOAD_SHARE: f64 = 0.8;
/// Least bytes sent in an hour for a ratio flip.
pub const RATIO_MIN_SENT: u64 = 10_000_000;
/// Connections needed before beaconing is considered.
pub const BEACON_MIN: usize = 6;
/// Largest spread of gaps between connections (standard deviation over
/// mean) that still counts as regular.
pub const BEACON_MAX_CV: f64 = 0.1;
/// Shortest gap between beacon connections, in seconds.
pub const BEACON_MIN_GAP: u64 = 10;
/// Longest gap between beacon connections, in seconds.
pub const BEACON_MAX_GAP: u64 = 3600;
/// Most bytes per connection, on average, for a beacon.
pub const BEACON_MAX_BYTES: u64 = 64 * 1024;
/// An hour of the day used in less than this share of active hours is unusual.
pub const UNUSUAL_HOUR_SHARE: f64 = 0.01;
/// Least entropy, in bits per character, of a random-looking name.
pub const RANDOM_NAME_ENTROPY: f64 = 3.5;
/// Fewest characters in a random-looking name.
const RANDOM_NAME_MIN_LEN: usize = 8;

/// Every signal.
const ALL: [Signal; 11] = [
    Signal::NewSite,
    Signal::NewCompany,
    Signal::NewCountry,
    Signal::UploadSpike,
    Signal::RatioFlip,
    Signal::Beaconing,
    Signal::UnusualTime,
    Signal::RandomName,
    Signal::BinaryChanged,
    Signal::Impostor,
    Signal::ImpostorUnchecked,
];

/// Which signals are switched on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toggles {
    /// On or off per signal; a signal not listed is off.
    pub on: HashMap<Signal, bool>,
}

impl Default for Toggles {
    /// Every signal on except beaconing, which ships off until the lab has
    /// connection times (spec §8).
    fn default() -> Self {
        Self {
            on: ALL.iter().map(|&s| (s, s != Signal::Beaconing)).collect(),
        }
    }
}

impl Toggles {
    /// Every signal on, for the lab.
    pub fn all_on() -> Self {
        Self {
            on: ALL.iter().map(|&s| (s, true)).collect(),
        }
    }

    /// Whether `signal` is switched on.
    pub fn is_on(&self, signal: Signal) -> bool {
        self.on.get(&signal).copied().unwrap_or(false)
    }
}

/// The starting severity of a signal ([`Signal::severity`], kept by the
/// store so it can keep an alert's most severe reasons). New sites,
/// companies and countries are only listed (Info): global CDNs made them far
/// too common to notify on (lab-tuned).
pub fn severity_of(signal: Signal) -> Severity {
    signal.severity()
}

fn reason(signal: Signal) -> Reason {
    Reason {
        signal,
        value: None,
        observed: None,
        usual: None,
        count: None,
    }
}

/// New site, company and country signals (in that order) for each value the
/// profile does not know. Nothing for an app that goes anywhere. Pending
/// values still count as new.
pub fn new_destinations(
    profile: &Profile,
    domain: Option<&str>,
    company: Option<&str>,
    country: Option<&str>,
    goes_anywhere: bool,
) -> Vec<Reason> {
    if goes_anywhere {
        return Vec::new();
    }
    [
        (Signal::NewSite, ItemKind::Domain, domain),
        (Signal::NewCompany, ItemKind::Company, company),
        (Signal::NewCountry, ItemKind::Country, country),
    ]
    .into_iter()
    .filter_map(|(signal, kind, value)| {
        let value = value.filter(|v| !v.is_empty())?;
        (!profile.knows(kind, value)).then(|| Reason {
            value: Some(value.to_owned()),
            ..reason(signal)
        })
    })
    .collect()
}

/// Far more data sent this hour than the app's usual hours. A flat history
/// (spread 0) is judged with a spread of 1 byte, so any big jump counts.
pub fn upload_spike(profile: &Profile, hour_sent: u64) -> Option<Reason> {
    let history = profile.hourly_sent();
    if history.len() < UPLOAD_MIN_HOURS || hour_sent <= UPLOAD_MIN_BYTES {
        return None;
    }
    let usual = median(&history)?;
    let spread = MAD_SCALE * mad(&history)?.max(1.0);
    let observed = hour_sent as f64;
    ((observed - usual) / spread > UPLOAD_Z).then(|| Reason {
        observed: Some(observed),
        usual: Some(usual),
        ..reason(Signal::UploadSpike)
    })
}

/// An app that mostly downloads is now mostly uploading.
pub fn ratio_flip(profile: &Profile, hour_sent: u64, hour_received: u64) -> Option<Reason> {
    let share = profile.download_share()?;
    (share >= RATIO_DOWNLOAD_SHARE && hour_sent > RATIO_MIN_SENT && hour_sent > hour_received).then(
        || Reason {
            observed: Some(hour_sent as f64),
            usual: Some(share),
            ..reason(Signal::RatioFlip)
        },
    )
}

/// Traffic in a local hour the app is almost never active in. The reason's
/// value is the hour as two digits. `local_hour` must be derived from the
/// same `local_offset_secs`.
pub fn unusual_time(profile: &Profile, local_hour: u8, local_offset_secs: i32) -> Option<Reason> {
    if profile.hourly_sent().len() < UPLOAD_MIN_HOURS {
        return None;
    }
    let share = *profile
        .hour_of_day_share(local_offset_secs)
        .get(usize::from(local_hour))?;
    (share < UNUSUAL_HOUR_SHARE).then(|| Reason {
        value: Some(format!("{local_hour:02}")),
        observed: Some(share),
        ..reason(Signal::UnusualTime)
    })
}

/// A domain with a label that looks machine-generated. Each label left of
/// the public suffix is judged on its own (dots do not count), and any one
/// label of enough length and entropy is enough. If no label is left of the
/// suffix, the first label is judged. Known trackers and companies are
/// skipped. The reason's value is the whole domain.
pub fn random_name(domain: &str, enricher: &Enricher) -> Option<Reason> {
    let name = domain.trim_end_matches('.').to_ascii_lowercase();
    let info = enricher.domain(&name);
    if info.tracker || info.company.is_some() {
        return None;
    }
    let suffix = info
        .registrable
        .as_deref()
        .and_then(|registrable| registrable.split_once('.'))
        .map(|(_, suffix)| suffix);
    let rest = suffix
        .and_then(|suffix| name.strip_suffix(suffix))
        .map_or("", |rest| rest.trim_end_matches('.'));
    let rest = if rest.is_empty() {
        name.split('.').next().unwrap_or("")
    } else {
        rest
    };
    let entropy = rest
        .split('.')
        .filter(|label| label.chars().count() >= RANDOM_NAME_MIN_LEN)
        .map(shannon_entropy)
        .filter(|&entropy| entropy >= RANDOM_NAME_ENTROPY)
        .fold(None, |best: Option<f64>, e| {
            Some(best.map_or(e, |b| b.max(e)))
        })?;
    Some(Reason {
        value: Some(name),
        observed: Some(entropy),
        ..reason(Signal::RandomName)
    })
}

/// The program file changed, it lost a signature it had (the profile stored
/// a publisher, it is now unsigned or invalid) or is signed by another
/// publisher, and it contacts something new. An app that was never signed
/// does not fire on being unsigned. Never fires when the profile has no file
/// hash to compare with yet.
pub fn binary_changed(
    profile: &Profile,
    sha256: Option<&str>,
    publisher: Option<&str>,
    signature_valid: bool,
    new_destination: bool,
) -> Option<Reason> {
    let row = &profile.stored().row;
    let (last, now) = (row.last_sha256.as_deref()?, sha256?);
    if !new_destination || last.eq_ignore_ascii_case(now) {
        return None;
    }
    let publisher_differs = publisher != row.last_publisher.as_deref();
    let lost_signature = !signature_valid && row.last_publisher.is_some();
    (lost_signature || publisher_differs).then(|| reason(Signal::BinaryChanged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};
    use whereabouts_enrich::{CompanyList, GeoDatabases, TrackerList};
    use whereabouts_store::{
        GoesAnywhere, HourRow, ItemState, ProfileItem, ProfileRow, StoredProfile,
    };

    const MB: u64 = 1_000_000;

    fn profile_with(items: Vec<ProfileItem>, hours: Vec<HourRow>) -> Profile {
        let t = UNIX_EPOCH + Duration::from_secs(1_000_000);
        Profile::new(StoredProfile {
            row: ProfileRow {
                key: "k".into(),
                path: r"C:\x\a.exe".into(),
                app_name: "a.exe".into(),
                first_data: t,
                learned_since: t,
                last_data: t,
                active_days: 1,
                last_active_day: None,
                last_sha256: Some("aaaa".into()),
                last_publisher: Some("Good Inc".into()),
                goes_anywhere: GoesAnywhere::Auto,
                reset_at: None,
            },
            items,
            hours,
        })
    }

    fn item(kind: ItemKind, value: &str, state: ItemState) -> ProfileItem {
        ProfileItem {
            kind,
            value: value.into(),
            first_seen: UNIX_EPOCH,
            last_seen: UNIX_EPOCH,
            seen_on_day: 1,
            state,
        }
    }

    /// `n` active hours of `sent` and `received` bytes, cycling through the
    /// given hours of the day (in UTC) on successive days.
    fn hours(n: usize, sent: u64, received: u64, of_day: &[i64]) -> Vec<HourRow> {
        (0..n)
            .map(|i| HourRow {
                hour: (i / of_day.len()) as i64 * 24 + of_day[i % of_day.len()],
                bytes_sent: sent,
                bytes_received: received,
                connections: 1,
            })
            .collect()
    }

    fn daytime() -> Vec<i64> {
        (8..20).collect()
    }

    fn enricher() -> Enricher {
        Enricher::from_parts(
            TrackerList::parse("||tracker-abcdefgh7.net^\n"),
            CompanyList::default(),
            GeoDatabases::default(),
        )
    }

    #[test]
    fn new_destinations_are_info_only() {
        assert_eq!(severity_of(Signal::NewCountry), Severity::Info);
        assert_eq!(severity_of(Signal::NewSite), Severity::Info);
        assert_eq!(severity_of(Signal::NewCompany), Severity::Info);
        assert_eq!(severity_of(Signal::UploadSpike), Severity::High);
        assert_eq!(severity_of(Signal::RatioFlip), Severity::Medium);
        assert_eq!(severity_of(Signal::Beaconing), Severity::Medium);
        assert_eq!(severity_of(Signal::UnusualTime), Severity::Info);
        assert_eq!(severity_of(Signal::RandomName), Severity::Medium);
        assert_eq!(severity_of(Signal::BinaryChanged), Severity::High);
    }

    #[test]
    fn impostor_is_high_and_on_by_default() {
        assert_eq!(Signal::Impostor.as_str(), "impostor");
        assert_eq!(severity_of(Signal::Impostor), Severity::High);
        assert!(Toggles::default().is_on(Signal::Impostor));
        assert!(Toggles::all_on().is_on(Signal::Impostor));
        assert_eq!(Signal::ImpostorUnchecked.as_str(), "impostor_unchecked");
        assert_eq!(severity_of(Signal::ImpostorUnchecked), Severity::Medium);
        assert!(Toggles::default().is_on(Signal::ImpostorUnchecked));
    }

    #[test]
    fn known_and_allowed_destinations_raise_nothing() {
        let p = profile_with(
            vec![
                item(ItemKind::Domain, "a.com", ItemState::Learned),
                item(ItemKind::Company, "Acme", ItemState::Allowed),
                item(ItemKind::Country, "DE", ItemState::Learned),
            ],
            vec![],
        );
        let r = new_destinations(&p, Some("a.com"), Some("Acme"), Some("DE"), false);
        assert!(r.is_empty());
        // Empty and missing values produce nothing either.
        assert!(new_destinations(&p, Some(""), None, Some(""), false).is_empty());
    }

    #[test]
    fn unknown_destinations_come_in_site_company_country_order() {
        let p = profile_with(vec![], vec![]);
        let r = new_destinations(&p, Some("b.com"), Some("Beta"), Some("FR"), false);
        let signals: Vec<_> = r.iter().map(|r| r.signal).collect();
        assert_eq!(
            signals,
            [Signal::NewSite, Signal::NewCompany, Signal::NewCountry]
        );
        assert_eq!(r[0].value.as_deref(), Some("b.com"));
        assert_eq!(r[2].value.as_deref(), Some("FR"));
    }

    #[test]
    fn pending_destination_still_counts_as_new() {
        let p = profile_with(
            vec![item(ItemKind::Country, "RU", ItemState::Pending)],
            vec![],
        );
        let r = new_destinations(&p, None, None, Some("RU"), false);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].signal, Signal::NewCountry);
    }

    #[test]
    fn goes_anywhere_skips_destination_signals() {
        let p = profile_with(vec![], vec![]);
        assert!(new_destinations(&p, Some("b.com"), Some("Beta"), Some("FR"), true).is_empty());
    }

    #[test]
    fn upload_spike_needs_history_and_ten_megabytes() {
        let short = profile_with(vec![], hours(23, MB, 0, &daytime()));
        assert!(upload_spike(&short, 300 * MB).is_none());
        let long = profile_with(vec![], hours(24, MB, 0, &daytime()));
        let r = upload_spike(&long, 300 * MB).unwrap();
        assert_eq!(r.signal, Signal::UploadSpike);
        assert_eq!(r.observed, Some(3e8));
        assert_eq!(r.usual, Some(1e6));
        assert!(upload_spike(&long, 9 * MB).is_none());
    }

    #[test]
    fn upload_spike_with_flat_history_uses_mad_floor() {
        // MAD is 0 here; a floor of 1 byte makes 20 MB over 1 MB count.
        let p = profile_with(vec![], hours(30, MB, 0, &daytime()));
        assert!(upload_spike(&p, 20 * MB).is_some());
    }

    #[test]
    fn upload_spike_ignores_ordinary_variation() {
        let mut h = hours(30, 20 * MB, 0, &daytime());
        for (i, row) in h.iter_mut().enumerate() {
            row.bytes_sent += (i as u64 % 5) * 10 * MB;
        }
        let p = profile_with(vec![], h);
        assert!(upload_spike(&p, 40 * MB).is_none());
    }

    #[test]
    fn ratio_flip_only_for_download_apps() {
        let download = profile_with(vec![], hours(24, 5 * MB, 95 * MB, &daytime()));
        let r = ratio_flip(&download, 20 * MB, 5 * MB).unwrap();
        assert_eq!(r.signal, Signal::RatioFlip);
        assert_eq!(r.observed, Some(2e7));
        assert_eq!(r.usual, Some(0.95));
        // Not more sent than received, or too little sent: nothing.
        assert!(ratio_flip(&download, 20 * MB, 30 * MB).is_none());
        assert!(ratio_flip(&download, 5 * MB, MB).is_none());
        let balanced = profile_with(vec![], hours(24, 50 * MB, 50 * MB, &daytime()));
        assert!(ratio_flip(&balanced, 20 * MB, 5 * MB).is_none());
        let empty = profile_with(vec![], vec![]);
        assert!(ratio_flip(&empty, 20 * MB, 5 * MB).is_none());
    }

    #[test]
    fn unusual_time_below_one_percent() {
        // 120 active hours spread over 12 daytime hours; 03:00 is never used.
        let p = profile_with(vec![], hours(120, MB, 0, &daytime()));
        let r = unusual_time(&p, 3, 0).unwrap();
        assert_eq!(r.signal, Signal::UnusualTime);
        assert_eq!(r.value.as_deref(), Some("03"));
        assert!(unusual_time(&p, 10, 0).is_none());
        // The local offset moves which hour is which.
        assert!(unusual_time(&p, 8, 0).is_none());
        assert!(unusual_time(&p, 8, 7_200).is_some());
        // Too little history, or a nonsense hour: nothing.
        let short = profile_with(vec![], hours(23, MB, 0, &daytime()));
        assert!(unusual_time(&short, 3, 0).is_none());
        assert!(unusual_time(&p, 24, 0).is_none());
    }

    #[test]
    fn random_name_flags_noise_not_words() {
        let e = enricher();
        let r = random_name("x7kq9zp2vtmw4.example.net", &e).unwrap();
        assert_eq!(r.signal, Signal::RandomName);
        assert_eq!(r.value.as_deref(), Some("x7kq9zp2vtmw4.example.net"));
        assert!(random_name("wikipedia.org", &e).is_none());
        assert!(random_name("cdn-akamai.net", &e).is_none());
        // Short names are never flagged; known trackers are skipped.
        assert!(random_name("x7kq9z.com", &e).is_none());
        // Ordinary multi-label names are not noise.
        for name in [
            "static.cdn.someshop.com",
            "update.fabrikam.com",
            "d1a2b3c4.cloudfront.net",
        ] {
            assert!(random_name(name, &e).is_none(), "{name}");
        }
        // One random label is enough, wherever it sits.
        assert!(random_name("x7kq9zp2vtmw4.static.cdn.someshop.com", &e).is_some());
        // A name with no label left of the suffix uses its first label.
        assert!(random_name("co.uk", &e).is_none());
        assert!(random_name("tracker-abcdefgh7.net", &e).is_none());
    }

    #[test]
    fn random_name_skips_known_companies() {
        let e = Enricher::from_parts(
            TrackerList::parse(""),
            CompanyList::parse(
                "known.example	Known Co	ads
",
            )
            .unwrap(),
            GeoDatabases::default(),
        );
        assert!(random_name("x7kq9zp2vtmw4.known.example", &e).is_none());
        assert!(random_name("x7kq9zp2vtmw4.other.example", &e).is_some());
    }

    #[test]
    fn binary_changed_needs_new_destination_and_lost_signature() {
        let p = profile_with(vec![], vec![]);
        // Same file: nothing.
        assert!(binary_changed(&p, Some("aaaa"), None, false, true).is_none());
        // Changed, still signed by the same publisher: nothing.
        assert!(binary_changed(&p, Some("bbbb"), Some("Good Inc"), true, true).is_none());
        // Changed, unsigned, but nothing new contacted: nothing.
        assert!(binary_changed(&p, Some("bbbb"), None, false, false).is_none());
        // Changed and unsigned, or another publisher, with a new destination.
        let r = binary_changed(&p, Some("bbbb"), None, false, true).unwrap();
        assert_eq!(r.signal, Signal::BinaryChanged);
        assert!(binary_changed(&p, Some("bbbb"), Some("Evil Ltd"), true, true).is_some());
        // An app that was never signed is not "losing" a signature.
        let mut unsigned = profile_with(vec![], vec![]);
        unsigned.row_mut().last_publisher = None;
        assert!(binary_changed(&unsigned, Some("bbbb"), None, false, true).is_none());
        // Unknown hash now, or none stored yet: nothing to compare.
        assert!(binary_changed(&p, None, None, false, true).is_none());
        let mut fresh = profile_with(vec![], vec![]);
        fresh.row_mut().last_sha256 = None;
        assert!(binary_changed(&fresh, Some("bbbb"), None, false, true).is_none());
    }

    #[test]
    fn beaconing_is_off_by_default() {
        let t = Toggles::default();
        assert!(!t.is_on(Signal::Beaconing));
        for s in ALL.into_iter().filter(|&s| s != Signal::Beaconing) {
            assert!(t.is_on(s), "{s:?} should be on");
        }
        assert!(Toggles::all_on().is_on(Signal::Beaconing));
    }
}
