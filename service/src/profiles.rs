//! How the service shows behaviour profiles to clients. The profiles
//! themselves are learned in `whereabouts-detect` (see `crate::learning`).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use whereabouts_detect::browsers::auto_goes_anywhere;
use whereabouts_detect::{LEARNING, Profile};
use whereabouts_ipc::{
    GoesAnywhereChoice, MAX_MESSAGE, MAX_ROWS, MAX_RULE_PATH, ProfileItemView, ProfileView,
};
use whereabouts_store::{
    GoesAnywhere, ItemKind, ProfileItem, REASON_VALUE_MAX_CHARS, Store, StoreError, known_app_key,
};

/// Room left in a message for the JSON around a profile.
const MESSAGE_MARGIN: usize = 4 * 1024;

/// The user's choice as the store keeps it.
pub fn choice_to_store(choice: GoesAnywhereChoice) -> GoesAnywhere {
    match choice {
        GoesAnywhereChoice::Auto => GoesAnywhere::Auto,
        GoesAnywhereChoice::On => GoesAnywhere::UserOn,
        GoesAnywhereChoice::Off => GoesAnywhere::UserOff,
    }
}

/// The user's choice as clients see it.
fn choice_view(value: GoesAnywhere) -> GoesAnywhereChoice {
    match value {
        GoesAnywhere::Auto => GoesAnywhereChoice::Auto,
        GoesAnywhere::UserOn => GoesAnywhereChoice::On,
        GoesAnywhere::UserOff => GoesAnywhereChoice::Off,
    }
}

/// The behaviour profile of the program at `path` as clients see it, or
/// `None` if it has none. `local_offset_secs` is the local time zone's
/// offset from UTC, for the hours of the day.
///
/// Whether it goes anywhere depends on its signature, which the store does
/// not keep: a publisher saved with the profile counts as a valid
/// signature from that publisher (the Learner saves one only for a valid
/// signature). Whether the file is installed by administrators is checked
/// now; an error counts as no.
pub fn view(
    store: &Store,
    path: &str,
    now: SystemTime,
    local_offset_secs: i32,
) -> Result<Option<ProfileView>, StoreError> {
    let Some(stored) = store.profile(&known_app_key(path))? else {
        return Ok(None);
    };
    let profile = Profile::new(stored);
    let row = &profile.stored().row;
    let publisher = row.last_publisher.as_deref();
    let installed =
        whereabouts_win_secrets::installed_by_administrators(Path::new(&row.path)).unwrap_or(false);
    let recognised_browser =
        auto_goes_anywhere(&row.app_name, publisher, publisher.is_some(), installed);

    let mut sent: Vec<f64> = profile.hourly_sent();
    sent.sort_by(f64::total_cmp);
    let mut view = ProfileView {
        path: capped(&row.path, MAX_RULE_PATH),
        app: capped(&row.app_name, MAX_RULE_PATH),
        learning: profile.is_learning(now),
        learning_ends_secs: unix_secs(
            row.first_data
                .checked_add(LEARNING)
                .unwrap_or(row.first_data),
        ),
        learned_since_secs: unix_secs(row.learned_since),
        goes_anywhere: profile.goes_anywhere(publisher, publisher.is_some(), installed),
        goes_anywhere_choice: choice_view(row.goes_anywhere),
        recognised_browser,
        sites: items(&profile.stored().items, ItemKind::Domain),
        companies: items(&profile.stored().items, ItemKind::Company),
        countries: items(&profile.stored().items, ItemKind::Country),
        usual_sent_per_hour: median(&sent).map(bytes),
        busiest_sent_per_hour: sent.last().copied().map(bytes),
        active_hours: profile
            .hour_of_day_share(local_offset_secs)
            .map(|share| share as f32),
    };
    fit(&mut view);
    Ok(Some(view))
}

/// One kind of the profile's destinations, newest first, at most
/// [`MAX_ROWS`].
fn items(items: &[ProfileItem], kind: ItemKind) -> Vec<ProfileItemView> {
    let mut of_kind: Vec<&ProfileItem> = items.iter().filter(|item| item.kind == kind).collect();
    of_kind.sort_by(|a, b| {
        b.last_seen
            .cmp(&a.last_seen)
            .then_with(|| a.value.cmp(&b.value))
    });
    of_kind
        .into_iter()
        .take(usize::try_from(MAX_ROWS).unwrap_or(usize::MAX))
        .map(|item| ProfileItemView {
            value: capped(&item.value, REASON_VALUE_MAX_CHARS),
            last_seen_secs: unix_secs(item.last_seen),
            state: String::from(item.state.as_str()),
        })
        .collect()
}

/// Shortens the lists (keeping the newest) until the profile fits in a
/// message. Real profiles are far smaller; this only guards against odd
/// values filling every row.
fn fit(view: &mut ProfileView) {
    let too_big = |view: &ProfileView| {
        serde_json::to_vec(view).map_or(true, |json| json.len() > MAX_MESSAGE - MESSAGE_MARGIN)
    };
    while too_big(view)
        && !(view.sites.is_empty() && view.companies.is_empty() && view.countries.is_empty())
    {
        for list in [&mut view.sites, &mut view.companies, &mut view.countries] {
            list.truncate(list.len() / 2);
        }
    }
}

/// The middle of sorted values (the mean of the two middle ones for an even
/// count), or `None` if there are none.
fn median(sorted: &[f64]) -> Option<f64> {
    let middle = sorted.len() / 2;
    match sorted.len() {
        0 => None,
        n if n % 2 == 1 => Some(sorted[middle]),
        _ => Some((sorted[middle - 1] + sorted[middle]) / 2.0),
    }
}

/// Whole bytes (the hours hold whole numbers).
fn bytes(value: f64) -> u64 {
    value.round() as u64
}

/// `text` cut to `max` characters.
fn capped(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_of_odd_and_even_counts() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[5.0]), Some(5.0));
        assert_eq!(median(&[1.0, 2.0, 10.0]), Some(2.0));
        assert_eq!(median(&[1.0, 2.0, 4.0, 10.0]), Some(3.0));
    }

    #[test]
    fn choices_map_both_ways() {
        for choice in [
            GoesAnywhereChoice::Auto,
            GoesAnywhereChoice::On,
            GoesAnywhereChoice::Off,
        ] {
            assert_eq!(choice_view(choice_to_store(choice)), choice);
        }
    }

    #[test]
    fn huge_profiles_are_cut_to_fit_a_message() {
        let item = |i: usize| ProfileItemView {
            value: format!("{i}{}", "\u{1}".repeat(REASON_VALUE_MAX_CHARS)),
            last_seen_secs: 0,
            state: String::from("learned"),
        };
        let rows = usize::try_from(MAX_ROWS).unwrap();
        let list: Vec<ProfileItemView> = (0..rows).map(item).collect();
        let mut view = ProfileView {
            path: String::from(r"C:\x.exe"),
            app: String::from("x.exe"),
            learning: false,
            learning_ends_secs: 0,
            learned_since_secs: 0,
            goes_anywhere: false,
            goes_anywhere_choice: GoesAnywhereChoice::Auto,
            recognised_browser: false,
            sites: list.clone(),
            companies: list.clone(),
            countries: list,
            usual_sent_per_hour: None,
            busiest_sent_per_hour: None,
            active_hours: [0.0; 24],
        };
        fit(&mut view);
        assert!(serde_json::to_vec(&view).unwrap().len() <= MAX_MESSAGE);
        assert!(!view.sites.is_empty());
        assert_eq!(view.sites[0].value, item(0).value, "the newest are kept");
    }
}
