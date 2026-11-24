//! A read-only view of one app's stored behaviour profile (design spec
//! v0.3): whether it is still learning, what it is known to talk to, and
//! the traffic shape the detectors compare against.

use std::time::{Duration, SystemTime};

use whereabouts_store::{GoesAnywhere, HourRow, ItemKind, ItemState, StoredProfile};

use crate::browsers;

/// How long a profile learns, from its first data, before alerts based on it
/// are raised.
pub const LEARNING: Duration = Duration::from_secs(7 * 86_400);

const SECS_PER_HOUR: i64 = 3_600;
const SECS_PER_DAY: i64 = 86_400;

/// One app's profile as stored, with the questions the detectors ask of it.
#[derive(Debug, Clone)]
pub struct Profile {
    /// The profile as read from the store.
    pub stored: StoredProfile,
}

impl Profile {
    /// Returns `true` until [`LEARNING`] has passed since the first data.
    pub fn is_learning(&self, now: SystemTime) -> bool {
        now < self.stored.row.first_data + LEARNING
    }

    /// Returns `true` if the app is known to use this item (learned, or
    /// allowed by the user). Pending and absent items are not known.
    pub fn knows(&self, kind: ItemKind, value: &str) -> bool {
        matches!(
            self.state_of(kind, value),
            Some(ItemState::Learned | ItemState::Allowed)
        )
    }

    /// Returns `true` if the item is waiting on a warning.
    pub fn pending(&self, kind: ItemKind, value: &str) -> bool {
        self.state_of(kind, value) == Some(ItemState::Pending)
    }

    /// Bytes sent in each active hour.
    pub fn hourly_sent(&self) -> Vec<f64> {
        self.active_hours().map(|h| h.bytes_sent as f64).collect()
    }

    /// Bytes received in each active hour.
    pub fn hourly_received(&self) -> Vec<f64> {
        self.active_hours()
            .map(|h| h.bytes_received as f64)
            .collect()
    }

    /// The share of active hours that fall in each local hour of the day
    /// (`local_offset_secs` is the local time's offset from UTC). All zeros
    /// if there are no active hours.
    pub fn hour_of_day_share(&self, local_offset_secs: i32) -> [f64; 24] {
        let mut counts = [0u32; 24];
        let mut total = 0u32;
        for h in self.active_hours() {
            let secs = h
                .hour
                .saturating_mul(SECS_PER_HOUR)
                .saturating_add(i64::from(local_offset_secs));
            let hour_of_day = (secs.rem_euclid(SECS_PER_DAY) / SECS_PER_HOUR) as usize;
            counts[hour_of_day] += 1;
            total += 1;
        }
        let mut share = [0.0; 24];
        if total > 0 {
            for (s, c) in share.iter_mut().zip(counts) {
                *s = f64::from(c) / f64::from(total);
            }
        }
        share
    }

    /// Received bytes as a share of all bytes over the profile, or `None`
    /// if no bytes were seen.
    pub fn download_share(&self) -> Option<f64> {
        let (sent, received) = self.stored.hours.iter().fold((0u128, 0u128), |(s, r), h| {
            (
                s + u128::from(h.bytes_sent),
                r + u128::from(h.bytes_received),
            )
        });
        let total = sent + received;
        (total > 0).then(|| received as f64 / total as f64)
    }

    /// Whether this app may contact any site without it being unusual: the
    /// user's choice if they made one, otherwise automatic recognition of a
    /// genuine, administrator-installed browser from its signature.
    pub fn goes_anywhere(
        &self,
        signature_publisher: Option<&str>,
        signature_valid: bool,
        installed_by_admins: bool,
    ) -> bool {
        match self.stored.row.goes_anywhere {
            GoesAnywhere::UserOn => true,
            GoesAnywhere::UserOff => false,
            GoesAnywhere::Auto => browsers::auto_goes_anywhere(
                &self.stored.row.app_name,
                signature_publisher,
                signature_valid,
                installed_by_admins,
            ),
        }
    }

    fn state_of(&self, kind: ItemKind, value: &str) -> Option<ItemState> {
        self.stored
            .items
            .iter()
            .find(|i| i.kind == kind && i.value == value)
            .map(|i| i.state)
    }

    fn active_hours(&self) -> impl Iterator<Item = &HourRow> {
        self.stored
            .hours
            .iter()
            .filter(|h| h.bytes_sent > 0 || h.bytes_received > 0 || h.connections > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;
    use whereabouts_store::{ProfileItem, ProfileRow};

    fn profile(app: &str, goes: GoesAnywhere) -> Profile {
        let t = UNIX_EPOCH + Duration::from_secs(1_000_000);
        Profile {
            stored: StoredProfile {
                row: ProfileRow {
                    key: "k".into(),
                    path: format!("C:\\x\\{app}"),
                    app_name: app.into(),
                    first_data: t,
                    learned_since: t + Duration::from_secs(3 * 86_400),
                    last_data: t + Duration::from_secs(5 * 86_400),
                    active_days: 1,
                    last_active_day: None,
                    last_sha256: None,
                    last_publisher: None,
                    goes_anywhere: goes,
                    reset_at: None,
                },
                items: vec![],
                hours: vec![],
            },
        }
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

    fn hour(hour: i64, sent: u64, received: u64, connections: u64) -> HourRow {
        HourRow {
            hour,
            bytes_sent: sent,
            bytes_received: received,
            connections,
        }
    }

    #[test]
    fn learning_for_seven_days_from_first_data() {
        let p = profile("a.exe", GoesAnywhere::Auto);
        let t = p.stored.row.first_data;
        assert!(p.is_learning(t + Duration::from_secs(6 * 86_400 + 23 * 3_600)));
        assert!(!p.is_learning(t + LEARNING));
    }

    #[test]
    fn pending_items_are_not_known() {
        let mut p = profile("a.exe", GoesAnywhere::Auto);
        p.stored.items = vec![
            item(ItemKind::Domain, "new.com", ItemState::Pending),
            item(ItemKind::Domain, "old.com", ItemState::Learned),
            item(ItemKind::Domain, "ok.com", ItemState::Allowed),
        ];
        assert!(!p.knows(ItemKind::Domain, "new.com"));
        assert!(p.pending(ItemKind::Domain, "new.com"));
        assert!(p.knows(ItemKind::Domain, "old.com"));
        assert!(p.knows(ItemKind::Domain, "ok.com"));
        assert!(!p.pending(ItemKind::Domain, "old.com"));
        assert!(!p.knows(ItemKind::Domain, "absent.com"));
        assert!(!p.knows(ItemKind::Country, "new.com"));
    }

    #[test]
    fn user_choice_wins_over_auto() {
        let off = profile("chrome.exe", GoesAnywhere::UserOff);
        assert!(!off.goes_anywhere(Some("Google LLC"), true, true));
        let on = profile("notepad.exe", GoesAnywhere::UserOn);
        assert!(on.goes_anywhere(None, false, false));
        let auto = profile("chrome.exe", GoesAnywhere::Auto);
        assert!(auto.goes_anywhere(Some("Google LLC"), true, true));
        assert!(!auto.goes_anywhere(Some("Evil Ltd"), true, true));
    }

    #[test]
    fn hour_of_day_share_uses_local_offset() {
        let mut p = profile("a.exe", GoesAnywhere::Auto);
        // Day 10, 23:00 UTC; an idle hour is ignored.
        p.stored.hours = vec![hour(10 * 24 + 23, 5, 5, 1), hour(10 * 24 + 5, 0, 0, 0)];
        let share = p.hour_of_day_share(3_600);
        assert_eq!(share[0], 1.0);
        assert_eq!(share.iter().sum::<f64>(), 1.0);
        // A negative offset works too (Euclidean remainder).
        assert_eq!(p.hour_of_day_share(-3_600)[22], 1.0);
        assert_eq!(p.hour_of_day_share(-24 * 3_600 + 3_600)[0], 1.0);
    }

    #[test]
    fn empty_profile_shapes() {
        let p = profile("a.exe", GoesAnywhere::Auto);
        assert_eq!(p.hour_of_day_share(0), [0.0; 24]);
        assert_eq!(p.download_share(), None);
        assert!(p.hourly_sent().is_empty());
    }

    #[test]
    fn hourly_series_and_download_share_use_active_hours() {
        let mut p = profile("a.exe", GoesAnywhere::Auto);
        p.stored.hours = vec![hour(1, 100, 300, 2), hour(2, 0, 0, 0), hour(3, 0, 0, 1)];
        assert_eq!(p.hourly_sent(), vec![100.0, 0.0]);
        assert_eq!(p.hourly_received(), vec![300.0, 0.0]);
        assert_eq!(p.download_share(), Some(0.75));
    }
}
