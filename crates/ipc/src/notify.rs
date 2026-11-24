//! Which alerts the desktop app pushes as Windows notifications (design spec
//! §6.4), shared with the lab's replay tool so the lab counts exactly what
//! users would be told about.

use std::collections::HashMap;

use crate::Severity;

/// One pushed notification per app (or kind of system alert) at most this often.
pub const ALERT_REPEAT_SECS: u64 = 60 * 60;

/// Remembers when each app was last notified about.
#[derive(Debug, Default, Clone)]
pub struct AlertLimiter {
    last: HashMap<String, u64>,
}

impl AlertLimiter {
    /// Whether an alert for `who` (an app name, or the kind of a system
    /// alert) is notified at `now_secs`.
    pub fn allow(&mut self, who: &str, severity: Severity, now_secs: u64) -> bool {
        if severity < Severity::Medium {
            return false;
        }
        let recent = self
            .last
            .get(who)
            .is_some_and(|last| now_secs.saturating_sub(*last) < ALERT_REPEAT_SECS);
        if recent && severity < Severity::Critical {
            return false;
        }
        self.last.insert(who.to_owned(), now_secs);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 10_000;

    #[test]
    fn info_never() {
        assert!(!AlertLimiter::default().allow("chat.exe", Severity::Info, T0));
    }

    #[test]
    fn first_medium_allowed() {
        assert!(AlertLimiter::default().allow("chat.exe", Severity::Medium, T0));
    }

    #[test]
    fn same_who_blocked_for_an_hour() {
        let mut limiter = AlertLimiter::default();
        assert!(limiter.allow("chat.exe", Severity::Medium, T0));
        assert!(!limiter.allow("chat.exe", Severity::High, T0 + 3599));
        assert!(limiter.allow("chat.exe", Severity::Medium, T0 + 3600));
    }

    #[test]
    fn other_who_allowed() {
        let mut limiter = AlertLimiter::default();
        assert!(limiter.allow("chat.exe", Severity::Medium, T0));
        assert!(limiter.allow("game.exe", Severity::Medium, T0 + 1));
    }

    #[test]
    fn critical_always() {
        let mut limiter = AlertLimiter::default();
        assert!(limiter.allow("chat.exe", Severity::Critical, T0));
        assert!(limiter.allow("chat.exe", Severity::Critical, T0 + 1));
        assert!(!limiter.allow("chat.exe", Severity::Medium, T0 + 2));
    }
}
