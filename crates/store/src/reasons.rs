//! Why a behaviour alert was raised: the signals that fired, and the
//! numbers behind them.

use std::cmp::Reverse;

use serde::{Deserialize, Serialize};

use crate::Severity;

/// Longest `value` kept in a [`Reason`], in characters (a domain name is at
/// most 253).
pub const REASON_VALUE_MAX_CHARS: usize = 253;

/// Most reasons kept in one alert. More are only counted (see
/// [`cap_reasons`]), so an app reaching thousands of new places in a few
/// minutes cannot grow one alert without limit.
pub const MAX_REASONS: usize = 24;

/// The kinds of unusual behaviour that are noticed.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    /// A domain the app never used before.
    NewSite,
    /// A company the app never talked to before.
    NewCompany,
    /// A country the app never connected to before.
    NewCountry,
    /// Far more data sent than usual in an hour.
    UploadSpike,
    /// Mostly downloading before, now mostly uploading.
    RatioFlip,
    /// Connections at very regular intervals.
    Beaconing,
    /// Traffic at an hour the app is rarely active.
    UnusualTime,
    /// A domain name that looks randomly generated.
    RandomName,
    /// The program file changed and it now behaves differently.
    BinaryChanged,
    /// A new program named like a known, signed one, but not signed by the
    /// same publisher.
    Impostor,
    /// A new program named like a known, signed one whose own signature
    /// could not be checked.
    ImpostorUnchecked,
}

impl Signal {
    /// The stored spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewSite => "new_site",
            Self::NewCompany => "new_company",
            Self::NewCountry => "new_country",
            Self::UploadSpike => "upload_spike",
            Self::RatioFlip => "ratio_flip",
            Self::Beaconing => "beaconing",
            Self::UnusualTime => "unusual_time",
            Self::RandomName => "random_name",
            Self::BinaryChanged => "binary_changed",
            Self::Impostor => "impostor",
            Self::ImpostorUnchecked => "impostor_unchecked",
        }
    }

    /// The severity a reason of this signal starts with (design spec v0.3,
    /// §5; new sites, companies and countries were lowered to info by the
    /// lab).
    pub fn severity(self) -> Severity {
        match self {
            Self::NewSite | Self::NewCompany | Self::NewCountry | Self::UnusualTime => {
                Severity::Info
            }
            Self::RatioFlip | Self::Beaconing | Self::RandomName | Self::ImpostorUnchecked => {
                Severity::Medium
            }
            Self::UploadSpike | Self::BinaryChanged | Self::Impostor => Severity::High,
        }
    }
}

/// One reason behind a behaviour alert.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Reason {
    /// Which signal fired.
    pub signal: Signal,
    /// The domain, company, country code or port concerned (at most
    /// [`REASON_VALUE_MAX_CHARS`] characters).
    pub value: Option<String>,
    /// What was seen (e.g. bytes sent in the hour).
    pub observed: Option<f64>,
    /// What is usual for this app.
    pub usual: Option<f64>,
    /// A count (e.g. connections).
    pub count: Option<u32>,
}

impl Reason {
    /// Cuts `value` to [`REASON_VALUE_MAX_CHARS`] characters.
    pub(crate) fn capped(mut self) -> Self {
        if let Some(value) = &mut self.value
            && value.chars().count() > REASON_VALUE_MAX_CHARS
        {
            *value = value.chars().take(REASON_VALUE_MAX_CHARS).collect();
        }
        self
    }
}

/// Cuts `reasons` to [`MAX_REASONS`], keeping the most severe and, among
/// equally severe ones, the earliest; the kept ones stay in their order.
/// Returns how many were dropped.
pub fn cap_reasons(reasons: &mut Vec<Reason>) -> u32 {
    if reasons.len() <= MAX_REASONS {
        return 0;
    }
    let mut ranked: Vec<usize> = (0..reasons.len()).collect();
    ranked.sort_by_key(|&at| (Reverse(reasons[at].signal.severity()), at));
    let mut keep = vec![false; reasons.len()];
    for &at in &ranked[..MAX_REASONS] {
        keep[at] = true;
    }
    let dropped = reasons.len() - MAX_REASONS;
    let mut at = 0;
    reasons.retain(|_| {
        at += 1;
        keep[at - 1]
    });
    u32::try_from(dropped).unwrap_or(u32::MAX)
}
