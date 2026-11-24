//! Why a behaviour alert was raised: the signals that fired, and the
//! numbers behind them.

use serde::{Deserialize, Serialize};

/// Longest `value` kept in a [`Reason`], in characters (a domain name is at
/// most 253).
pub const REASON_VALUE_MAX_CHARS: usize = 253;

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
