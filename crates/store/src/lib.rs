//! Encrypted local storage for Whereabouts (design spec §5.7).
//!
//! Stores flows, hourly summaries, profiles, alerts and rules in an
//! SQLCipher database whose key is protected by Windows DPAPI. Also owns
//! retention (deleting old data), export and "delete everything".

#![forbid(unsafe_code)]
