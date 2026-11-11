//! Offline enrichment for Whereabouts (design spec §5.5).
//!
//! Turns raw connection metadata into something people can read: the
//! registrable domain (via the Public Suffix List), the company behind it,
//! its category (tracker, ads, CDN, ...) and the country of the IP address.
//!
//! Every lookup uses databases bundled with the app. This crate must never
//! make network requests (privacy principle P6).

#![forbid(unsafe_code)]
