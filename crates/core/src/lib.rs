//! Platform-independent logic for Whereabouts.
//!
//! This crate holds everything that does not depend on Windows: the data
//! model, the statistics behind per-app behaviour profiles, and detection
//! signals such as domain entropy. It is shared with the future Android app,
//! so it must never contain `unsafe` code.
//!
//! See `docs/design-spec.md`, sections 5 and 6.

#![forbid(unsafe_code)]

pub mod dns;
pub mod entropy;
pub mod flow;
pub mod model;
pub mod privacy;
pub mod stats;
