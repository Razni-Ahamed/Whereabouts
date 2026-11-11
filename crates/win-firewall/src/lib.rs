//! Windows Filtering Platform rules for Whereabouts (design spec §5.6).
//!
//! Creates and removes user-mode WFP filters that block an app, or block a
//! domain for an app. All filters live under the Whereabouts WFP provider and
//! sublayer so they can be listed and removed cleanly on uninstall.
//!
//! `unsafe` is allowed in this crate only for Windows API calls. Every
//! `unsafe` block must have a `// SAFETY:` comment explaining why it is sound.
