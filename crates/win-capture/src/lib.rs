//! Windows network event capture for Whereabouts (design spec §5.2-5.4).
//!
//! Reads connection metadata from Event Tracing for Windows (kernel network
//! and DNS client providers) and from Windows Filtering Platform network
//! events. It never reads packet contents.
//!
//! `unsafe` is allowed in this crate only for Windows API calls. Every
//! `unsafe` block must have a `// SAFETY:` comment explaining why it is sound.
