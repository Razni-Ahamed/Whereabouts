//! Windows network event capture for Whereabouts (design spec §5.2-5.4).
//!
//! Reads connection metadata from the `Microsoft-Windows-Kernel-Network`
//! ETW provider: which process, which remote address and port, how many
//! bytes, and when. It never reads packet contents. Process start and exit
//! events from `Microsoft-Windows-Kernel-Process` keep app attribution
//! correct when Windows reuses a process ID.
//!
//! `unsafe` code is denied crate-wide and allowed only in [`process`], for
//! Windows API calls. Every `unsafe` block has a `// SAFETY:` comment.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::mpsc;
//! use whereabouts_win_capture::Capture;
//!
//! let (sender, receiver) = mpsc::sync_channel(10_000);
//! let capture = Capture::start(sender)?; // needs administrator rights
//! for event in receiver.iter().take(10) {
//!     println!("{event:?}");
//! }
//! drop(receiver); // release any process event waiting for queue space
//! capture.stop()?;
//! # Ok::<(), whereabouts_win_capture::CaptureError>(())
//! ```

#![deny(unsafe_code)]

pub mod dns;
mod etw;
pub mod events;
pub mod process;
pub mod protection;
pub mod service;

pub use etw::{Capture, CaptureCounts, CaptureError, SESSION_NAME};
