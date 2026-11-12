//! Checks that ordinary programs cannot fake kernel events (design spec §8).
//!
//! Any program can register an ETW provider ID and write events under it.
//! For the DNS Client provider that is possible, which is why DNS labels are
//! verified separately. For the kernel network and process providers,
//! Windows refuses: `EventRegister` fails with `ERROR_ACCESS_DENIED`, even
//! from an administrator process (verified on Windows 11, 2026-11-12, with
//! `examples/forgery_probe.rs`). So those events cannot be faked from user
//! mode.
//!
//! Whereabouts relies on this, so it checks it at start-up instead of
//! assuming it: if a future or different Windows version allowed it, app
//! attribution could be faked, and the user is warned.

#![allow(unsafe_code)]

use windows::Win32::System::Diagnostics::Etw::{EventRegister, EventUnregister, REGHANDLE};
use windows::core::GUID;

use crate::events::{KERNEL_NETWORK_PROVIDER_ID, KERNEL_PROCESS_PROVIDER_ID};

/// Result of trying to register an ETW provider ID from this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// Windows refused, with this Win32 error code.
    Refused(u32),
    /// Windows allowed it. The registration has already been removed again.
    Allowed,
}

/// Tries to register `provider` as an event writer, and immediately
/// unregisters it if that worked. Writes no events.
pub fn try_register(provider: u128) -> Registration {
    let guid = GUID::from_u128(provider);
    let mut handle = REGHANDLE::default();
    // SAFETY: `guid` and `handle` are valid for the call; no callback or
    // context pointer is passed.
    let status = unsafe { EventRegister(&guid, None, None, &mut handle) };
    if status != 0 {
        return Registration::Refused(status);
    }
    // SAFETY: `handle` was just registered and is unregistered exactly once.
    unsafe { EventUnregister(handle) };
    Registration::Allowed
}

/// Returns `true` if this process cannot register the kernel network and
/// process provider IDs, so programs (at least those with no more rights
/// than this one) cannot fake their events.
pub fn kernel_providers_protected() -> bool {
    [KERNEL_NETWORK_PROVIDER_ID, KERNEL_PROCESS_PROVIDER_ID]
        .into_iter()
        .all(|provider| matches!(try_register(provider), Registration::Refused(_)))
}
