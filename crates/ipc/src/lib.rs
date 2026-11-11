//! Message types shared by the Whereabouts service and UI (design spec §5.8).
//!
//! The service and the UI talk over a named pipe that only SYSTEM and the
//! installing user can open. Messages are typed and versioned, and the UI can
//! only send the commands defined here; it cannot run arbitrary queries.

#![forbid(unsafe_code)]

/// Version of the service <-> UI protocol.
///
/// Increase this when a message changes in a way that old clients cannot
/// understand.
pub const PROTOCOL_VERSION: u32 = 1;
