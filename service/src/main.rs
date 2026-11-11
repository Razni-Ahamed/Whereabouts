//! Whereabouts background service.
//!
//! From v0.1 this hosts capture, analysis, storage and the firewall (design
//! spec §5.1). For now it only reports its version.

fn main() {
    println!(
        "whereabouts-service {} (IPC protocol v{})",
        env!("CARGO_PKG_VERSION"),
        whereabouts_ipc::PROTOCOL_VERSION
    );
}
