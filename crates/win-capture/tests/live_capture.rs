//! Live tests against the real Windows ETW providers.
//!
//! They need administrator rights and network access, so they are ignored by
//! default. Run them with `scripts/live-test.ps1`, or from an administrator
//! terminal with:
//!
//! ```powershell
//! cargo test -p whereabouts-win-capture --test live_capture -- --ignored --test-threads=1
//! ```
//!
//! They must run one at a time (`--test-threads=1`) because only one
//! Whereabouts ETW session can exist at once.

use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use whereabouts_core::model::{CaptureEvent, NetEvent, NetEventKind};
use whereabouts_win_capture::Capture;

const TARGET: &str = "https://example.com";

/// Collects events until `wait` has passed.
fn collect(receiver: &Receiver<CaptureEvent>, wait: Duration) -> Vec<CaptureEvent> {
    let deadline = Instant::now() + wait;
    let mut events = Vec::new();
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match receiver.recv_timeout(remaining) {
            Ok(event) => events.push(event),
            Err(_) => break,
        }
    }
    events
}

fn start_capture(queue: usize) -> (Capture, Receiver<CaptureEvent>) {
    let (sender, receiver) = mpsc::sync_channel(queue);
    let capture = Capture::start(sender).unwrap_or_else(|e| panic!("{e}"));
    // Give the new session a moment to start delivering events.
    std::thread::sleep(Duration::from_secs(2));
    (capture, receiver)
}

#[test]
#[ignore = "needs administrator rights and network access"]
fn captures_a_short_lived_process_and_its_https_traffic() {
    let (capture, receiver) = start_capture(200_000);

    let mut child = Command::new("curl.exe")
        .args(["--silent", "--output", "NUL", "--max-time", "15", TARGET])
        .spawn()
        .expect("curl.exe is available on Windows 10 and later");
    let pid = child.id();
    let status = child.wait().expect("curl.exe ran");
    assert!(status.success(), "curl.exe failed: {status}");

    // Late traffic (e.g. TLS close messages) arrives just after exit.
    let events = collect(&receiver, Duration::from_secs(5));
    let counts = capture.counts();
    drop(receiver);
    capture.stop().expect("capture stops cleanly");

    let started = events.iter().any(|e| {
        matches!(e, CaptureEvent::ProcessStarted { pid: p, image, .. }
            if *p == pid && image.to_ascii_lowercase().ends_with("curl.exe"))
    });
    let exited = events
        .iter()
        .any(|e| matches!(e, CaptureEvent::ProcessExited { pid: p, .. } if *p == pid));
    let traffic: Vec<&NetEvent> = events
        .iter()
        .filter_map(|e| match e {
            CaptureEvent::Net(n) if n.pid == pid && n.remote.port() == 443 => Some(n),
            _ => None,
        })
        .collect();
    let sent: u64 = traffic
        .iter()
        .filter(|n| n.kind == NetEventKind::Send)
        .map(|n| n.bytes)
        .sum();
    let received: u64 = traffic
        .iter()
        .filter(|n| n.kind == NetEventKind::Receive)
        .map(|n| n.bytes)
        .sum();

    assert!(started, "no ProcessStarted event for curl.exe (pid {pid})");
    assert!(exited, "no ProcessExited event for curl.exe (pid {pid})");
    assert!(
        !traffic.is_empty(),
        "no port-443 traffic attributed to curl.exe (pid {pid})"
    );
    assert!(sent > 0, "curl.exe sent nothing to port 443");
    assert!(received > 500, "curl.exe received only {received} bytes");
    assert_eq!(
        counts.malformed, 0,
        "some events could not be decoded: {counts:?}"
    );
    assert_eq!(counts.dropped, 0, "events were dropped: {counts:?}");
}

#[test]
#[ignore = "needs administrator rights and network access"]
fn stopping_does_not_hang_when_the_queue_is_full() {
    // A queue of one, never read: network events fill it, and the next
    // process event blocks in the ETW callback waiting for space.
    let (capture, receiver) = start_capture(1);
    for _ in 0..3 {
        let _ = Command::new("cmd.exe").args(["/C", "exit"]).status();
    }
    std::thread::sleep(Duration::from_secs(2));

    // Dropping the receiver must release the blocked callback so that
    // stopping finishes.
    drop(receiver);
    let (done_sender, done_receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let result = capture.stop();
        let _ = done_sender.send(result.is_ok());
    });
    let stopped = done_receiver
        .recv_timeout(Duration::from_secs(15))
        .expect("Capture::stop did not return within 15 seconds");
    assert!(stopped, "Capture::stop returned an error");
}
