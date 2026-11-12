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

use std::net::IpAddr;
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

/// Empties the Windows DNS cache so the next lookup goes to the DNS service
/// (which then logs a confirming event) instead of being answered from the
/// cache.
fn flush_dns_cache() {
    let status = Command::new("ipconfig")
        .arg("/flushdns")
        .output()
        .expect("ipconfig runs");
    assert!(status.status.success(), "ipconfig /flushdns failed");
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
    assert!(
        capture.kernel_events_protected(),
        "kernel events could be faked here"
    );
    flush_dns_cache();

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

    let answers: Vec<&Vec<IpAddr>> = events
        .iter()
        .filter_map(|e| match e {
            CaptureEvent::DnsAnswer {
                pid: p,
                name,
                addresses,
                ..
            } if *p == pid && name == "example.com" => Some(addresses),
            _ => None,
        })
        .collect();
    let connected_to_answer = traffic.iter().any(|n| {
        let remote = n.remote.ip().to_canonical();
        answers.iter().any(|addresses| addresses.contains(&remote))
    });
    let confirmed: Vec<&Vec<IpAddr>> = events
        .iter()
        .filter_map(|e| match e {
            CaptureEvent::DnsConfirmed {
                name, addresses, ..
            } if name == "example.com" => Some(addresses),
            _ => None,
        })
        .collect();
    let connected_to_confirmed = traffic.iter().any(|n| {
        let remote = n.remote.ip().to_canonical();
        confirmed
            .iter()
            .any(|addresses| addresses.contains(&remote))
    });

    assert!(started, "no ProcessStarted event for curl.exe (pid {pid})");
    assert!(
        !answers.is_empty(),
        "no DNS answer for example.com attributed to curl.exe (pid {pid})"
    );
    assert!(
        connected_to_answer,
        "curl.exe's traffic did not go to an address from its DNS answer"
    );
    assert!(
        connected_to_confirmed,
        "the DNS service did not confirm the address curl.exe connected to"
    );
    assert_eq!(
        counts.rejected, 0,
        "genuine DNS service events were rejected: {counts:?}"
    );
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

#[test]
#[ignore = "needs administrator rights and network access"]
fn rejects_dns_service_events_forged_by_another_process() {
    use windows::Win32::System::Diagnostics::Etw::{
        EVENT_DESCRIPTOR, EventRegister, EventUnregister, EventWrite, REGHANDLE,
    };
    use windows::core::GUID;

    let (capture, receiver) = start_capture(100_000);

    // Register as the DNS Client provider from this ordinary test process
    // and write events that pretend to be the DNS service's "query
    // response" (3020). Any program can do this.
    let provider = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
    let mut handle = REGHANDLE::default();
    // SAFETY: `provider` and `handle` are valid for the call; no callback.
    let status = unsafe { EventRegister(&provider, None, None, &mut handle) };
    assert_eq!(status, 0, "EventRegister failed");
    let descriptor = EVENT_DESCRIPTOR {
        Id: 3020,
        Version: 0,
        Channel: 0,
        Level: 4,
        Opcode: 0,
        Task: 0,
        Keyword: 0,
    };
    for _ in 0..5 {
        // SAFETY: `handle` is registered and `descriptor` is valid; no data.
        unsafe { EventWrite(handle, &descriptor, None) };
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = collect(&receiver, Duration::from_secs(3));
    let counts = capture.counts();
    // SAFETY: `handle` was registered above and is unregistered once.
    unsafe { EventUnregister(handle) };
    drop(receiver);
    capture.stop().expect("capture stops cleanly");

    assert!(
        counts.rejected >= 1,
        "forged DNS service events were not rejected: {counts:?}"
    );
    // The forged events carry no data, so even if they had been accepted
    // they would show up as malformed, not as confirmations; the rejection
    // counter is what proves they were refused before decoding.
    assert_eq!(
        counts.malformed, 0,
        "forged events reached the decoder: {counts:?}"
    );
}

#[test]
#[ignore = "needs administrator rights and network access"]
fn checking_signatures_makes_no_network_requests() {
    use whereabouts_win_capture::identity::identify;

    let (capture, receiver) = start_capture(100_000);
    let own_pid = std::process::id();

    // Check several programs, including one with an embedded signature if
    // installed, the way Whereabouts does for every app it sees.
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
    let x86 = std::env::var("ProgramFiles(x86)").unwrap_or_default();
    let programs = [
        format!(r"{root}\System32\curl.exe"),
        format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe"),
        format!(r"{x86}\Microsoft\Edge\Application\msedge.exe"),
    ];
    for program in &programs {
        let _ = identify(program, None);
    }

    let events = collect(&receiver, Duration::from_secs(3));
    drop(receiver);
    capture.stop().expect("capture stops cleanly");

    let own_traffic: Vec<&NetEvent> = events
        .iter()
        .filter_map(|e| match e {
            CaptureEvent::Net(n) if n.pid == own_pid && !n.is_loopback() => Some(n),
            _ => None,
        })
        .collect();
    assert!(
        own_traffic.is_empty(),
        "checking signatures made network requests: {own_traffic:?}"
    );
}
