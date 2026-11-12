//! Research tool (S1): can an ordinary program fake events from the kernel
//! network and process providers, and how can real events be told apart?
//!
//! 1. Records header fields of real `Microsoft-Windows-Kernel-Network` and
//!    `Microsoft-Windows-Kernel-Process` events for a few seconds.
//! 2. From this (ordinary) process, registers the same provider IDs and
//!    writes fake events: a network connection blamed on a `ping.exe` child,
//!    and a fake exit of that child.
//! 3. Prints what the session received, so real and fake can be compared.
//!
//! Must run as administrator (to read the session). The fakes are only seen
//! by ETW sessions; nothing else on the computer is affected.
//!
//! Result on Windows 11 (2026-11-12): `EventRegister` for both kernel
//! provider IDs fails with error 5 (access denied), even as administrator,
//! so no fake events can be written. (By contrast, the DNS Client provider
//! ID can be registered by any program.) Real process-start events are
//! logged under the *parent* process's ID, which is why the start events of
//! this tool's own `curl.exe` and `ping.exe` children appear with this
//! process's ID in the header. `src/protection.rs` turns this into a
//! start-up check.
//!
//! ```powershell
//! cargo run -p whereabouts-win-capture --example forgery_probe
//! ```

#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{UserTrace, stop_trace_by_name};
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_DATA_DESCRIPTOR, EVENT_DESCRIPTOR, EVENT_RECORD, EventRegister, EventUnregister,
    EventWrite, REGHANDLE,
};
use windows::core::GUID;

const SESSION: &str = "Whereabouts-ForgeryProbe";
const NETWORK: u128 = 0x7dd42a49_5329_4832_8dfd_43d979153a88;
const PROCESS: u128 = 0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716;

/// Header fields worth comparing.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields are read through `Debug`
struct Seen {
    provider: &'static str,
    id: u16,
    descriptor: EVENT_DESCRIPTOR,
    header_pid: u32,
    payload_pid: Option<u32>,
    flags: u16,
    event_property: u16,
    kernel_time: u32,
    user_time: u32,
    processor: u8,
    daddr: Option<IpAddr>,
}

fn raw(record: &EventRecord) -> &EVENT_RECORD {
    // SAFETY: ferrisetw's EventRecord is #[repr(transparent)] over the
    // Windows EVENT_RECORD, whose layout is the same in every `windows`
    // crate version. Research tool only.
    unsafe { &*(record as *const EventRecord).cast::<EVENT_RECORD>() }
}

fn observe(
    provider: &'static str,
    pid_field: &'static str,
) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    let log = Arc::clone(&LOG);
    move |record, locator| {
        let header = &raw(record).EventHeader;
        let (payload_pid, daddr) = match locator.event_schema(record) {
            Ok(schema) => {
                let parser = Parser::create(record, &schema);
                (
                    parser.try_parse::<u32>(pid_field).ok(),
                    parser.try_parse::<IpAddr>("daddr").ok(),
                )
            }
            Err(_) => (None, None),
        };
        // SAFETY: reading a plain-integer union field.
        let (kernel_time, user_time) = unsafe {
            (
                header.Anonymous.Anonymous.KernelTime,
                header.Anonymous.Anonymous.UserTime,
            )
        };
        // SAFETY: as above.
        let processor = unsafe {
            raw(record)
                .BufferContext
                .Anonymous
                .Anonymous
                .ProcessorNumber
        };
        log.lock().unwrap().push(Seen {
            provider,
            id: header.EventDescriptor.Id,
            descriptor: header.EventDescriptor,
            header_pid: header.ProcessId,
            payload_pid,
            flags: header.Flags,
            event_property: header.EventProperty,
            kernel_time,
            user_time,
            processor,
            daddr,
        });
    }
}

static LOG: std::sync::LazyLock<Arc<Mutex<Vec<Seen>>>> = std::sync::LazyLock::new(Arc::default);

fn main() {
    let _ = stop_trace_by_name(SESSION);
    let network = Provider::by_guid("7dd42a49-5329-4832-8dfd-43d979153a88")
        .add_filter(EventFilter::ByEventIds(vec![
            10, 11, 12, 13, 26, 27, 28, 29, 42, 43, 58, 59,
        ]))
        .add_callback(observe("network", "PID"))
        .build();
    let process = Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")
        .any(0x10)
        .add_filter(EventFilter::ByEventIds(vec![1, 2]))
        .add_callback(observe("process", "ProcessID"))
        .build();
    let trace = UserTrace::new()
        .named(String::from(SESSION))
        .enable(network)
        .enable(process)
        .start_and_process()
        .expect("start ETW session (run as administrator)");

    // Real traffic, including an IPv4 connect (event 12) to copy.
    std::thread::sleep(Duration::from_secs(2));
    let _ = Command::new("curl.exe")
        .args(["-4", "-s", "-o", "NUL", "https://example.com"])
        .status();
    std::thread::sleep(Duration::from_secs(4));

    // The process we will try to frame.
    let mut victim = Command::new("ping.exe")
        .args(["-n", "30", "127.0.0.1"])
        .stdout(Stdio::null())
        .spawn()
        .expect("ping.exe");
    let victim_pid = victim.id();
    std::thread::sleep(Duration::from_secs(1));

    let real_connect = LOG
        .lock()
        .unwrap()
        .iter()
        .find(|s| s.provider == "network" && s.id == 12)
        .map(|s| s.descriptor);
    let real_exit = LOG
        .lock()
        .unwrap()
        .iter()
        .find(|s| s.provider == "process" && s.id == 2)
        .map(|s| s.descriptor);
    println!(
        "own pid = {}, victim (ping.exe) pid = {victim_pid}",
        std::process::id()
    );
    println!("real connect descriptor: {real_connect:?}");
    println!("real exit descriptor: {real_exit:?}");

    if let Some(descriptor) = real_connect {
        // Kernel-Network "TcpIp connect" (IPv4) payload layout.
        let mut payload = Vec::new();
        payload.extend_from_slice(&victim_pid.to_le_bytes()); // PID
        payload.extend_from_slice(&0u32.to_le_bytes()); // size
        payload.extend_from_slice(&[203, 0, 113, 99]); // daddr
        payload.extend_from_slice(&[192, 168, 1, 50]); // saddr
        payload.extend_from_slice(&4444u16.to_be_bytes()); // dport
        payload.extend_from_slice(&50000u16.to_be_bytes()); // sport
        payload.extend_from_slice(&[0u8; 8]); // mss, sackopt, tsopt, wsopt
        payload.extend_from_slice(&0u32.to_le_bytes()); // rcvwin
        payload.extend_from_slice(&[0u8; 4]); // rcvwinscale, sndwinscale
        payload.extend_from_slice(&0u32.to_le_bytes()); // seqnum
        payload.extend_from_slice(&0u64.to_le_bytes()); // connid
        forge(NETWORK, descriptor, &payload);
    }
    if let Some(descriptor) = real_exit {
        let mut payload = victim_pid.to_le_bytes().to_vec(); // ProcessID
        payload.extend_from_slice(&[0u8; 96]); // remaining fields, zeroed
        forge(PROCESS, descriptor, &payload);
    }
    std::thread::sleep(Duration::from_secs(3));
    let _ = trace.stop();
    let _ = victim.kill();
    let _ = victim.wait();

    summarize(std::process::id(), victim_pid);
}

fn forge(provider: u128, descriptor: EVENT_DESCRIPTOR, payload: &[u8]) {
    let guid = GUID::from_u128(provider);
    let mut handle = REGHANDLE::default();
    // SAFETY: valid pointers for the duration of the call; no callback.
    let status = unsafe { EventRegister(&guid, None, None, &mut handle) };
    println!("EventRegister({guid:?}) = {status}");
    let data = [EVENT_DATA_DESCRIPTOR {
        Ptr: payload.as_ptr() as u64,
        Size: u32::try_from(payload.len()).unwrap(),
        ..Default::default()
    }];
    for _ in 0..3 {
        // SAFETY: `handle` is registered; `data` points at `payload`, which
        // outlives the call.
        let status = unsafe { EventWrite(handle, &descriptor, Some(&data)) };
        println!("  EventWrite id {} = {status}", descriptor.Id);
        std::thread::sleep(Duration::from_millis(100));
    }
    // SAFETY: registered above, unregistered once.
    unsafe { EventUnregister(handle) };
}

fn summarize(own_pid: u32, victim_pid: u32) {
    let log = LOG.lock().unwrap();
    // Anything with this process's ID in the header was written by it (or,
    // for process starts, describes a child it created).
    let forged: Vec<&Seen> = log.iter().filter(|s| s.header_pid == own_pid).collect();
    let real: Vec<&Seen> = log.iter().filter(|s| s.header_pid != own_pid).collect();

    for provider in ["network", "process"] {
        let events: Vec<&&Seen> = real.iter().filter(|s| s.provider == provider).collect();
        let mut relation: BTreeMap<&str, usize> = BTreeMap::new();
        let mut flags: BTreeMap<u16, usize> = BTreeMap::new();
        let mut property: BTreeMap<u16, usize> = BTreeMap::new();
        let mut times = 0;
        for s in &events {
            let kind = match s.payload_pid {
                None => "payload pid unreadable",
                Some(_) if s.header_pid == 4 => "header pid = 4 (System)",
                Some(p) if p == s.header_pid => "header pid = payload pid",
                Some(_) => "header pid = OTHER",
            };
            *relation.entry(kind).or_default() += 1;
            *flags.entry(s.flags).or_default() += 1;
            *property.entry(s.event_property).or_default() += 1;
            if s.kernel_time != 0 || s.user_time != 0 {
                times += 1;
            }
        }
        println!("\nREAL {provider}: {} events", events.len());
        println!("  pid relation: {relation:?}");
        println!("  flags: {flags:x?}");
        println!("  event_property: {property:?}");
        println!("  with non-zero kernel/user time: {times}");
        for s in events
            .iter()
            .filter(|s| s.payload_pid.is_some_and(|p| p != s.header_pid) && s.header_pid != 4)
            .take(5)
        {
            println!("  OTHER sample: {s:?}");
        }
        if let Some(s) = events.first() {
            println!("  sample: {s:?}");
        }
    }

    println!("\nWritten under this process's ID (own pid {own_pid}, victim pid {victim_pid}):");
    for s in &forged {
        let note = if s.provider == "process" && s.id == 1 {
            "real start event of a child this process created"
        } else {
            "FORGED"
        };
        println!("  [{note}] {s:?}");
    }
    let accepted_fakes = forged
        .iter()
        .filter(|s| !(s.provider == "process" && s.id == 1))
        .count();
    println!("\nForged events that reached the session: {accepted_fakes}");
}
