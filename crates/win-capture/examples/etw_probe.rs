//! Developer tool: prints raw events from the Microsoft-Windows-Kernel-Network
//! ETW provider so the field names, types and byte order can be checked.
//!
//! Must run as administrator. Prints connection metadata only.
//!
//! ```powershell
//! cargo run -p whereabouts-win-capture --example etw_probe -- 15
//! ```

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::trace::{UserTrace, stop_trace_by_name};

const SESSION: &str = "Whereabouts-Probe";
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let _ = stop_trace_by_name(SESSION);

    // Print the first two events of each event ID in full, then just count.
    let seen: Arc<Mutex<BTreeMap<u16, u64>>> = Arc::default();
    let seen_cb = Arc::clone(&seen);
    let provider = Provider::by_guid(KERNEL_NETWORK)
        .add_callback(move |record, locator| {
            let id = record.event_id();
            let count = {
                let mut seen = seen_cb.lock().unwrap();
                let c = seen.entry(id).or_insert(0);
                *c += 1;
                *c
            };
            if count > 2 {
                return;
            }
            let Ok(schema) = locator.event_schema(record) else {
                println!("id={id} (no schema)");
                return;
            };
            let parser = Parser::create(record, &schema);
            let pid: Result<u32, _> = parser.try_parse("PID");
            let size: Result<u32, _> = parser.try_parse("size");
            let daddr: Result<IpAddr, _> = parser.try_parse("daddr");
            let saddr: Result<IpAddr, _> = parser.try_parse("saddr");
            let dport: Result<u16, _> = parser.try_parse("dport");
            let sport: Result<u16, _> = parser.try_parse("sport");
            println!(
                "id={id} opcode={} task={:?} opcode_name={:?} header_pid={} ts={}",
                record.opcode(),
                schema.task_name(),
                schema.opcode_name(),
                record.process_id(),
                record.raw_timestamp()
            );
            println!(
                "    PID={pid:?} size={size:?} daddr={daddr:?} saddr={saddr:?} dport_raw={dport:?} sport_raw={sport:?} dport_be={:?} sport_be={:?}",
                dport.as_ref().map(|p| u16::from_be(*p)),
                sport.as_ref().map(|p| u16::from_be(*p)),
            );
        })
        .build();

    let trace = UserTrace::new()
        .named(String::from(SESSION))
        .enable(provider)
        .start_and_process();
    let trace = match trace {
        Ok(trace) => trace,
        Err(e) => {
            eprintln!("could not start ETW session (run as administrator?): {e:?}");
            std::process::exit(1);
        }
    };
    std::thread::sleep(Duration::from_secs(seconds));
    let _ = trace.stop();
    println!("event counts by id: {:?}", seen.lock().unwrap());
}
