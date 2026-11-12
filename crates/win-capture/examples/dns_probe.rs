//! Developer tool: prints raw events from the Microsoft-Windows-DNS-Client
//! ETW provider so event IDs, field names and formats can be checked.
//!
//! Must run as administrator. Prints DNS metadata (names and answers).
//!
//! ```powershell
//! cargo run -p whereabouts-win-capture --example dns_probe -- 15
//! ```

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::trace::{UserTrace, stop_trace_by_name};

const SESSION: &str = "Whereabouts-DnsProbe";
const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";

/// Field names to try; the probe reports which ones exist and their values.
const STRING_FIELDS: [&str; 6] = [
    "QueryName",
    "QueryResults",
    "ServerList",
    "DnsServerIpAddress",
    "Location",
    "Context",
];
const NUMBER_FIELDS: [&str; 7] = [
    "QueryType",
    "QueryOptions",
    "QueryStatus",
    "Status",
    "IsNetworkQuery",
    "InterfaceIndex",
    "IsAsyncQuery",
];

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let filter: Option<String> = std::env::args().nth(2);
    let _ = stop_trace_by_name(SESSION);

    let seen: Arc<Mutex<BTreeMap<u16, u64>>> = Arc::default();
    let seen_cb = Arc::clone(&seen);
    let provider = Provider::by_guid(DNS_CLIENT)
        .add_callback(move |record, locator| {
            let id = record.event_id();
            *seen_cb.lock().unwrap().entry(id).or_insert(0) += 1;
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let name: Result<String, _> = parser.try_parse("QueryName");
            if let (Some(filter), Ok(name)) = (&filter, &name) {
                if !name.to_ascii_lowercase().contains(filter.as_str()) {
                    return;
                }
            } else if filter.is_some() {
                return;
            }
            println!(
                "id={id} task={:?} opcode={:?} header_pid={} ts={}",
                schema.task_name(),
                schema.opcode_name(),
                record.process_id(),
                record.raw_timestamp()
            );
            for field in STRING_FIELDS {
                let value: Result<String, _> = parser.try_parse(field);
                if let Ok(value) = value {
                    println!("    {field} = {value:?}");
                }
            }
            for field in NUMBER_FIELDS {
                let value: Result<u32, _> = parser.try_parse(field);
                match value {
                    Ok(value) => println!("    {field} = {value}"),
                    Err(_) => {
                        let wide: Result<u64, _> = parser.try_parse(field);
                        if let Ok(value) = wide {
                            println!("    {field} = {value} (u64)");
                        }
                    }
                }
            }
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
