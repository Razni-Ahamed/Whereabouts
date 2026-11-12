//! Real-time ETW session that turns kernel network, process and DNS events
//! into [`CaptureEvent`]s.

use std::fmt;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{UserTrace, stop_trace_by_name};
use whereabouts_core::model::{CaptureEvent, NetEvent};

use crate::dns::{
    DNS_CLIENT_PROVIDER, DNS_QUERY_COMPLETED_EVENT, DNS_SERVICE_RESPONSE_EVENT, normalize_name,
    parse_query_results,
};
use crate::events::{
    CAPTURED_EVENT_IDS, EventSpec, KERNEL_NETWORK_PROVIDER, KERNEL_PROCESS_KEYWORD,
    KERNEL_PROCESS_PROVIDER, PROCESS_START_EVENT, PROCESS_STOP_EVENT, RawFields, classify,
    filetime_to_system_time, to_net_event,
};
use crate::service::{DNS_CLIENT_SERVICE, service_process_id};

/// Name of the ETW session. Only one Whereabouts capture runs at a time.
pub const SESSION_NAME: &str = "Whereabouts-Capture";

/// Error starting or stopping a capture.
#[derive(Debug)]
pub enum CaptureError {
    /// The ETW session could not be started.
    Start(String),
    /// The ETW session could not be stopped cleanly.
    Stop(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(detail) => write!(
                f,
                "could not start network capture ({detail}); Whereabouts must run as administrator"
            ),
            Self::Stop(detail) => write!(f, "could not stop network capture cleanly ({detail})"),
        }
    }
}

impl std::error::Error for CaptureError {}

/// Counters describing how the capture is going.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureCounts {
    /// Network and process events received from ETW.
    pub events: u64,
    /// Events dropped because the consumer could not keep up.
    pub dropped: u64,
    /// Events that could not be decoded.
    pub malformed: u64,
    /// Events that claimed to come from the Windows DNS service but were
    /// written by another process. Ordinary programs can write events under
    /// any provider ID, so a non-zero value may mean a program is trying to
    /// fake DNS labels.
    pub rejected: u64,
}

#[derive(Debug, Default)]
struct Counters {
    events: AtomicU64,
    dropped: AtomicU64,
    malformed: AtomicU64,
    rejected: AtomicU64,
}

/// How often the DNS service's process ID may be looked up again, for
/// example after the service restarted.
const DNS_SERVICE_REFRESH: Duration = Duration::from_secs(30);

/// Knows which process hosts the Windows DNS Client service.
#[derive(Debug)]
struct DnsService {
    pid: AtomicU32,
    last_lookup: Mutex<Instant>,
}

impl DnsService {
    fn new() -> Self {
        Self {
            pid: AtomicU32::new(service_process_id(DNS_CLIENT_SERVICE).unwrap_or(0)),
            last_lookup: Mutex::new(Instant::now()),
        }
    }

    /// Returns `true` if `pid` is the DNS Client service's process. Looks
    /// the service up again (at most every [`DNS_SERVICE_REFRESH`]) in case
    /// it restarted with a new process ID.
    fn is_service(&self, pid: u32) -> bool {
        let known = self.pid.load(Ordering::Relaxed);
        if known != 0 && pid == known {
            return true;
        }
        let Ok(mut last) = self.last_lookup.lock() else {
            return false;
        };
        if last.elapsed() < DNS_SERVICE_REFRESH {
            return false;
        }
        *last = Instant::now();
        let current = service_process_id(DNS_CLIENT_SERVICE).unwrap_or(0);
        self.pid.store(current, Ordering::Relaxed);
        current != 0 && pid == current
    }
}

impl Counters {
    /// Delivers a high-volume network event. If the queue is full the event
    /// is dropped and counted, so a slow consumer cannot stall ETW.
    fn deliver_lossy(&self, sender: &SyncSender<CaptureEvent>, event: Option<CaptureEvent>) {
        self.events.fetch_add(1, Ordering::Relaxed);
        match event {
            Some(event) => {
                if sender.try_send(event).is_err() {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {
                self.malformed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Delivers a process start/exit event, waiting for queue space if
    /// needed. These events are rare, and losing one would let a reused
    /// process ID be attributed to the wrong app, so they are never dropped.
    /// The send fails only once the consumer has dropped its receiver.
    fn deliver_reliable(&self, sender: &SyncSender<CaptureEvent>, event: Option<CaptureEvent>) {
        self.events.fetch_add(1, Ordering::Relaxed);
        match event {
            Some(event) => {
                let _ = sender.send(event);
            }
            None => {
                self.malformed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// A running capture. Stops when dropped or when [`Capture::stop`] is
/// called.
pub struct Capture {
    trace: UserTrace,
    counters: Arc<Counters>,
}

impl Capture {
    /// Starts capturing and sends every decoded event to `sender`.
    ///
    /// Events are delivered from a background thread. If `sender`'s queue is
    /// full, network events are dropped (and counted) rather than buffered
    /// without limit, so memory use stays bounded. Process events wait for
    /// space instead and are never dropped.
    ///
    /// Drop the receiver before calling [`Capture::stop`]: a process event
    /// waiting for space in a full queue is released only when the receiver
    /// is read from or dropped.
    pub fn start(sender: SyncSender<CaptureEvent>) -> Result<Self, CaptureError> {
        // A session left behind by a crashed run would block a new one.
        let _ = stop_trace_by_name(SESSION_NAME);

        let counters = Arc::new(Counters::default());

        let net_counters = Arc::clone(&counters);
        let net_sender = sender.clone();
        let network = Provider::by_guid(KERNEL_NETWORK_PROVIDER)
            .add_filter(EventFilter::ByEventIds(CAPTURED_EVENT_IDS.to_vec()))
            .add_callback(move |record, locator| {
                let Some(spec) = classify(record.event_id()) else {
                    return;
                };
                let event = decode_net(record, locator, spec).map(CaptureEvent::Net);
                net_counters.deliver_lossy(&net_sender, event);
            })
            .build();

        let dns_counters = Arc::clone(&counters);
        let dns_sender = sender.clone();
        let dns_service = DnsService::new();
        let dns = Provider::by_guid(DNS_CLIENT_PROVIDER)
            .add_filter(EventFilter::ByEventIds(vec![
                DNS_QUERY_COMPLETED_EVENT,
                DNS_SERVICE_RESPONSE_EVENT,
            ]))
            .add_callback(move |record, locator| {
                let kind = match record.event_id() {
                    DNS_QUERY_COMPLETED_EVENT => DnsKind::App,
                    DNS_SERVICE_RESPONSE_EVENT => {
                        // Windows stamps the real writer's process ID on
                        // each event; only the DNS service may confirm.
                        if !dns_service.is_service(record.process_id()) {
                            dns_counters.events.fetch_add(1, Ordering::Relaxed);
                            dns_counters.rejected.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        DnsKind::Service
                    }
                    _ => return,
                };
                match decode_dns(record, locator, kind) {
                    DnsDecode::Answer(event) => {
                        dns_counters.deliver_lossy(&dns_sender, Some(event))
                    }
                    DnsDecode::Malformed => dns_counters.deliver_lossy(&dns_sender, None),
                    DnsDecode::Skip => {}
                }
            })
            .build();

        let process_counters = Arc::clone(&counters);
        let process = Provider::by_guid(KERNEL_PROCESS_PROVIDER)
            .any(KERNEL_PROCESS_KEYWORD)
            .add_filter(EventFilter::ByEventIds(vec![
                PROCESS_START_EVENT,
                PROCESS_STOP_EVENT,
            ]))
            .add_callback(move |record, locator| {
                let id = record.event_id();
                if id != PROCESS_START_EVENT && id != PROCESS_STOP_EVENT {
                    return;
                }
                let event = decode_process(record, locator, id);
                process_counters.deliver_reliable(&sender, event);
            })
            .build();

        let trace = UserTrace::new()
            .named(String::from(SESSION_NAME))
            .enable(network)
            .enable(process)
            .enable(dns)
            .start_and_process()
            .map_err(|e| CaptureError::Start(format!("{e:?}")))?;

        Ok(Self { trace, counters })
    }

    /// Returns the current counters.
    pub fn counts(&self) -> CaptureCounts {
        CaptureCounts {
            events: self.counters.events.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            malformed: self.counters.malformed.load(Ordering::Relaxed),
            rejected: self.counters.rejected.load(Ordering::Relaxed),
        }
    }

    /// Stops the capture.
    pub fn stop(self) -> Result<(), CaptureError> {
        self.trace
            .stop()
            .map_err(|e| CaptureError::Stop(format!("{e:?}")))
    }
}

impl fmt::Debug for Capture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Capture")
            .field("session", &SESSION_NAME)
            .field("counts", &self.counts())
            .finish()
    }
}

fn decode_net(record: &EventRecord, locator: &SchemaLocator, spec: EventSpec) -> Option<NetEvent> {
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);
    let raw = RawFields {
        pid: parser.try_parse("PID").ok()?,
        size: parser.try_parse("size").ok()?,
        daddr: parser.try_parse("daddr").ok()?,
        saddr: parser.try_parse("saddr").ok()?,
        dport_raw: parser.try_parse("dport").ok()?,
        sport_raw: parser.try_parse("sport").ok()?,
    };
    let timestamp = filetime_to_system_time(record.raw_timestamp());
    Some(to_net_event(spec, &raw, timestamp))
}

/// Which DNS event is being decoded.
#[derive(Clone, Copy)]
enum DnsKind {
    /// Event 3008, logged by the app that asked.
    App,
    /// Event 3020, logged by the DNS Client service.
    Service,
}

/// Result of decoding a DNS event.
enum DnsDecode {
    /// A successful answer with at least one address.
    Answer(CaptureEvent),
    /// A failed query, an answer without addresses, or an invalid name.
    /// Ordinary lookup failures are not decoding problems, so these are not
    /// counted as malformed.
    Skip,
    /// The event's fields could not be read.
    Malformed,
}

fn decode_dns(record: &EventRecord, locator: &SchemaLocator, kind: DnsKind) -> DnsDecode {
    let Ok(schema) = locator.event_schema(record) else {
        return DnsDecode::Malformed;
    };
    let parser = Parser::create(record, &schema);
    let status_field = match kind {
        DnsKind::App => "QueryStatus",
        DnsKind::Service => "Status",
    };
    let (Ok(status), Ok(name), Ok(results)) = (
        parser.try_parse::<u32>(status_field),
        parser.try_parse::<String>("QueryName"),
        parser.try_parse::<String>("QueryResults"),
    ) else {
        return DnsDecode::Malformed;
    };
    let Some(name) = normalize_name(&name).filter(|_| status == 0) else {
        return DnsDecode::Skip;
    };
    let parsed = parse_query_results(&results);
    if parsed.addresses.is_empty() {
        return DnsDecode::Skip;
    }
    let timestamp = filetime_to_system_time(record.raw_timestamp());
    DnsDecode::Answer(match kind {
        DnsKind::App => CaptureEvent::DnsAnswer {
            // Event 3008 is logged in the requesting process.
            pid: record.process_id(),
            name,
            aliases: parsed.aliases,
            addresses: parsed.addresses,
            timestamp,
        },
        DnsKind::Service => CaptureEvent::DnsConfirmed {
            name,
            addresses: parsed.addresses,
            timestamp,
        },
    })
}

fn decode_process(record: &EventRecord, locator: &SchemaLocator, id: u16) -> Option<CaptureEvent> {
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);
    let pid: u32 = parser.try_parse("ProcessID").ok()?;
    let timestamp = filetime_to_system_time(record.raw_timestamp());
    if id == PROCESS_START_EVENT {
        let image: String = parser.try_parse("ImageName").ok()?;
        Some(CaptureEvent::ProcessStarted {
            pid,
            image,
            timestamp,
        })
    } else {
        Some(CaptureEvent::ProcessExited { pid, timestamp })
    }
}
