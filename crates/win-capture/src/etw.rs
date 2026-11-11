//! Real-time ETW session that turns kernel network and process events into
//! [`CaptureEvent`]s.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{UserTrace, stop_trace_by_name};
use whereabouts_core::model::{CaptureEvent, NetEvent};

use crate::events::{
    CAPTURED_EVENT_IDS, EventSpec, KERNEL_NETWORK_PROVIDER, KERNEL_PROCESS_KEYWORD,
    KERNEL_PROCESS_PROVIDER, PROCESS_START_EVENT, PROCESS_STOP_EVENT, RawFields, classify,
    filetime_to_system_time, to_net_event,
};

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
}

#[derive(Debug, Default)]
struct Counters {
    events: AtomicU64,
    dropped: AtomicU64,
    malformed: AtomicU64,
}

impl Counters {
    fn deliver(&self, sender: &SyncSender<CaptureEvent>, event: Option<CaptureEvent>) {
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
    /// full, events are dropped (and counted) rather than buffered without
    /// limit, so memory use stays bounded.
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
                net_counters.deliver(&net_sender, event);
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
                process_counters.deliver(&sender, event);
            })
            .build();

        let trace = UserTrace::new()
            .named(String::from(SESSION_NAME))
            .enable(network)
            .enable(process)
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

fn decode_process(record: &EventRecord, locator: &SchemaLocator, id: u16) -> Option<CaptureEvent> {
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);
    let pid: u32 = parser.try_parse("ProcessID").ok()?;
    if id == PROCESS_START_EVENT {
        let image: String = parser.try_parse("ImageName").ok()?;
        Some(CaptureEvent::ProcessStarted { pid, image })
    } else {
        Some(CaptureEvent::ProcessExited { pid })
    }
}
