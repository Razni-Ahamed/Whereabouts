//! Real-time ETW session that turns kernel network events into [`NetEvent`]s.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{UserTrace, stop_trace_by_name};
use whereabouts_core::model::NetEvent;

use crate::events::{
    CAPTURED_EVENT_IDS, EventSpec, KERNEL_NETWORK_PROVIDER, RawFields, classify,
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
    /// Network events received from ETW.
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

/// A running network capture. Stops when dropped or when [`Capture::stop`]
/// is called.
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
    pub fn start(sender: SyncSender<NetEvent>) -> Result<Self, CaptureError> {
        // A session left behind by a crashed run would block a new one.
        let _ = stop_trace_by_name(SESSION_NAME);

        let counters = Arc::new(Counters::default());
        let callback_counters = Arc::clone(&counters);
        let provider = Provider::by_guid(KERNEL_NETWORK_PROVIDER)
            .add_filter(EventFilter::ByEventIds(CAPTURED_EVENT_IDS.to_vec()))
            .add_callback(move |record, locator| {
                handle_record(record, locator, &sender, &callback_counters);
            })
            .build();

        let trace = UserTrace::new()
            .named(String::from(SESSION_NAME))
            .enable(provider)
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

fn handle_record(
    record: &EventRecord,
    locator: &SchemaLocator,
    sender: &SyncSender<NetEvent>,
    counters: &Counters,
) {
    let Some(spec) = classify(record.event_id()) else {
        return;
    };
    counters.events.fetch_add(1, Ordering::Relaxed);
    match decode(record, locator, spec) {
        Some(event) => {
            if sender.try_send(event).is_err() {
                counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        None => {
            counters.malformed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn decode(record: &EventRecord, locator: &SchemaLocator, spec: EventSpec) -> Option<NetEvent> {
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
