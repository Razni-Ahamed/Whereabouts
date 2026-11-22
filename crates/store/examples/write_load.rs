//! Saves made-up flows the way the service does (a batch every 2 seconds),
//! to measure how much the database writes to disk. Used with Windows' file
//! tracing; see `scripts/measure-db-writes.ps1`.
//!
//! ```text
//! write_load <database> <wal|journal> <flows-per-hour> [--minutes N] [--prefill N]
//! ```
//!
//! `--prefill N` first saves N older flows in large batches (so the
//! database is not empty) and stops. The flows are the same for every run
//! with the same rate, so two runs differ only in how they save.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime};

use whereabouts_core::dns::LabelSource;
use whereabouts_core::model::{Protocol, Signature};
use whereabouts_store::{FlowRecord, Journal, KEY_LEN, Key, Store};

/// How often the service saves finished flows.
const SAVE_EVERY: Duration = Duration::from_secs(2);

const APPS: [(&str, &str); 8] = [
    (
        "chrome.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ),
    (
        "msedge.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ),
    ("svchost.exe", r"C:\Windows\System32\svchost.exe"),
    (
        "Teams.exe",
        r"C:\Program Files\WindowsApps\MSTeams\ms-teams.exe",
    ),
    (
        "Spotify.exe",
        r"C:\Users\someone\AppData\Roaming\Spotify\Spotify.exe",
    ),
    (
        "utweb.exe",
        r"C:\Users\someone\AppData\Roaming\uTorrent Web\utweb.exe",
    ),
    (
        "OneDrive.exe",
        r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
    ),
    (
        "git-remote-https.exe",
        r"C:\Program Files\Git\mingw64\libexec\git-core\git-remote-https.exe",
    ),
];
const DOMAINS: [&str; 10] = [
    "google.com",
    "googleapis.com",
    "microsoft.com",
    "windowsupdate.com",
    "github.com",
    "spotify.com",
    "doubleclick.net",
    "cloudflare.com",
    "akamaihd.net",
    "example.org",
];
const OWNERS: [&str; 5] = [
    "Google LLC",
    "Microsoft Corporation",
    "Cloudflare, Inc.",
    "Akamai International B.V.",
    "M247 Europe SRL",
];

/// A small, fixed pseudo-random sequence (no extra dependency needed).
struct Sequence(u64);

impl Sequence {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 16
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[usize::try_from(self.next()).unwrap_or(0) % items.len()]
    }
}

fn flow(seq: &mut Sequence, now: SystemTime) -> FlowRecord {
    let (app_name, app_path) = seq.pick(&APPS);
    let udp = seq.next().is_multiple_of(3);
    let remote_ip = if seq.next().is_multiple_of(4) {
        IpAddr::V6(Ipv6Addr::from(
            u128::from(seq.next()) << 64 | u128::from(seq.next()),
        ))
    } else {
        IpAddr::V4(Ipv4Addr::from(
            u32::try_from(seq.next() & 0xFFFF_FFFF).unwrap_or(0),
        ))
    };
    let named = !seq.next().is_multiple_of(5);
    let lasted = Duration::from_secs(seq.next() % 600);
    FlowRecord {
        app_name: app_name.to_owned(),
        app_path: Some(app_path.to_owned()),
        app_sha256: Some(format!("{:016x}", seq.next()).repeat(4)),
        signature: Some(Signature::Signed {
            publisher: String::from("Example Publisher Ltd"),
            via_catalog: false,
        }),
        signature_confirmed: true,
        protocol: if udp { Protocol::Udp } else { Protocol::Tcp },
        remote_ip,
        remote_port: if udp {
            u16::try_from(seq.next() % 60_000 + 1024).unwrap_or(443)
        } else {
            443
        },
        domain: named.then(|| seq.pick(&DOMAINS).to_owned()),
        domain_source: named.then_some(LabelSource::Verified),
        owner: Some(seq.pick(&OWNERS).to_owned()),
        country: Some(String::from("US")),
        first_seen: now.checked_sub(lasted).unwrap_or(now),
        last_seen: now,
        bytes_sent: seq.next() % 5_000_000,
        bytes_received: seq.next() % 50_000_000,
        connections: 1,
    }
}

struct Options {
    database: PathBuf,
    journal: Journal,
    per_hour: f64,
    minutes: u64,
    prefill: Option<u64>,
}

fn parse() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: write_load <database> <wal|journal> <flows-per-hour> \
                 [--minutes N] [--prefill N]";
    let database = PathBuf::from(args.next().ok_or(usage)?);
    let journal = match args.next().as_deref() {
        Some("wal") => Journal::WriteAheadLog,
        Some("journal") => Journal::Rollback,
        _ => return Err(usage.to_owned()),
    };
    let per_hour: f64 = args
        .next()
        .and_then(|rate| rate.parse().ok())
        .ok_or(usage)?;
    let mut options = Options {
        database,
        journal,
        per_hour,
        minutes: 20,
        prefill: None,
    };
    while let Some(flag) = args.next() {
        let value: u64 = args
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or(usage)?;
        match flag.as_str() {
            "--minutes" => options.minutes = value,
            "--prefill" => options.prefill = Some(value),
            _ => return Err(usage.to_owned()),
        }
    }
    Ok(options)
}

fn run(options: &Options) -> Result<(), String> {
    let key = Key::from_bytes([0x5A; KEY_LEN]);
    let mut store = Store::open_with_journal(&options.database, &key, options.journal)
        .map_err(|e| e.to_string())?;
    if let Some(count) = options.prefill {
        let mut seq = Sequence(1);
        let start = SystemTime::now() - Duration::from_secs(7 * 24 * 60 * 60);
        let mut saved = 0;
        while saved < count {
            let batch: Vec<_> = (0..count.saturating_sub(saved).min(1000))
                .map(|i| flow(&mut seq, start + Duration::from_secs(saved + i)))
                .collect();
            store.insert_flows(&batch).map_err(|e| e.to_string())?;
            saved += batch.len() as u64;
        }
        println!("prefilled {saved} flows");
        return Ok(());
    }
    // The same rate gives the same flows, whichever way they are saved.
    let mut seq = Sequence(options.per_hour.to_bits());
    let per_save = options.per_hour * SAVE_EVERY.as_secs_f64() / 3600.0;
    let started = Instant::now();
    let end = started + Duration::from_secs(options.minutes * 60);
    let mut due = 0.0;
    let mut saved = 0u64;
    let mut next = started;
    while next < end {
        next += SAVE_EVERY;
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
        due += per_save;
        let count = due.floor();
        due -= count;
        if count < 1.0 {
            continue;
        }
        let now = SystemTime::now();
        // `count` is small and whole.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let batch: Vec<_> = (0..count as u64).map(|_| flow(&mut seq, now)).collect();
        store.insert_flows(&batch).map_err(|e| e.to_string())?;
        saved += batch.len() as u64;
    }
    println!(
        "saved {saved} flows in {:.1} minutes",
        started.elapsed().as_secs_f64() / 60.0
    );
    Ok(())
}

fn main() -> ExitCode {
    match parse().and_then(|options| run(&options)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
