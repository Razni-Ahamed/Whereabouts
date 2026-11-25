//! The replay runs timelines through the shipped detector.

use std::path::PathBuf;

use whereabouts_enrich::{CompanyList, DropList, Enricher, GeoDatabases, TrackerList};
use whereabouts_lab_replay::replay::{AlertOut, Layers, run};
use whereabouts_lab_replay::timeline::{Line, parse};

fn enricher() -> Enricher {
    Enricher::from_parts(
        TrackerList::parse("||google-analytics.com^\n"),
        CompanyList::default(),
        GeoDatabases::default(),
    )
}

fn drop_list() -> DropList {
    DropList::parse(r#"{"cidr":"192.0.2.0/24","sblid":"SBL-TEST"}"#, "")
}

fn work(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wlab-replay-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

const HEADER: &str = r#"{"type":"header","schema":2}"#;

fn flow(user: &str, time: u64, ip: &str, domain: Option<&str>, source: &str) -> String {
    let domain = domain.map_or("null".to_owned(), |d| format!("\"{d}\""));
    format!(
        r#"{{"type":"flow","user":"{user}","day":1,"app_name":"chat.exe","app_path":"C:\\Apps\\chat.exe","app_sha256":null,"protocol":"TCP","remote_ip":"{ip}","remote_port":443,"domain":{domain},"domain_source":"{source}","owner":null,"country":null,"first_seen":{time},"last_seen":{},"bytes_sent":100,"bytes_received":200,"connections":1,"scenario":null}}"#,
        time + 5
    )
}

fn replay_layers(name: &str, lines: &[String], layers: Layers) -> Result<Vec<AlertOut>, String> {
    let text = std::iter::once(HEADER.to_owned())
        .chain(lines.iter().cloned())
        .collect::<Vec<_>>()
        .join("\n");
    let events = parse(&text)?;
    let dir = work(name);
    let out = run(&events, &enricher(), Some(&drop_list()), layers, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn replay(name: &str, lines: &[String]) -> Result<Vec<AlertOut>, String> {
    replay_layers(name, lines, Layers::One)
}

const T0: u64 = 1_800_000_000;

#[test]
fn drop_hit_is_high_and_notified() {
    let alerts = replay("drop", &[flow("u1", T0, "192.0.2.7", None, "verified")]).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "bad_network");
    assert_eq!(alerts[0].severity, "high");
    assert!(alerts[0].notified);
    assert_eq!(alerts[0].user, "u1");
    assert_eq!(alerts[0].time, T0);
    assert_eq!(alerts[0].layer, 1);
}

#[test]
fn tracker_is_info_not_notified() {
    let alerts = replay(
        "tracker",
        &[flow(
            "u1",
            T0,
            "198.51.100.1",
            Some("www.google-analytics.com"),
            "verified",
        )],
    )
    .unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "tracker");
    assert_eq!(alerts[0].severity, "info");
    assert!(!alerts[0].notified);
}

#[test]
fn unverified_domain_ignored() {
    let alerts = replay(
        "unverified",
        &[flow(
            "u1",
            T0,
            "198.51.100.1",
            Some("www.google-analytics.com"),
            "unverified",
        )],
    )
    .unwrap();
    assert!(alerts.is_empty());
}

#[test]
fn counters_raise_faked_dns() {
    let lines = vec![
        format!(r#"{{"type":"counters","user":"u1","time":{T0},"rejected":0,"unattributed":0}}"#),
        format!(
            r#"{{"type":"counters","user":"u1","time":{},"rejected":3,"unattributed":0}}"#,
            T0 + 10
        ),
    ];
    let alerts = replay("counters", &lines).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "faked_dns");
    assert_eq!(alerts[0].severity, "medium");
    assert_eq!(alerts[0].app_name, None);
    assert!(alerts[0].notified);
}

#[test]
fn users_are_separate() {
    let alerts = replay(
        "users",
        &[
            flow("a", T0, "192.0.2.7", None, "verified"),
            flow("b", T0 + 1, "192.0.2.7", None, "verified"),
        ],
    )
    .unwrap();
    assert_eq!(alerts.len(), 2);
    assert!(alerts.iter().all(|alert| alert.notified));
}

#[test]
fn sorts_rows() {
    let forward = vec![
        flow("u1", T0, "192.0.2.7", None, "verified"),
        flow("u1", T0 + 4000, "192.0.2.8", None, "verified"),
    ];
    let backward: Vec<String> = forward.iter().rev().cloned().collect();
    assert_eq!(
        replay("fwd", &forward).unwrap(),
        replay("bwd", &backward).unwrap()
    );
}

#[test]
fn bad_line_names_its_number() {
    let error = replay(
        "bad",
        &[
            flow("u1", T0, "192.0.2.7", None, "verified"),
            String::from("{not json"),
        ],
    )
    .unwrap_err();
    assert!(error.contains("line 3"), "{error}");
}

#[test]
fn second_drop_hit_same_hour_not_notified() {
    let alerts = replay(
        "hour",
        &[
            flow("u1", T0, "192.0.2.7", None, "verified"),
            flow("u1", T0 + 60, "192.0.2.9", None, "verified"),
        ],
    )
    .unwrap();
    assert_eq!(alerts.len(), 2);
    assert!(alerts[0].notified);
    assert!(!alerts[1].notified);
}

#[test]
fn header_must_come_first() {
    assert!(parse(&flow("u1", T0, "192.0.2.7", None, "verified")).is_err());
    assert!(parse(r#"{"type":"header","schema":3}"#).is_err());
    assert!(parse(r#"{"type":"header","schema":2}"#).is_ok());
}

#[test]
fn timeline_schema_1_still_reads() {
    let text = format!(
        "{}\n{}",
        r#"{"type":"header","schema":1}"#,
        flow("u1", T0, "192.0.2.7", None, "verified")
    );
    let lines = parse(&text).unwrap();
    let [Line::Flow(row)] = &lines[..] else {
        panic!("{lines:?}");
    };
    assert_eq!(row.signature, None);
    assert_eq!(row.publisher, None);
}

#[test]
fn layer1_output_is_unchanged() {
    // `--layers 1` writes exactly what it wrote before Layer 2 existed.
    let alerts = replay("pin", &[flow("u1", T0, "192.0.2.7", None, "verified")]).unwrap();
    let text: Vec<String> = alerts
        .iter()
        .map(|alert| serde_json::to_string(alert).unwrap())
        .collect();
    assert_eq!(
        text,
        [concat!(
            r#"{"user":"u1","time":1800000000,"layer":1,"kind":"bad_network","severity":"high","#,
            r#""app_name":"chat.exe","app_path":"C:\\Apps\\chat.exe","target":"192.0.2.7","#,
            r#""detail":"192.0.2.0/24 (SBL-TEST)","reasons":[],"notified":true}"#
        )]
    );
}

const HOUR: u64 = 3_600;
const MB: u64 = 1_000_000;
const UPLOADER: &str = r"C:\Program Files\Upload\upload.exe";

/// A flow of `upload.exe` (signed, in Program Files) to `files.example.net`.
fn traffic(first_seen: u64, last_seen: u64, sent: u64) -> String {
    serde_json::json!({
        "type": "flow", "user": "u1", "day": 1, "app_name": "upload.exe",
        "app_path": UPLOADER, "app_sha256": "ab".repeat(32),
        "signature": "signed", "publisher": "Upload Ltd", "protocol": "TCP",
        "remote_ip": "198.51.100.20", "remote_port": 443, "domain": "api.files.example.net",
        "domain_source": "verified", "owner": null, "country": null,
        "first_seen": first_seen, "last_seen": last_seen, "bytes_sent": sent,
        "bytes_received": 200, "connections": 1, "scenario": null,
    })
    .to_string()
}

/// One 1 MB flow an hour for 8 days: a profile past its learning week.
fn learned_week() -> Vec<String> {
    (0..8 * 24)
        .map(|h| traffic(T0 + h * HOUR + 60, T0 + h * HOUR + 65, MB))
        .collect()
}

/// After the learning week.
const TEST_DAY: u64 = T0 + 8 * 24 * HOUR;

fn connection(time: u64, destination: &str) -> String {
    serde_json::json!({
        "type": "connection", "user": "u1", "app_name": "upload.exe",
        "app_path": UPLOADER, "destination": destination, "time": time,
    })
    .to_string()
}

fn behaviour(alerts: &[AlertOut]) -> Vec<&AlertOut> {
    alerts.iter().filter(|alert| alert.layer == 2).collect()
}

#[test]
fn replay_layer2_flags_injected_upload() {
    let mut lines = learned_week();
    let spike = TEST_DAY + 120;
    lines.push(traffic(spike, spike + 5, 200 * MB));
    let alerts = replay_layers("upload", &lines, Layers::OneAndTwo).unwrap();
    let found = behaviour(&alerts);
    assert_eq!(found.len(), 1, "{alerts:?}");
    let alert = found[0];
    assert_eq!(alert.kind, "behaviour");
    assert_eq!(alert.severity, "high");
    assert_eq!(alert.reasons, ["upload_spike"]);
    assert_eq!(alert.app_name.as_deref(), Some("upload.exe"));
    assert_eq!(alert.app_path.as_deref(), Some(UPLOADER));
    assert_eq!(alert.time, spike + 5);
    assert!(alert.notified);
}

#[test]
fn layer1_alone_learns_nothing() {
    let mut lines = learned_week();
    lines.push(traffic(TEST_DAY + 120, TEST_DAY + 125, 200 * MB));
    assert!(replay("layer1-only", &lines).unwrap().is_empty());
}

#[test]
fn bytes_are_spread_over_the_hours_a_flow_spans() {
    // 200 MB over 25 hours is 8 MB an hour: no hour reaches the minimum.
    let mut lines = learned_week();
    lines.push(traffic(TEST_DAY, TEST_DAY + 25 * HOUR - 1, 200 * MB));
    let alerts = replay_layers("spread", &lines, Layers::OneAndTwo).unwrap();
    assert!(behaviour(&alerts).is_empty(), "{alerts:?}");
}

#[test]
fn connection_lines_feed_the_beacon_tracker() {
    let mut lines = learned_week();
    let start = TEST_DAY + 300;
    for i in 0..8 {
        lines.push(connection(start + i * 60, "cdn-1.files.example.net"));
    }
    let alerts = replay_layers("beacon", &lines, Layers::OneAndTwo).unwrap();
    let found = behaviour(&alerts);
    assert_eq!(found.len(), 1, "{alerts:?}");
    assert_eq!(found[0].reasons, ["beaconing"]);
    assert_eq!(found[0].severity, "medium");
}

#[test]
fn connections_to_bare_addresses_are_not_beacons() {
    // As the app: only confirmed names are tracked for beaconing.
    let mut lines = learned_week();
    let start = TEST_DAY + 300;
    for i in 0..8 {
        lines.push(connection(start + i * 60, "198.51.100.20"));
    }
    let alerts = replay_layers("beacon-ip", &lines, Layers::OneAndTwo).unwrap();
    assert!(behaviour(&alerts).is_empty(), "{alerts:?}");
}
