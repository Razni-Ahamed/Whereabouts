//! The replay runs timelines through the shipped detector.

use std::path::PathBuf;

use whereabouts_enrich::{CompanyList, DropList, Enricher, GeoDatabases, TrackerList};
use whereabouts_lab_replay::replay::{AlertOut, run};
use whereabouts_lab_replay::timeline::parse;

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

const HEADER: &str = r#"{"type":"header","schema":1}"#;

fn flow(user: &str, time: u64, ip: &str, domain: Option<&str>, source: &str) -> String {
    let domain = domain.map_or("null".to_owned(), |d| format!("\"{d}\""));
    format!(
        r#"{{"type":"flow","user":"{user}","day":1,"app_name":"chat.exe","app_path":"C:\\Apps\\chat.exe","app_sha256":null,"protocol":"TCP","remote_ip":"{ip}","remote_port":443,"domain":{domain},"domain_source":"{source}","owner":null,"country":null,"first_seen":{time},"last_seen":{},"bytes_sent":100,"bytes_received":200,"connections":1,"scenario":null}}"#,
        time + 5
    )
}

fn replay(name: &str, lines: &[String]) -> Result<Vec<AlertOut>, String> {
    let text = std::iter::once(HEADER.to_owned())
        .chain(lines.iter().cloned())
        .collect::<Vec<_>>()
        .join("\n");
    let events = parse(&text)?;
    let dir = work(name);
    let out = run(&events, &enricher(), Some(&drop_list()), &dir);
    let _ = std::fs::remove_dir_all(&dir);
    out
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
    assert!(parse(r#"{"type":"header","schema":2}"#).is_err());
}
