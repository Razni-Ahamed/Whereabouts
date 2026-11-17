//! Live blocking tests against the real Windows Filtering Platform.
//!
//! They need administrator rights and the internet, so `cargo test` skips
//! them; `scripts/live-test.ps1` and CI run them with `--ignored`.
//!
//! They only ever touch a separate test scope (`Firewall::open_for_tests`)
//! and block a temporary *copy* of curl.exe, so they cannot affect real
//! rules or real programs, even if they fail half-way.

use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;

use whereabouts_win_firewall::{Block, BlockError, Firewall};

const URL: &str = "https://example.com";
const SYSTEM_CURL: &str = r"C:\Windows\System32\curl.exe";

/// Removes the test scope and the curl copy when the test ends, even on a
/// failed assertion.
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Ok(firewall) = Firewall::open_for_tests() {
            let _ = firewall.uninstall();
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Whether `curl` can fetch the test page.
fn connects(curl: &Path) -> bool {
    Command::new(curl)
        .args(["--silent", "--output", "NUL", "--max-time", "10", URL])
        .status()
        .is_ok_and(|status| status.success())
}

/// A copy of curl.exe in its own folder.
fn curl_copy() -> (PathBuf, Cleanup) {
    let dir = std::env::temp_dir().join(format!("whereabouts-block-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let copy = dir.join("blocked-curl.exe");
    std::fs::copy(SYSTEM_CURL, &copy).unwrap();
    (copy, Cleanup(dir))
}

#[test]
#[ignore = "needs administrator rights and the internet; run with --ignored"]
fn blocks_and_unblocks_a_program() {
    let (curl, _cleanup) = curl_copy();
    let firewall = Firewall::open_for_tests().expect("opening WFP needs administrator rights");
    assert!(
        connects(&curl),
        "the copy must connect before anything is blocked"
    );

    let block = Block::app(&curl).unwrap();
    firewall.block(&block).unwrap();
    firewall.block(&block).unwrap(); // blocking twice is harmless
    assert!(!connects(&curl), "the blocked copy must not connect");
    assert!(
        connects(Path::new(SYSTEM_CURL)),
        "other programs are not affected"
    );
    assert_eq!(firewall.rules().unwrap(), vec![block.clone()]);

    assert!(firewall.unblock(&block).unwrap());
    assert!(!firewall.unblock(&block).unwrap(), "already unblocked");
    assert!(connects(&curl), "the copy connects again after unblocking");
    assert!(firewall.rules().unwrap().is_empty());
}

#[test]
#[ignore = "needs administrator rights and the internet; run with --ignored"]
fn blocks_addresses_for_one_program() {
    let (curl, _cleanup) = curl_copy();
    let firewall = Firewall::open_for_tests().expect("opening WFP needs administrator rights");
    let addresses: Vec<IpAddr> = ("example.com", 443)
        .to_socket_addrs()
        .unwrap()
        .map(|a| a.ip())
        .collect();
    assert!(!addresses.is_empty());

    for ip in &addresses {
        firewall
            .block(&Block::address(*ip, Some(&curl)).unwrap())
            .unwrap();
    }
    assert!(
        !connects(&curl),
        "the copy cannot reach the blocked addresses"
    );
    assert!(connects(Path::new(SYSTEM_CURL)), "other programs still can");
    assert_eq!(firewall.rules().unwrap().len(), addresses.len());

    let removed = firewall.remove_all().unwrap();
    assert!(removed >= addresses.len());
    assert!(firewall.rules().unwrap().is_empty());
    assert!(connects(&curl), "everything works again after removing all");
}

#[test]
#[ignore = "needs administrator rights; run with --ignored"]
fn refuses_to_block_what_the_system_needs() {
    let firewall = Firewall::open_for_tests().expect("opening WFP needs administrator rights");
    let svchost = Block::app(Path::new(r"C:\Windows\System32\svchost.exe")).unwrap();
    assert!(matches!(
        firewall.block(&svchost),
        Err(BlockError::Refused(_))
    ));
    let loopback = Block::address("127.0.0.1".parse().unwrap(), None).unwrap();
    assert!(matches!(
        firewall.block(&loopback),
        Err(BlockError::Refused(_))
    ));
    assert!(firewall.rules().unwrap().is_empty());
    let _ = firewall.uninstall();
}
