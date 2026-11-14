//! A program that renames its own file after starting, and puts a signed
//! file at its old path, must still be checked as the file it is really
//! running. Needs no administrator rights.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use whereabouts_core::model::Signature;
use whereabouts_win_capture::identity::{DevicePaths, identify};
use whereabouts_win_capture::process::running_image_device_path;

const HELPER_ENV: &str = "WHEREABOUTS_SLEEP_HELPER";

/// Not a real test: when started by the test below (with the environment
/// variable set), this keeps a copy of the test program running.
#[test]
#[ignore = "helper process for renamed_running_program_is_checked_by_its_real_file"]
fn sleep_helper() {
    if std::env::var_os(HELPER_ENV).is_some() {
        std::thread::sleep(Duration::from_secs(30));
    }
}

fn curl() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
    Path::new(&root).join(r"System32\curl.exe")
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn renamed_running_program_is_checked_by_its_real_file() {
    let dir = std::env::temp_dir().join(format!("whereabouts-rename-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let start_path = dir.join("app.exe");
    let moved_path = dir.join("moved.exe");

    // Run an unsigned program (a copy of this test binary).
    std::fs::copy(std::env::current_exe().unwrap(), &start_path).unwrap();
    let child = Command::new(&start_path)
        .args(["--ignored", "--exact", "sleep_helper", "--test-threads=1"])
        .env(HELPER_ENV, "1")
        .spawn()
        .expect("start helper");
    let child = KillOnDrop(child);
    let pid = child.0.id();

    // Wait until it is running, then rename its file away and put a
    // Microsoft-signed program at the old path.
    let deadline = Instant::now() + Duration::from_secs(10);
    while running_image_device_path(pid).is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    std::fs::rename(&start_path, &moved_path).expect("a running program's file can be renamed");
    std::fs::copy(curl(), &start_path).unwrap();

    // Checking by the start path would be fooled...
    let fooled = identify(&start_path.to_string_lossy(), None);
    assert!(
        matches!(fooled.signature, Signature::Signed { .. }),
        "precondition: the old path now holds a signed file: {fooled:?}"
    );

    // ...but the file the process is really running is the moved, unsigned one.
    let device = running_image_device_path(pid).expect("process is running");
    let real = DevicePaths::load()
        .to_dos(&device)
        .expect("device path maps to a drive letter");
    assert!(
        real.to_ascii_lowercase().ends_with("moved.exe"),
        "expected the renamed file, got {real}"
    );
    assert_eq!(identify(&real, None).signature, Signature::Unsigned);

    drop(child);
    let _ = std::fs::remove_dir_all(dir);
}
