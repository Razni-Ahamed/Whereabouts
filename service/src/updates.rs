//! List updates (v0.2, N6; decisions D11 and D12).
//!
//! Two downloads, each switched on or off by the user. **Nothing is
//! downloaded until the user has answered the app's question** (both
//! switches are suggested on):
//!
//! - **Data updates**: Whereabouts' signed offline data (tracker, company,
//!   country and network lists) from its GitHub releases, checked once a
//!   day. The manifest's Ed25519 signature must match the public key built
//!   into Whereabouts, every file must match the manifest, and the bundle
//!   must be newer than the one in use. New files are written to a staging
//!   folder and swapped in whole.
//! - **Spamhaus DROP** from spamhaus.org, at most once a day (Spamhaus'
//!   terms). Spamhaus does not allow it to be redistributed, so each
//!   computer downloads it itself. Turning it off deletes the copy.
//!
//! The requests are plain HTTPS downloads of fixed public files, through
//! Windows' own TLS and certificate store: no ID, no cookies, nothing about
//! the user. Like everything else, they show up as Whereabouts' own
//! connections.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use whereabouts_data_bundle::{
    FILES, MANIFEST, MAX_FILE, MAX_MANIFEST, SIGNATURE, check_file, public_key, verify,
};
use whereabouts_enrich::DropList;
use whereabouts_ipc::ListsView;
use whereabouts_store::Store;

use crate::server::{EngineCommand, LiveState};

/// Where Whereabouts' data releases are.
const DATA_BASE: &str = "https://github.com/Razni-Ahamed/Whereabouts/releases/download";

/// Spamhaus' DROP files and where they come from.
const DROP_FILES: [(&str, &str); 2] = [
    ("drop_v4.json", "https://www.spamhaus.org/drop/drop_v4.json"),
    ("drop_v6.json", "https://www.spamhaus.org/drop/drop_v6.json"),
];

/// Largest DROP file accepted.
const MAX_DROP_FILE: u64 = 8 * 1024 * 1024;

/// How often each download is due.
const EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// After a failure, the next try.
const RETRY_AFTER: Duration = Duration::from_secs(6 * 60 * 60);
/// "Check now" never fetches DROP more often than this (Spamhaus' terms).
const DROP_AT_MOST: Duration = Duration::from_secs(60 * 60);
/// How often the updater looks whether something is due.
const TICK: Duration = Duration::from_secs(15 * 60);
/// Nothing is checked in the first minutes after the service starts.
const START_DELAY: Duration = Duration::from_secs(90);

// Saved settings.
const DATA_ON: &str = "data_updates";
const DROP_ON: &str = "drop_updates";
const DATA_SEQUENCE: &str = "data_sequence";
const DATA_CREATED: &str = "data_created";
const DATA_CHECKED: &str = "data_checked_secs";
const DATA_FAILED: &str = "data_failed_secs";
const DROP_FETCHED: &str = "drop_fetched_secs";
const DROP_FAILED: &str = "drop_failed_secs";

/// What the updater can be asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdaterCommand {
    /// The user changed the switches.
    SettingsChanged,
    /// The user asked to check now.
    CheckNow,
}

/// Where downloaded data lives (preferred over the installed data once a
/// signed bundle was accepted).
pub fn data_home() -> PathBuf {
    crate::storage::home_dir().join("data")
}

/// Where Spamhaus DROP lives.
pub fn lists_dir() -> PathBuf {
    crate::storage::home_dir().join("lists")
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn setting_bool(store: &Store, key: &str) -> Option<bool> {
    match store.setting(key).ok().flatten()?.as_str() {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

fn setting_secs(store: &Store, key: &str) -> Option<u64> {
    store.setting(key).ok().flatten()?.parse().ok()
}

/// The switches and what has been downloaded, for clients.
pub fn view(store: &Store) -> ListsView {
    ListsView {
        data_updates: setting_bool(store, DATA_ON),
        drop_updates: setting_bool(store, DROP_ON),
        data_version: store.setting(DATA_CREATED).ok().flatten(),
        data_checked_secs: setting_secs(store, DATA_CHECKED),
        drop_fetched_secs: setting_secs(store, DROP_FETCHED),
        problem: None,
        checking: false,
    }
}

/// Saves the user's choice.
pub fn set_switches(store: &mut Store, data: bool, drop: bool) -> Result<(), String> {
    let text = |on: bool| if on { "on" } else { "off" };
    store
        .set_setting(DATA_ON, text(data))
        .and_then(|()| store.set_setting(DROP_ON, text(drop)))
        .map_err(|e| e.to_string())
}

/// Starts the updater thread. Returns where to send it commands.
pub fn start(live: crate::server::SharedState) -> Sender<UpdaterCommand> {
    let (sender, receiver) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name(String::from("list-updates"))
        .spawn(move || run(&live, &receiver));
    if let Err(error) = spawned {
        report!("warning: could not start list updates: {error}");
    }
    sender
}

fn run(live: &Mutex<LiveState>, commands: &Receiver<UpdaterCommand>) {
    let mut store = match crate::storage::open() {
        Ok(store) => store,
        Err(error) => {
            report!("warning: list updates are off: {error}");
            return;
        }
    };
    publish(live, view(&store), None, false);
    let agent = agent();
    let mut wait = START_DELAY;
    loop {
        let command = match commands.recv_timeout(wait) {
            Ok(command) => Some(command),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        wait = TICK;
        let now = SystemTime::now();
        if command == Some(UpdaterCommand::SettingsChanged)
            && setting_bool(&store, DROP_ON) != Some(true)
        {
            remove_drop(live);
        }
        let check_now = command == Some(UpdaterCommand::CheckNow);
        let mut problems = Vec::new();
        publish(live, view(&store), None, true);
        if setting_bool(&store, DATA_ON) == Some(true)
            && (check_now || due(&store, DATA_CHECKED, DATA_FAILED, now, EVERY))
        {
            match check_data(&agent, &mut store, now) {
                Ok(true) => send(live, EngineCommand::ReloadData),
                Ok(false) => {}
                Err(error) => {
                    report!("warning: data update failed: {error}");
                    let _ = store.set_setting(DATA_FAILED, &unix_secs(now).to_string());
                    problems.push(format!("Data update: {error}"));
                }
            }
        }
        let drop_due = due(&store, DROP_FETCHED, DROP_FAILED, now, EVERY)
            || (check_now && due(&store, DROP_FETCHED, DROP_FAILED, now, DROP_AT_MOST));
        if setting_bool(&store, DROP_ON) == Some(true) && drop_due {
            match fetch_drop(&agent, &mut store, now) {
                Ok(()) => send(live, EngineCommand::ReloadDrop),
                Err(error) => {
                    report!("warning: Spamhaus DROP download failed: {error}");
                    let _ = store.set_setting(DROP_FAILED, &unix_secs(now).to_string());
                    problems.push(format!("Spamhaus list: {error}"));
                }
            }
        }
        let problem = (!problems.is_empty()).then(|| problems.join(" · "));
        publish(live, view(&store), problem, false);
    }
}

/// Whether a download is due: `every` since the last success, and
/// [`RETRY_AFTER`] since the last failure.
fn due(store: &Store, done: &str, failed: &str, now: SystemTime, every: Duration) -> bool {
    let since = |key: &str| {
        setting_secs(store, key)
            .map(|secs| Duration::from_secs(unix_secs(now).saturating_sub(secs)))
    };
    since(done).is_none_or(|age| age >= every) && since(failed).is_none_or(|age| age >= RETRY_AFTER)
}

fn publish(live: &Mutex<LiveState>, mut lists: ListsView, problem: Option<String>, checking: bool) {
    lists.problem = problem;
    lists.checking = checking;
    live.lock().unwrap_or_else(PoisonError::into_inner).lists = lists;
}

fn send(live: &Mutex<LiveState>, command: EngineCommand) {
    let commands = live
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .commands
        .clone();
    if let Some(commands) = commands {
        let _ = commands.send(command);
    }
}

fn agent() -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::NativeTls)
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .https_only(true)
        .max_redirects(5)
        .timeout_global(Some(Duration::from_secs(180)))
        .user_agent("Whereabouts list updates")
        .build()
        .into()
}

/// Downloads `url`, refusing more than `limit` bytes.
fn get(agent: &ureq::Agent, url: &str, limit: u64) -> Result<Vec<u8>, String> {
    let mut response = agent.get(url).call().map_err(|e| format!("{url}: {e}"))?;
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|e| format!("{url}: {e}"))
}

/// Checks for a newer signed bundle and installs it. `true` if one was
/// installed.
fn check_data(agent: &ureq::Agent, store: &mut Store, now: SystemTime) -> Result<bool, String> {
    let manifest_bytes = get(
        agent,
        &format!("{DATA_BASE}/data-latest/{MANIFEST}"),
        MAX_MANIFEST,
    )?;
    let signature = get(agent, &format!("{DATA_BASE}/data-latest/{SIGNATURE}"), 1024)?;
    let manifest = verify(&manifest_bytes, &signature, &public_key()).map_err(|e| e.to_string())?;
    let in_use = setting_secs(store, DATA_SEQUENCE).unwrap_or(0);
    let _ = store.set_setting(DATA_CHECKED, &unix_secs(now).to_string());
    if manifest.sequence <= in_use {
        return Ok(false);
    }
    let home = crate::storage::home_dir();
    let staging = home.join("data.new");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    for entry in &manifest.files {
        // The names were checked against FILES by `verify`.
        debug_assert!(FILES.contains(&entry.name.as_str()));
        let url = format!("{DATA_BASE}/data-{}/{}", manifest.sequence, entry.name);
        let bytes = get(agent, &url, entry.size.min(MAX_FILE) + 1)?;
        check_file(entry, &bytes).map_err(|e| e.to_string())?;
        std::fs::write(staging.join(&entry.name), &bytes).map_err(|e| e.to_string())?;
    }
    std::fs::write(staging.join(MANIFEST), &manifest_bytes).map_err(|e| e.to_string())?;
    std::fs::write(staging.join(SIGNATURE), &signature).map_err(|e| e.to_string())?;
    swap_in(&staging, &data_home())?;
    store
        .set_setting(DATA_SEQUENCE, &manifest.sequence.to_string())
        .and_then(|()| store.set_setting(DATA_CREATED, &manifest.created))
        .map_err(|e| e.to_string())?;
    println!(
        "Installed data update {} ({})",
        manifest.sequence, manifest.created
    );
    Ok(true)
}

/// Replaces `target` with `staging` as a whole.
fn swap_in(staging: &Path, target: &Path) -> Result<(), String> {
    let old = target.with_extension("old");
    let _ = std::fs::remove_dir_all(&old);
    if target.exists() {
        std::fs::rename(target, &old)
            .map_err(|e| format!("could not move the old data aside: {e}"))?;
    }
    if let Err(error) = std::fs::rename(staging, target) {
        // Put the old data back.
        let _ = std::fs::rename(&old, target);
        return Err(format!("could not put the new data in place: {error}"));
    }
    let _ = std::fs::remove_dir_all(&old);
    Ok(())
}

/// Downloads Spamhaus DROP and puts it in place if it parses.
fn fetch_drop(agent: &ureq::Agent, store: &mut Store, now: SystemTime) -> Result<(), String> {
    let mut texts = Vec::new();
    for (_, url) in DROP_FILES {
        let bytes = get(agent, url, MAX_DROP_FILE)?;
        texts.push(String::from_utf8(bytes).map_err(|_| format!("{url}: not text"))?);
    }
    let list = DropList::parse(&texts[0], &texts[1]);
    if list.is_empty() {
        return Err(String::from("the downloaded list has no ranges"));
    }
    let dir = lists_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for ((name, _), text) in DROP_FILES.iter().zip(&texts) {
        let temporary = dir.join(format!("{name}.new"));
        std::fs::write(&temporary, text).map_err(|e| e.to_string())?;
        std::fs::rename(&temporary, dir.join(name)).map_err(|e| e.to_string())?;
    }
    store
        .set_setting(DROP_FETCHED, &unix_secs(now).to_string())
        .map_err(|e| e.to_string())?;
    println!("Spamhaus DROP updated: {} ranges", list.len());
    Ok(())
}

/// Deletes the downloaded DROP list (the user turned it off).
fn remove_drop(live: &Mutex<LiveState>) {
    let dir = lists_dir();
    let mut removed = false;
    for (name, _) in DROP_FILES {
        removed |= std::fs::remove_file(dir.join(name)).is_ok();
    }
    if removed {
        send(live, EngineCommand::ReloadDrop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use whereabouts_store::Key;

    fn store(name: &str) -> (Store, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("whereabouts-updates-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("t.db"), &Key::from_bytes([6; 32])).unwrap();
        (store, dir)
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn nothing_is_on_until_the_user_chooses() {
        let (mut store, dir) = store("switches");
        let lists = view(&store);
        assert_eq!((lists.data_updates, lists.drop_updates), (None, None));
        set_switches(&mut store, true, false).unwrap();
        let lists = view(&store);
        assert_eq!(
            (lists.data_updates, lists.drop_updates),
            (Some(true), Some(false))
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn downloads_are_due_daily_and_retried_after_failures() {
        let (mut store, dir) = store("due");
        let t0 = 1_800_000_000;
        assert!(
            due(&store, DATA_CHECKED, DATA_FAILED, at(t0), EVERY),
            "never checked"
        );
        store.set_setting(DATA_CHECKED, &t0.to_string()).unwrap();
        assert!(!due(
            &store,
            DATA_CHECKED,
            DATA_FAILED,
            at(t0 + 3600),
            EVERY
        ));
        assert!(due(
            &store,
            DATA_CHECKED,
            DATA_FAILED,
            at(t0 + 86_400),
            EVERY
        ));
        store
            .set_setting(DATA_FAILED, &(t0 + 86_400).to_string())
            .unwrap();
        assert!(!due(
            &store,
            DATA_CHECKED,
            DATA_FAILED,
            at(t0 + 86_400 + 3600),
            EVERY
        ));
        assert!(due(
            &store,
            DATA_CHECKED,
            DATA_FAILED,
            at(t0 + 86_400 + 6 * 3600),
            EVERY
        ));
        // "Check now" for DROP: at most hourly.
        store.set_setting(DROP_FETCHED, &t0.to_string()).unwrap();
        assert!(!due(
            &store,
            DROP_FETCHED,
            DROP_FAILED,
            at(t0 + 600),
            DROP_AT_MOST
        ));
        assert!(due(
            &store,
            DROP_FETCHED,
            DROP_FAILED,
            at(t0 + 3600),
            DROP_AT_MOST
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Downloads Spamhaus DROP for real, through Windows' TLS. Not run by
    /// default: it contacts spamhaus.org (at most once a day, please).
    #[test]
    #[ignore = "contacts spamhaus.org; run with --ignored"]
    fn downloads_spamhaus_drop_over_windows_tls() {
        let agent = agent();
        let v4 = get(&agent, DROP_FILES[0].1, MAX_DROP_FILE).unwrap();
        let list = DropList::parse(std::str::from_utf8(&v4).unwrap(), "");
        assert!(list.len() > 100, "{} ranges", list.len());
        // Plain HTTP is refused.
        assert!(get(&agent, "http://www.spamhaus.org/drop/drop_v4.json", 1024).is_err());
    }

    #[test]
    fn swapping_replaces_the_whole_folder() {
        let base = std::env::temp_dir().join(format!("whereabouts-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (staging, target) = (base.join("data.new"), base.join("data"));
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("old.txt"), "old").unwrap();
        std::fs::write(staging.join("new.txt"), "new").unwrap();
        swap_in(&staging, &target).unwrap();
        assert!(target.join("new.txt").is_file());
        assert!(!target.join("old.txt").exists());
        assert!(!staging.exists() && !base.join("data.old").exists());
        let _ = std::fs::remove_dir_all(base);
    }
}
