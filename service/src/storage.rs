//! Where and how the service keeps its encrypted data (design spec §5.7).
//!
//! Everything lives in one folder, by default `%ProgramData%\Whereabouts`,
//! which is restricted to SYSTEM and Administrators:
//!
//! - `whereabouts.db`: the SQLCipher database, with its write-ahead log
//!   `whereabouts.db-wal` (encrypted too) and its index `whereabouts.db-shm`
//!   (page numbers only) while it is open;
//! - `database.key`: the database key, encrypted with DPAPI for this
//!   computer (older versions used `store.key`, encrypted for one account;
//!   it is moved over automatically);
//! - `service.log`: the service's warnings (never captured data).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use whereabouts_core::text::display_safe;
use whereabouts_store::{AppSummary, Key, Retention, Store};
use whereabouts_win_secrets::{
    KnownFolder, ensure_private_file, known_folder, load_or_create_key, secure_directory,
};

/// Database file name.
const DATABASE_FILE: &str = "whereabouts.db";
/// Files SQLite keeps next to the database: the write-ahead log, its index,
/// and the rollback journal of older versions.
const DATABASE_SIDE_FILES: [&str; 3] = [
    "whereabouts.db-wal",
    "whereabouts.db-shm",
    "whereabouts.db-journal",
];
/// Protected key file name.
const KEY_FILE: &str = "database.key";
/// Key file of older versions (protected for one account only).
const LEGACY_KEY_FILE: &str = "store.key";
/// The service's log.
const LOG_FILE: &str = "service.log";

/// The folder for saved data: `WHEREABOUTS_HOME` if set (for tests),
/// otherwise `%ProgramData%\Whereabouts`.
pub fn home_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("WHEREABOUTS_HOME") {
        return PathBuf::from(dir);
    }
    let program_data =
        known_folder(KnownFolder::ProgramData).unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"));
    program_data.join("Whereabouts")
}

/// Creates the data folder restricted to SYSTEM and Administrators, or
/// checks an existing one can be trusted.
fn prepare_home() -> Result<PathBuf, String> {
    let home = home_dir();
    secure_directory(&home).map_err(|e| {
        format!(
            "could not prepare {} ({e}); run as administrator",
            home.display()
        )
    })?;
    Ok(home)
}

/// Starts writing reported warnings to the service log in the data folder.
pub fn open_log() -> Result<(), String> {
    let log = prepare_home()?.join(LOG_FILE);
    ensure_private_file(&log).map_err(|e| e.to_string())?;
    crate::log::to_file(&log).map_err(|e| format!("could not open {} ({e})", log.display()))
}

/// Deletes all saved data and the data folder itself: the database is
/// wiped first (so its contents are overwritten), then every file is
/// removed.
pub fn delete_folder() -> Result<(), String> {
    let home = home_dir();
    if !home.exists() {
        return Ok(());
    }
    match open() {
        Ok(mut store) => {
            if let Err(error) = store.wipe() {
                eprintln!("warning: could not wipe the database before deleting it: {error}");
            }
        }
        Err(error) => eprintln!("warning: could not open the database to wipe it: {error}"),
    }
    std::fs::remove_dir_all(&home).map_err(|e| format!("could not delete {} ({e})", home.display()))
}

/// Opens the store, creating the folder, key and database the first time.
/// The folder is restricted to SYSTEM and Administrators before any key or
/// data is written into it.
pub fn open() -> Result<Store, String> {
    let home = prepare_home()?;
    // Existing files must not be links and must belong to SYSTEM or
    // Administrators, or someone could have planted them.
    for file in [KEY_FILE, LEGACY_KEY_FILE, DATABASE_FILE]
        .into_iter()
        .chain(DATABASE_SIDE_FILES)
    {
        ensure_private_file(&home.join(file)).map_err(|e| e.to_string())?;
    }
    let key = load_or_create_key(&home.join(KEY_FILE), &home.join(LEGACY_KEY_FILE))
        .map_err(|e| format!("could not load the database key ({e})"))?;
    Store::open(&home.join(DATABASE_FILE), &Key::from_bytes(key))
        .map_err(|e| format!("could not open the database ({e})"))
}

/// Applies the default retention, printing what it did if anything.
pub fn apply_retention(store: &mut Store) {
    match store.apply_retention(SystemTime::now(), Retention::default()) {
        Ok(report) if report.flows_summarized > 0 || report.hourly_deleted > 0 => println!(
            "Retention: {} flows older than 30 days folded into hourly totals, {} hourly \
             totals older than 180 days deleted",
            report.flows_summarized, report.hourly_deleted
        ),
        Ok(_) => {}
        Err(error) => report!("warning: retention failed: {error}"),
    }
}

/// `--history`: shows what is saved.
pub fn show_history() -> ExitCode {
    let mut store = match open() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    apply_retention(&mut store);
    let count = store.flow_count().unwrap_or(0);
    let oldest = store
        .oldest_flow()
        .ok()
        .flatten()
        .map(|time| format!(", oldest {} ago", age(time)))
        .unwrap_or_default();
    println!("Saved flows: {count}{oldest} (in {})", home_dir().display());

    let since = SystemTime::now()
        .checked_sub(Duration::from_secs(24 * 60 * 60))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let top = match store.top_apps(since, 20) {
        Ok(top) => top,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    if top.is_empty() {
        println!("Nothing saved in the last 24 hours.");
        return ExitCode::SUCCESS;
    }
    println!("\nTop apps, last 24 hours:");
    println!(
        "{:<24} {:<26} {:>6} {:>13} {:>10} {:>10}",
        "APP", "PUBLISHER", "FLOWS", "DESTINATIONS", "SENT", "RECEIVED"
    );
    let shared = shared_names(&top);
    for app in &top {
        println!(
            "{:<24} {:<26} {:>6} {:>13} {:>10} {:>10}",
            truncate(&app.app_name, 24),
            truncate(app.publisher.as_deref().unwrap_or("-"), 26),
            app.flows,
            app.destinations,
            crate::console::format_bytes(app.bytes_sent),
            crate::console::format_bytes(app.bytes_received)
        );
        if let Some(folder) = folder_line(app, &shared) {
            println!("{folder}");
        }
    }
    ExitCode::SUCCESS
}

/// File names (lowercase) that more than one app in `apps` has.
fn shared_names(apps: &[AppSummary]) -> HashSet<String> {
    let mut seen = HashSet::new();
    let mut shared = HashSet::new();
    for app in apps {
        let name = app.app_name.to_lowercase();
        if !seen.insert(name.clone()) {
            shared.insert(name);
        }
    }
    shared
}

/// For an app whose file name another app in the table shares, a line
/// under its row with its folder, so the two can be told apart.
fn folder_line(app: &AppSummary, shared: &HashSet<String>) -> Option<String> {
    if !shared.contains(&app.app_name.to_lowercase()) {
        return None;
    }
    let folder = match app.app_path.as_deref() {
        Some(path) => path.rsplit_once('\\').map_or(path, |(folder, _)| folder),
        None => "(folder not saved)",
    };
    Some(format!("  in {}", display_safe(folder)))
}

/// `--export <FILE>`: writes all saved flows as CSV.
pub fn export(path: &Path) -> ExitCode {
    let store = match open() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    // `create_new`: never overwrite an existing file by accident.
    let file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,
        Err(error) => {
            eprintln!("error: could not create {} ({error})", path.display());
            return ExitCode::FAILURE;
        }
    };
    let mut out = std::io::BufWriter::new(file);
    match store.export_csv(&mut out) {
        Ok(rows) => {
            println!(
                "Exported {rows} flows to {}. The file is NOT encrypted: it contains which apps \
                 contacted which servers. Keep it private.",
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: export failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `--delete-all [--yes]`: deletes all saved data.
pub fn delete_all(confirmed: bool) -> ExitCode {
    if !confirmed {
        println!(
            "This deletes all saved flows and hourly totals in {} and cannot be undone.\n\
             To go ahead, run again with: --delete-all --yes",
            home_dir().display()
        );
        return ExitCode::SUCCESS;
    }
    let mut store = match open() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let count = store.flow_count().unwrap_or(0);
    match store.wipe() {
        Ok(()) => {
            println!("Deleted {count} saved flows and all hourly totals.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: delete failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Rough age of `time`, e.g. `5 min` or `3 days`.
fn age(time: SystemTime) -> String {
    let secs = SystemTime::now()
        .duration_since(time)
        .unwrap_or_default()
        .as_secs();
    match secs {
        0..120 => format!("{secs} s"),
        120..7_200 => format!("{} min", secs / 60),
        7_200..172_800 => format!("{} h", secs / 3_600),
        _ => format!("{} days", secs / 86_400),
    }
}

fn truncate(text: &str, max: usize) -> String {
    crate::console::truncate(text, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(name: &str, path: Option<&str>) -> AppSummary {
        AppSummary {
            app_name: name.to_owned(),
            app_path: path.map(str::to_owned),
            publisher: None,
            flows: 1,
            destinations: 1,
            bytes_sent: 1,
            bytes_received: 1,
        }
    }

    #[test]
    fn apps_that_share_a_name_show_their_folder() {
        let apps = [
            app(
                "chrome.exe",
                Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            ),
            app(
                "Chrome.exe",
                Some(r"C:\Users\me\AppData\Local\Temp\Chrome.exe"),
            ),
            app("chrome.exe", None),
            app("code.exe", Some(r"C:\Apps\code.exe")),
        ];
        let shared = shared_names(&apps);
        let lines: Vec<_> = apps.iter().map(|a| folder_line(a, &shared)).collect();
        assert_eq!(
            lines,
            [
                Some(String::from(
                    r"  in C:\Program Files\Google\Chrome\Application"
                )),
                Some(String::from(r"  in C:\Users\me\AppData\Local\Temp")),
                Some(String::from("  in (folder not saved)")),
                None,
            ]
        );
    }

    #[test]
    fn folder_lines_hide_invisible_characters() {
        let apps = [
            app("a.exe", Some("C:\\Temp\u{202E}exe.\\a.exe")),
            app("a.exe", None),
        ];
        let shared = shared_names(&apps);
        assert_eq!(
            folder_line(&apps[0], &shared).as_deref(),
            Some(r"  in C:\Temp?exe.")
        );
    }
}
