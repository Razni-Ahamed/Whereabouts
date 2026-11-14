//! Where and how the service keeps its encrypted data (design spec §5.7).
//!
//! Everything lives in one folder, by default `%ProgramData%\Whereabouts`,
//! which is restricted to SYSTEM and Administrators:
//!
//! - `whereabouts.db`: the SQLCipher database;
//! - `database.key`: the database key, encrypted with DPAPI for this
//!   computer (older versions used `store.key`, encrypted for one account;
//!   it is moved over automatically);
//! - `service.log`: the service's warnings (never captured data).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use whereabouts_store::{Key, Retention, Store};
use whereabouts_win_secrets::{
    KnownFolder, ensure_private_file, known_folder, load_or_create_key, secure_directory,
};

/// Database file name.
const DATABASE_FILE: &str = "whereabouts.db";
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
    for file in [KEY_FILE, LEGACY_KEY_FILE, DATABASE_FILE] {
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
    for app in top {
        println!(
            "{:<24} {:<26} {:>6} {:>13} {:>10} {:>10}",
            truncate(&app.app_name, 24),
            truncate(app.publisher.as_deref().unwrap_or("-"), 26),
            app.flows,
            app.destinations,
            crate::console::format_bytes(app.bytes_sent),
            crate::console::format_bytes(app.bytes_received)
        );
    }
    ExitCode::SUCCESS
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
