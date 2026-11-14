//! Warnings and errors from the engine.
//!
//! In a terminal they go to the error output. A Windows service has no
//! terminal, so the service also writes them to `service.log` in the data
//! folder (readable by administrators only). Only how Whereabouts itself is
//! doing is logged, never what it captured: no app names, domains or
//! addresses.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

/// Largest log file. A bigger one is renamed to `service.old.log` (replacing
/// the previous old log) when the service starts; within one run, writing
/// stops at this size.
const MAX_LOG: u64 = 1024 * 1024;

/// The log file and how many bytes it holds.
static FILE: OnceLock<Mutex<(File, u64)>> = OnceLock::new();

/// Writes a line to the error output and, if one is open, the log file.
macro_rules! report {
    ($($arg:tt)*) => {
        $crate::log::write(&format!($($arg)*))
    };
}

/// Also writes every reported line to the file at `path` from now on.
pub fn to_file(path: &Path) -> io::Result<()> {
    if std::fs::metadata(path).is_ok_and(|meta| meta.len() > MAX_LOG) {
        let old = path.with_extension("old.log");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(path, &old)?;
    }
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let size = file.metadata()?.len();
    FILE.set(Mutex::new((file, size)))
        .map_err(|_| io::Error::other("the log file is already open"))
}

/// Writes `message` (see [`report!`]).
pub fn write(message: &str) {
    eprintln!("{message}");
    if let Some(file) = FILE.get() {
        let mut guard = file.lock().unwrap_or_else(PoisonError::into_inner);
        let (file, size) = &mut *guard;
        if *size >= MAX_LOG {
            return;
        }
        let mut line = format!("{} {message}\n", timestamp(SystemTime::now()));
        if *size + line.len() as u64 >= MAX_LOG {
            line = format!(
                "{} log full; further messages are not saved until the service restarts\n",
                timestamp(SystemTime::now())
            );
        }
        if file.write_all(line.as_bytes()).is_ok() {
            *size += line.len() as u64;
        }
    }
}

/// Formats a time as UTC, e.g. `2026-11-14 10:08:09Z`.
fn timestamp(time: SystemTime) -> String {
    let secs = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (hour, minute, second) = (secs / 3600 % 24, secs / 60 % 60, secs % 60);
    // Days since 1970 to a civil date (Howard Hinnant's algorithm).
    let z = i64::try_from(secs / 86_400).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timestamps_are_utc_dates() {
        let at = |secs| timestamp(UNIX_EPOCH + Duration::from_secs(secs));
        assert_eq!(at(0), "1970-01-01 00:00:00Z");
        assert_eq!(at(951_868_800), "2000-03-01 00:00:00Z");
        assert_eq!(at(1_700_000_000), "2023-11-14 22:13:20Z");
        assert_eq!(at(1_709_208_000), "2024-02-29 12:00:00Z");
    }
}
