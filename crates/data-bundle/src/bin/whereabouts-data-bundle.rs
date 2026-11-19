//! Builds, signs and checks Whereabouts data bundles (used by CI).
//!
//! ```text
//! whereabouts-data-bundle keygen <SECRET_FILE>
//!     Makes a new signing key. Writes the private key (hex) to SECRET_FILE,
//!     which must not exist yet, and prints only the public key.
//! whereabouts-data-bundle build <DATA_DIR> <OUT_DIR> --sequence <N>
//!     Copies the bundle files from DATA_DIR to OUT_DIR, writes the manifest
//!     and signs it with the private key in the environment variable
//!     WHEREABOUTS_DATA_SIGNING_KEY. Refuses to sign with a key that does
//!     not match the public key built into Whereabouts.
//! whereabouts-data-bundle verify <BUNDLE_DIR>
//!     Checks a bundle against the built-in public key.
//! ```
//!
//! The private key is never printed.

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use whereabouts_data_bundle::{
    FILES, MANIFEST, SIGNATURE, build_manifest, check_file, from_hex, new_seed, public_key,
    public_key_of, sign, to_hex, verify,
};

const KEY_VARIABLE: &str = "WHEREABOUTS_DATA_SIGNING_KEY";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["keygen", secret] => keygen(Path::new(secret)),
        ["build", data, out, "--sequence", sequence] => sequence
            .parse()
            .map_err(|_| format!("{sequence:?} is not a number"))
            .and_then(|n| build(Path::new(data), Path::new(out), n)),
        ["verify", dir] => check(Path::new(dir)),
        _ => Err(String::from(
            "usage: whereabouts-data-bundle keygen <SECRET_FILE> | build <DATA_DIR> <OUT_DIR> \
             --sequence <N> | verify <BUNDLE_DIR>",
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(secret: &Path) -> Result<(), String> {
    let seed = new_seed().map_err(|e| e.to_string())?;
    // create_new: never overwrite an existing key.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(secret)
        .map_err(|e| format!("{}: {e}", secret.display()))?;
    std::io::Write::write_all(&mut file, to_hex(&seed).as_bytes()).map_err(|e| e.to_string())?;
    println!("public key: {}", to_hex(&public_key_of(&seed)));
    Ok(())
}

fn build(data: &Path, out: &Path, sequence: u64) -> Result<(), String> {
    let seed = std::env::var(KEY_VARIABLE)
        .ok()
        .and_then(|hex| from_hex::<32>(&hex))
        .ok_or_else(|| format!("{KEY_VARIABLE} is not set to a 64-character hex key"))?;
    if public_key_of(&seed) != public_key() {
        return Err(String::from(
            "the signing key does not match the public key built into Whereabouts",
        ));
    }
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    for name in FILES {
        std::fs::copy(data.join(name), out.join(name)).map_err(|e| format!("{name}: {e}"))?;
    }
    let sources = std::fs::read_to_string(data.join("SOURCES.generated.txt"))
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| line.chars().take(512).collect())
        .take(32)
        .collect();
    let manifest =
        build_manifest(out, sequence, &rfc3339_now(), sources).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    std::fs::write(out.join(MANIFEST), &bytes).map_err(|e| e.to_string())?;
    std::fs::write(out.join(SIGNATURE), sign(&bytes, &seed)).map_err(|e| e.to_string())?;
    check(out)?;
    println!("signed bundle {sequence} in {}", out.display());
    Ok(())
}

fn check(dir: &Path) -> Result<(), String> {
    let read = |name: &str| std::fs::read(dir.join(name)).map_err(|e| format!("{name}: {e}"));
    let manifest =
        verify(&read(MANIFEST)?, &read(SIGNATURE)?, &public_key()).map_err(|e| e.to_string())?;
    for entry in &manifest.files {
        check_file(entry, &read(&entry.name)?).map_err(|e| e.to_string())?;
    }
    println!(
        "ok: bundle {} ({}), {} files, signed by Whereabouts",
        manifest.sequence,
        manifest.created,
        manifest.files.len()
    );
    Ok(())
}

/// The current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// Days since 1970-01-01 to a calendar date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (era * 400 + yoe + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_right() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_412), (2025, 11, 20));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }
}
