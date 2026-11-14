//! Encrypted local storage for Whereabouts (design spec §5.7).
//!
//! Flows are kept in an SQLCipher database: the whole file is encrypted with
//! a 256-bit key, so not even the table layout is readable without it. The
//! caller supplies the key (on Windows it is protected with DPAPI by the
//! `win-secrets` crate). Deleted data is overwritten (`secure_delete`).
//!
//! Retention (privacy principle P5): individual flows are kept for a limited
//! time (default 30 days), then folded into hourly totals per app and domain,
//! which are kept longer (default 180 days) and then deleted.
//!
//! This crate contains no `unsafe` code and makes no network requests.

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, ErrorCode, params};
use whereabouts_core::dns::LabelSource;
use whereabouts_core::model::{Protocol, Signature};

/// Version of the database layout this code writes.
pub const SCHEMA_VERSION: i64 = 1;

/// Length of the database key in bytes.
pub const KEY_LEN: usize = 32;

/// The database key. Its bytes are never printed.
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Wraps 32 key bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    fn sqlcipher_literal(&self) -> String {
        // SQLCipher's raw-key form, x'<64 hex digits>', skips the key
        // derivation step that is only needed for passwords.
        let hex: String = self.0.iter().map(|b| format!("{b:02X}")).collect();
        format!("x'{hex}'")
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<hidden>)")
    }
}

/// Errors from the store.
#[derive(Debug)]
pub enum StoreError {
    /// The key does not open this database, or the file is not a database.
    WrongKey,
    /// The database was written by a newer version of Whereabouts.
    NewerSchema(i64),
    /// An SQLite error.
    Sqlite(rusqlite::Error),
    /// A file error.
    Io(io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongKey => f.write_str("the key does not open this database"),
            Self::NewerSchema(version) => write!(
                f,
                "the database uses layout version {version}, newer than this version of Whereabouts"
            ),
            Self::Sqlite(error) => write!(f, "database error: {error}"),
            Self::Io(error) => write!(f, "file error: {error}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// One finished flow, ready to be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRecord {
    /// Executable file name, e.g. `chrome.exe`.
    pub app_name: String,
    /// Full path of the executable, if known.
    pub app_path: Option<String>,
    /// SHA-256 of the executable, if known.
    pub app_sha256: Option<String>,
    /// Code signature of the executable, if it was checked.
    pub signature: Option<Signature>,
    /// Whether the signature check was confirmed to be of the running file.
    pub signature_confirmed: bool,
    /// Transport protocol.
    pub protocol: Protocol,
    /// Remote address.
    pub remote_ip: IpAddr,
    /// Remote port.
    pub remote_port: u16,
    /// Domain name, if known. For web browsers, only the registrable domain.
    pub domain: Option<String>,
    /// How much the domain can be trusted.
    pub domain_source: Option<LabelSource>,
    /// Company or network owner, as shown to the user.
    pub owner: Option<String>,
    /// Two-letter country code.
    pub country: Option<String>,
    /// When the flow was first seen.
    pub first_seen: SystemTime,
    /// When the flow was last seen.
    pub last_seen: SystemTime,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
    /// TCP connections opened or accepted.
    pub connections: u32,
}

/// Totals for one app over a period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSummary {
    /// Executable file name.
    pub app_name: String,
    /// Publisher of the most recent stored flow, if signed.
    pub publisher: Option<String>,
    /// Number of stored flows.
    pub flows: u64,
    /// Number of different domains (or addresses, when no domain is known).
    pub destinations: u64,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
}

/// How long data is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// How long individual flows are kept before being folded into hourly
    /// totals.
    pub flows: Duration,
    /// How long hourly totals are kept.
    pub hourly: Duration,
}

impl Default for Retention {
    fn default() -> Self {
        const DAY: u64 = 24 * 60 * 60;
        Self {
            flows: Duration::from_secs(30 * DAY),
            hourly: Duration::from_secs(180 * DAY),
        }
    }
}

/// What a retention run did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionReport {
    /// Flows folded into hourly totals and deleted.
    pub flows_summarized: u64,
    /// Hourly totals deleted.
    pub hourly_deleted: u64,
}

/// The encrypted database.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens (or creates) the database at `path` with `key`, and brings its
    /// layout up to date.
    pub fn open(path: &Path, key: &Key) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "key", key.sqlcipher_literal())?;
        // SQLCipher only checks the key when the file is first read.
        match conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        }) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == ErrorCode::NotADatabase =>
            {
                return Err(StoreError::WrongKey);
            }
            Err(error) => return Err(error.into()),
        }
        conn.pragma_update(None, "secure_delete", true)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;",
        )?;
        let version: Option<i64> = self
            .conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        match version {
            Some(version) if version > SCHEMA_VERSION => Err(StoreError::NewerSchema(version)),
            Some(_) => Ok(()),
            None => {
                self.conn.execute_batch(SCHEMA_V1)?;
                Ok(())
            }
        }
    }

    /// Stores finished flows in one transaction.
    pub fn insert_flows(&mut self, records: &[FlowRecord]) -> Result<(), StoreError> {
        let transaction = self.conn.transaction()?;
        {
            let mut insert = transaction.prepare_cached(
                "INSERT INTO flows (app_name, app_path, app_sha256, signature, publisher,
                     signature_code, signature_confirmed, protocol, remote_ip, remote_port, domain,
                     domain_source, owner, country, first_seen, last_seen, bytes_sent,
                     bytes_received, connections)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                     ?17, ?18, ?19)",
            )?;
            for record in records {
                let (signature, publisher, code) = signature_columns(record.signature.as_ref());
                insert.execute(params![
                    record.app_name,
                    record.app_path,
                    record.app_sha256,
                    signature,
                    publisher,
                    code,
                    record.signature_confirmed,
                    protocol_text(record.protocol),
                    record.remote_ip.to_string(),
                    record.remote_port,
                    record.domain,
                    record.domain_source.map(label_text),
                    record.owner,
                    record.country,
                    unix_ms(record.first_seen),
                    unix_ms(record.last_seen),
                    clamp(record.bytes_sent),
                    clamp(record.bytes_received),
                    record.connections,
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Number of stored flows.
    pub fn flow_count(&self) -> Result<u64, StoreError> {
        let count: i64 = self
            .conn
            .query_row("SELECT count(*) FROM flows", [], |row| row.get(0))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Time of the oldest stored flow, if any.
    pub fn oldest_flow(&self) -> Result<Option<SystemTime>, StoreError> {
        let oldest: Option<i64> =
            self.conn
                .query_row("SELECT min(first_seen) FROM flows", [], |row| row.get(0))?;
        Ok(oldest.map(from_unix_ms))
    }

    /// Per-app totals of flows last seen at or after `since`, largest
    /// first.
    pub fn top_apps(&self, since: SystemTime, limit: usize) -> Result<Vec<AppSummary>, StoreError> {
        let mut query = self.conn.prepare(
            "SELECT app_name,
                    (SELECT publisher FROM flows f2 WHERE f2.app_name = flows.app_name
                        ORDER BY last_seen DESC LIMIT 1),
                    count(*),
                    count(DISTINCT coalesce(domain, remote_ip)),
                    sum(bytes_sent), sum(bytes_received)
             FROM flows WHERE last_seen >= ?1
             GROUP BY app_name
             ORDER BY sum(bytes_sent) + sum(bytes_received) DESC
             LIMIT ?2",
        )?;
        let rows = query.query_map(
            params![unix_ms(since), i64::try_from(limit).unwrap_or(i64::MAX)],
            |row| {
                Ok(AppSummary {
                    app_name: row.get(0)?,
                    publisher: row.get(1)?,
                    flows: to_u64(row.get(2)?),
                    destinations: to_u64(row.get(3)?),
                    bytes_sent: to_u64(row.get(4)?),
                    bytes_received: to_u64(row.get(5)?),
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Folds flows older than `retention.flows` into hourly totals, deletes
    /// them, and deletes hourly totals older than `retention.hourly`, all
    /// measured at `now`.
    pub fn apply_retention(
        &mut self,
        now: SystemTime,
        retention: Retention,
    ) -> Result<RetentionReport, StoreError> {
        let flows_cutoff = unix_ms(now.checked_sub(retention.flows).unwrap_or(UNIX_EPOCH));
        let hourly_cutoff = unix_ms(now.checked_sub(retention.hourly).unwrap_or(UNIX_EPOCH));
        let transaction = self.conn.transaction()?;
        transaction.execute(
            "INSERT INTO hourly (hour, app_name, domain, bytes_sent, bytes_received, flows)
             SELECT (first_seen / 3600000) * 3600000, app_name, coalesce(domain, ''),
                    sum(bytes_sent), sum(bytes_received), count(*)
             FROM flows WHERE last_seen < ?1
             GROUP BY 1, 2, 3
             ON CONFLICT (hour, app_name, domain) DO UPDATE SET
                 bytes_sent = bytes_sent + excluded.bytes_sent,
                 bytes_received = bytes_received + excluded.bytes_received,
                 flows = flows + excluded.flows",
            params![flows_cutoff],
        )?;
        let flows_summarized = transaction.execute(
            "DELETE FROM flows WHERE last_seen < ?1",
            params![flows_cutoff],
        )?;
        let hourly_deleted =
            transaction.execute("DELETE FROM hourly WHERE hour < ?1", params![hourly_cutoff])?;
        transaction.commit()?;
        Ok(RetentionReport {
            flows_summarized: u64::try_from(flows_summarized).unwrap_or(0),
            hourly_deleted: u64::try_from(hourly_deleted).unwrap_or(0),
        })
    }

    /// Writes all stored flows as CSV (with a header row) to `out`.
    pub fn export_csv(&self, out: &mut impl Write) -> Result<u64, StoreError> {
        const COLUMNS: [&str; 18] = [
            "app_name",
            "app_path",
            "app_sha256",
            "signature",
            "publisher",
            "signature_confirmed",
            "protocol",
            "remote_ip",
            "remote_port",
            "domain",
            "domain_source",
            "owner",
            "country",
            "first_seen_unix_ms",
            "last_seen_unix_ms",
            "bytes_sent",
            "bytes_received",
            "connections",
        ];
        writeln!(out, "{}", COLUMNS.join(","))?;
        let mut query = self.conn.prepare(&format!(
            "SELECT {} FROM flows ORDER BY first_seen",
            COLUMNS
                .iter()
                .map(|column| column.trim_end_matches("_unix_ms"))
                .collect::<Vec<_>>()
                .join(", ")
        ))?;
        let mut rows = query.query([])?;
        let mut written = 0u64;
        while let Some(row) = rows.next()? {
            let mut fields = Vec::with_capacity(COLUMNS.len());
            for index in 0..COLUMNS.len() {
                let value: rusqlite::types::Value = row.get(index)?;
                fields.push(csv_field(&value));
            }
            writeln!(out, "{}", fields.join(","))?;
            written += 1;
        }
        Ok(written)
    }

    /// Deletes every stored flow and hourly total and compacts the file, so
    /// the deleted data is not left behind in free pages.
    pub fn wipe(&mut self) -> Result<(), StoreError> {
        self.conn
            .execute_batch("DELETE FROM flows; DELETE FROM hourly; VACUUM;")?;
        Ok(())
    }
}

const SCHEMA_V1: &str = "
BEGIN;
CREATE TABLE flows (
    id INTEGER PRIMARY KEY,
    app_name TEXT NOT NULL,
    app_path TEXT,
    app_sha256 TEXT,
    signature TEXT CHECK (signature IN ('signed', 'unsigned', 'invalid', 'unknown')),
    publisher TEXT,
    signature_code INTEGER,
    signature_confirmed INTEGER NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('TCP', 'UDP')),
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    domain TEXT,
    domain_source TEXT CHECK (domain_source IN ('verified', 'unverified', 'inferred')),
    owner TEXT,
    country TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL,
    connections INTEGER NOT NULL
) STRICT;
CREATE INDEX flows_last_seen ON flows (last_seen);
CREATE INDEX flows_app ON flows (app_name);
CREATE TABLE hourly (
    hour INTEGER NOT NULL,
    app_name TEXT NOT NULL,
    domain TEXT NOT NULL,
    bytes_sent INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL,
    flows INTEGER NOT NULL,
    PRIMARY KEY (hour, app_name, domain)
) STRICT;
INSERT INTO meta (key, value) VALUES ('schema_version', '1');
COMMIT;
";

fn signature_columns(
    signature: Option<&Signature>,
) -> (Option<&'static str>, Option<String>, Option<i64>) {
    match signature {
        None => (None, None, None),
        Some(Signature::Signed { publisher, .. }) => {
            (Some("signed"), Some(publisher.clone()), None)
        }
        Some(Signature::Unsigned) => (Some("unsigned"), None, None),
        Some(Signature::Invalid { code }) => (Some("invalid"), None, Some(i64::from(*code))),
        Some(Signature::Unknown) => (Some("unknown"), None, None),
    }
}

fn protocol_text(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
    }
}

fn label_text(source: LabelSource) -> &'static str {
    match source {
        LabelSource::Verified => "verified",
        LabelSource::Unverified => "unverified",
        LabelSource::Inferred => "inferred",
    }
}

fn unix_ms(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn from_unix_ms(ms: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(u64::try_from(ms).unwrap_or(0))
}

fn clamp(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_u64(value: Option<i64>) -> u64 {
    value.and_then(|v| u64::try_from(v).ok()).unwrap_or(0)
}

/// Formats one CSV field, quoting it if needed. Text that a spreadsheet
/// could run as a formula is prefixed with `'` so opening the export cannot
/// run anything: text starting with `=`, `+`, `-`, `@`, a tab or a carriage
/// return, including after leading spaces or line breaks.
fn csv_field(value: &rusqlite::types::Value) -> String {
    use rusqlite::types::Value;
    match value {
        Value::Null => String::new(),
        Value::Integer(n) => n.to_string(),
        Value::Real(x) => x.to_string(),
        Value::Text(text) => {
            let after_space = text.trim_start_matches([' ', '\t', '\r', '\n']);
            let risky =
                text.starts_with(['\t', '\r']) || after_space.starts_with(['=', '+', '-', '@']);
            let text = if risky {
                format!("'{text}")
            } else {
                text.clone()
            };
            if text.contains([',', '"', '\n', '\r']) {
                format!("\"{}\"", text.replace('"', "\"\""))
            } else {
                text
            }
        }
        Value::Blob(_) => String::from("(binary)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_db(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("whereabouts-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("test.db")
    }

    fn key(byte: u8) -> Key {
        Key::from_bytes([byte; KEY_LEN])
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn record(app: &str, domain: &str, secs: u64, sent: u64) -> FlowRecord {
        FlowRecord {
            app_name: app.to_owned(),
            app_path: Some(format!(r"C:\Apps\{app}")),
            app_sha256: Some("ab".repeat(32)),
            signature: Some(Signature::Signed {
                publisher: String::from("Example Corp"),
                via_catalog: false,
            }),
            signature_confirmed: true,
            protocol: Protocol::Tcp,
            remote_ip: "203.0.113.10".parse().unwrap(),
            remote_port: 443,
            domain: Some(domain.to_owned()),
            domain_source: Some(LabelSource::Verified),
            owner: Some(String::from("Example Network")),
            country: Some(String::from("US")),
            first_seen: at(secs),
            last_seen: at(secs + 5),
            bytes_sent: sent,
            bytes_received: sent * 10,
            connections: 1,
        }
    }

    #[test]
    fn stores_and_summarises_flows() {
        let path = temp_db("roundtrip");
        let mut store = Store::open(&path, &key(7)).unwrap();
        store
            .insert_flows(&[
                record("a.exe", "one.example", 100, 10),
                record("a.exe", "two.example", 200, 20),
                record("b.exe", "one.example", 300, 1),
            ])
            .unwrap();
        assert_eq!(store.flow_count().unwrap(), 3);
        assert_eq!(store.oldest_flow().unwrap(), Some(at(100)));

        let top = store.top_apps(at(0), 10).unwrap();
        assert_eq!(top[0].app_name, "a.exe");
        assert_eq!(top[0].flows, 2);
        assert_eq!(top[0].destinations, 2);
        assert_eq!(top[0].bytes_sent, 30);
        assert_eq!(top[0].bytes_received, 300);
        assert_eq!(top[0].publisher.as_deref(), Some("Example Corp"));
    }

    #[test]
    fn data_survives_reopening_with_the_same_key() {
        let path = temp_db("reopen");
        {
            let mut store = Store::open(&path, &key(7)).unwrap();
            store
                .insert_flows(&[record("a.exe", "x.example", 1, 1)])
                .unwrap();
        }
        let store = Store::open(&path, &key(7)).unwrap();
        assert_eq!(store.flow_count().unwrap(), 1);
    }

    #[test]
    fn the_file_is_encrypted_and_the_wrong_key_is_refused() {
        let path = temp_db("encrypted");
        {
            let mut store = Store::open(&path, &key(7)).unwrap();
            store
                .insert_flows(&[record("secret-app.exe", "very-private.example", 1, 1)])
                .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        for needle in [&b"secret-app"[..], b"very-private", b"SQLite format 3"] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "{} readable on disk",
                String::from_utf8_lossy(needle)
            );
        }
        assert!(matches!(
            Store::open(&path, &key(8)),
            Err(StoreError::WrongKey)
        ));
    }

    #[test]
    fn retention_folds_old_flows_into_hourly_totals() {
        let path = temp_db("retention");
        let mut store = Store::open(&path, &key(7)).unwrap();
        let day = 24 * 60 * 60;
        store
            .insert_flows(&[
                record("a.exe", "old.example", 1_000, 10),
                record("a.exe", "old.example", 1_100, 5),
                record("a.exe", "new.example", 40 * day, 1),
            ])
            .unwrap();
        let report = store
            .apply_retention(at(40 * day + 10), Retention::default())
            .unwrap();
        assert_eq!(report.flows_summarized, 2);
        assert_eq!(store.flow_count().unwrap(), 1);
        let (sent, flows): (i64, i64) = store
            .conn
            .query_row(
                "SELECT bytes_sent, flows FROM hourly WHERE domain = 'old.example'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((sent, flows), (15, 2));

        // Much later, the remaining flow is folded in too, and then every
        // hourly total is past 180 days and is deleted.
        let report = store
            .apply_retention(at(400 * day), Retention::default())
            .unwrap();
        assert_eq!(report.flows_summarized, 1);
        assert_eq!(report.hourly_deleted, 2);
        assert_eq!(store.flow_count().unwrap(), 0);
    }

    #[test]
    fn export_quotes_fields_and_defuses_formulas() {
        let path = temp_db("export");
        let mut store = Store::open(&path, &key(7)).unwrap();
        let mut tricky = record("a.exe", "x.example", 1, 1);
        tricky.owner = Some(String::from("=HYPERLINK(\"http://evil\")"));
        tricky.app_path = Some(String::from(r"C:\Program Files, Inc\a.exe"));
        store.insert_flows(&[tricky]).unwrap();

        let mut out = Vec::new();
        assert_eq!(store.export_csv(&mut out).unwrap(), 1);
        let text = String::from_utf8(out).unwrap();
        let mut lines = text.lines();
        assert!(lines.next().unwrap().starts_with("app_name,app_path,"));
        let row = lines.next().unwrap();
        assert!(row.contains(r#""C:\Program Files, Inc\a.exe""#), "{row}");
        assert!(row.contains(r#""'=HYPERLINK(""http://evil"")""#), "{row}");
    }

    #[test]
    fn hidden_formula_starts_are_defused_too() {
        use rusqlite::types::Value;
        for risky in ["\t=1+1", "\r@SUM(A1)", "  =cmd()", "\n-2+3"] {
            let field = csv_field(&Value::Text(String::from(risky)));
            assert!(
                field.starts_with('\'') || field.starts_with("\"'"),
                "{risky:?} became {field:?}"
            );
        }
        assert_eq!(csv_field(&Value::Text(String::from("plain"))), "plain");
    }

    #[test]
    fn wipe_deletes_everything() {
        let path = temp_db("wipe");
        let mut store = Store::open(&path, &key(7)).unwrap();
        store
            .insert_flows(&[record("a.exe", "x.example", 1, 1)])
            .unwrap();
        store.wipe().unwrap();
        assert_eq!(store.flow_count().unwrap(), 0);
    }

    #[test]
    fn a_newer_database_layout_is_refused() {
        let path = temp_db("newer");
        {
            let store = Store::open(&path, &key(7)).unwrap();
            store
                .conn
                .execute(
                    "UPDATE meta SET value = '99' WHERE key = 'schema_version'",
                    [],
                )
                .unwrap();
        }
        assert!(matches!(
            Store::open(&path, &key(7)),
            Err(StoreError::NewerSchema(99))
        ));
    }

    #[test]
    fn keys_are_never_printed() {
        assert_eq!(format!("{:?}", key(7)), "Key(<hidden>)");
    }
}
