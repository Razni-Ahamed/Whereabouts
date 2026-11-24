//! Encrypted local storage for Whereabouts (design spec §5.7).
//!
//! Flows are kept in an SQLCipher database: the whole file is encrypted with
//! a 256-bit key, so not even the table layout is readable without it. The
//! caller supplies the key (on Windows it is protected with DPAPI by the
//! `win-secrets` crate). Changes are first written to a write-ahead log
//! (`<database>-wal`), encrypted the same way. Deleted data is overwritten
//! (`secure_delete`), and deleting the history also empties the log.
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

mod profiles;
mod reasons;

pub use profiles::*;
pub use reasons::{REASON_VALUE_MAX_CHARS, Reason, Signal};

/// Version of the database layout this code writes.
pub const SCHEMA_VERSION: i64 = 5;

/// Setting holding the highest blocking-rule ID ever given out.
const RULE_ID_SETTING: &str = "rule_id_used";

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
    /// The data was deleted, but a reader kept the old copy in the
    /// write-ahead log from being cleared.
    LogBusy,
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
            Self::LogBusy => f.write_str(
                "the data was deleted, but its old copy in the database log could not be cleared \
                 yet because the database was busy; please try again",
            ),
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

/// Totals for one app over a period. An app is one program file: flows are
/// grouped by the program's full path (ignoring case), or by its file name
/// when no path was saved, so programs that share a name in different folders
/// get separate totals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSummary {
    /// Executable file name.
    pub app_name: String,
    /// Full path of the program, if it was saved.
    pub app_path: Option<String>,
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

/// How changes reach the database file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Journal {
    /// Changes are appended to `<database>-wal` and copied into the
    /// database now and then (what Whereabouts uses).
    WriteAheadLog,
    /// SQLite's default: the old pages are copied to `<database>-journal`,
    /// which is created and deleted for every save (Whereabouts 0.2 and
    /// earlier).
    Rollback,
}

/// The encrypted database.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens (or creates) the database at `path` with `key`, and brings its
    /// layout up to date. Changes go through a write-ahead log
    /// ([`Journal::WriteAheadLog`]).
    pub fn open(path: &Path, key: &Key) -> Result<Self, StoreError> {
        Self::open_with_journal(path, key, Journal::WriteAheadLog)
    }

    /// Like [`Store::open`], but choosing how changes reach the file (to
    /// compare them; Whereabouts itself always uses the write-ahead log).
    pub fn open_with_journal(path: &Path, key: &Key, journal: Journal) -> Result<Self, StoreError> {
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
        // The service and its pipe clients' requests use separate
        // connections; wait for a moment rather than fail if one is writing.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // Write-ahead log instead of a rollback journal: a save appends the
        // changed pages to `<database>-wal` (encrypted like the database),
        // and they are copied into the database now and then. That writes
        // far less than creating, filling and deleting a journal for every
        // save, and readers no longer wait for the writer. With
        // `synchronous=NORMAL`, a crash of the service loses nothing; a power
        // cut can lose the last few seconds of history, never the database.
        // The setting is kept in the file, so this only changes a database
        // still using the journal. If it cannot be changed (it needs a
        // moment with no other connection reading), the journal keeps
        // working and the next start tries again.
        let (mode, synchronous) = match journal {
            Journal::WriteAheadLog => ("WAL", "NORMAL"),
            Journal::Rollback => ("DELETE", "FULL"),
        };
        let _mode: String =
            conn.pragma_update_and_check(None, "journal_mode", mode, |row| row.get(0))?;
        conn.pragma_update(None, "synchronous", synchronous)?;
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
            Some(SCHEMA_VERSION) => Ok(()),
            Some(version) => {
                // Older versions are upgraded step by step, keeping history:
                // version 1 (Whereabouts 0.1) gets blocking rules, then
                // every version gets the list of known apps.
                if version < 2 {
                    self.conn.execute_batch(SCHEMA_V2)?;
                }
                if version < 3 {
                    self.conn.execute_batch(SCHEMA_V3)?;
                }
                if version < 4 {
                    self.conn.execute_batch(SCHEMA_V4)?;
                }
                self.conn.execute_batch(SCHEMA_V5)?;
                Ok(())
            }
            None => {
                self.conn.execute_batch(SCHEMA_V1)?;
                self.conn.execute_batch(SCHEMA_V2)?;
                self.conn.execute_batch(SCHEMA_V3)?;
                self.conn.execute_batch(SCHEMA_V4)?;
                self.conn.execute_batch(SCHEMA_V5)?;
                Ok(())
            }
        }
    }

    /// Saves an alert. Returns its ID, or `None` if an alert with the same
    /// key exists already, or the user said this is fine (its allow key).
    pub fn add_alert(
        &mut self,
        alert: &NewAlert,
        now: SystemTime,
    ) -> Result<Option<i64>, StoreError> {
        if let Some(allow) = &alert.allow_key
            && self.is_allowed(allow)?
        {
            return Ok(None);
        }
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO alerts (key, allow_key, created, kind, severity, app_name, \
             app_path, target, detail, reasons) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                alert.key,
                alert.allow_key,
                unix_ms(now),
                alert.kind.as_str(),
                alert.severity.as_str(),
                alert.app_name,
                alert.app_path,
                alert.target,
                alert.detail,
                reasons_to_json(&alert.reasons)
            ],
        )?;
        Ok((inserted > 0).then(|| self.conn.last_insert_rowid()))
    }

    /// Whether the user said alerts with this allow key are fine ("this is
    /// fine" on an alert that had it).
    pub fn is_allowed(&self, allow_key: &str) -> Result<bool, StoreError> {
        Ok(self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM alert_allows WHERE key = ?1)",
            [allow_key],
            |row| row.get(0),
        )?)
    }

    /// Adds `reasons` to an open alert (a reason with the same signal and
    /// value is not added twice), keeps the higher of the old and new
    /// severity, sets how many times the behaviour was seen again, and
    /// records the time as the alert's last update. `false` if there was no
    /// such alert.
    pub fn update_alert(
        &mut self,
        id: i64,
        reasons: &[Reason],
        severity: Severity,
        seen_again: u32,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        let transaction = self.conn.transaction()?;
        let current: Option<(String, String)> = transaction
            .query_row(
                "SELECT severity, reasons FROM alerts WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        let Some((old_severity, old_reasons)) = current else {
            return Ok(false);
        };
        let mut merged = reasons_from_json(&old_reasons);
        for reason in reasons {
            let reason = reason.clone().capped();
            if !merged
                .iter()
                .any(|r| r.signal == reason.signal && r.value == reason.value)
            {
                merged.push(reason);
            }
        }
        let severity = Severity::parse(&old_severity).map_or(severity, |old| old.max(severity));
        transaction.execute(
            "UPDATE alerts SET reasons = ?1, severity = ?2, seen_again = ?3, updated = ?4 \
             WHERE id = ?5",
            params![
                reasons_to_json(&merged),
                severity.as_str(),
                seen_again,
                unix_ms(now),
                id
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Alerts created since `since`, at most `limit`: those that need a
    /// look (above info) first, then the rest, each newest first. So many
    /// info alerts can never push a serious one out of the list.
    pub fn alerts(&self, since: SystemTime, limit: usize) -> Result<Vec<StoredAlert>, StoreError> {
        let mut query = self.conn.prepare(
            "SELECT id, created, kind, severity, app_name, app_path, target, detail, dismissed, \
             allow_key IS NOT NULL, reasons, seen_again FROM alerts WHERE created >= ?1              ORDER BY severity = 'info', id DESC LIMIT ?2",
        )?;
        let rows = query.query_map(
            params![unix_ms(since), i64::try_from(limit).unwrap_or(i64::MAX)],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, bool>(8)?,
                    row.get::<_, bool>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, u32>(11)?,
                ))
            },
        )?;
        let mut alerts = Vec::new();
        for row in rows {
            let (
                id,
                created,
                kind,
                severity,
                app_name,
                app_path,
                target,
                detail,
                dismissed,
                can_allow,
                reasons,
                seen_again,
            ) = row?;
            let (Some(kind), Some(severity)) =
                (AlertKind::parse(&kind), Severity::parse(&severity))
            else {
                continue;
            };
            alerts.push(StoredAlert {
                id,
                created: from_unix_ms(created),
                kind,
                severity,
                app_name,
                app_path,
                target,
                detail,
                dismissed,
                can_allow,
                reasons: reasons_from_json(&reasons),
                seen_again,
            });
        }
        Ok(alerts)
    }

    /// Marks an alert as seen and fine. With `allow`, alerts like it (same
    /// app and target) are not raised again. `false` if there was no such
    /// alert.
    pub fn dismiss_alert(
        &mut self,
        id: i64,
        allow: bool,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        let transaction = self.conn.transaction()?;
        let allow_key: Option<Option<String>> = transaction
            .query_row("SELECT allow_key FROM alerts WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        let Some(allow_key) = allow_key else {
            return Ok(false);
        };
        transaction.execute("UPDATE alerts SET dismissed = 1 WHERE id = ?1", [id])?;
        if allow && let Some(key) = allow_key {
            transaction.execute(
                "INSERT OR IGNORE INTO alert_allows (key, created) VALUES (?1, ?2)",
                params![key, unix_ms(now)],
            )?;
            transaction.execute(
                "UPDATE alerts SET dismissed = 1 WHERE allow_key = ?1",
                [&key],
            )?;
        }
        transaction.commit()?;
        Ok(true)
    }

    /// The programs that have used the network, as keys (see
    /// [`known_app_key`]).
    pub fn known_app_keys(&self) -> Result<Vec<String>, StoreError> {
        let mut query = self.conn.prepare("SELECT key FROM known_apps")?;
        let keys = query
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keys)
    }

    /// Remembers that the program at `path` used the network. Returns
    /// `false` if it was already known.
    pub fn add_known_app(&mut self, path: &str, now: SystemTime) -> Result<bool, StoreError> {
        Ok(self.conn.execute(
            "INSERT OR IGNORE INTO known_apps (key, path, first_seen) VALUES (?1, ?2, ?3)",
            params![known_app_key(path), path, unix_ms(now)],
        )? > 0)
    }

    /// Saves a blocking rule and returns its ID. Saving a rule that already
    /// exists returns the existing rule's ID.
    pub fn add_rule(&mut self, target: &RuleTarget, now: SystemTime) -> Result<i64, StoreError> {
        let (kind, app, domain, ip) = target.columns();
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM rules WHERE kind = ?1 AND app_path IS ?2 AND domain IS ?3 \
                 AND ip IS ?4",
                params![kind, app, domain, ip],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        if let Some(id) = existing {
            return Ok(id);
        }
        // IDs are never used twice: a removed rule's ID could otherwise be
        // given to the next rule, and an old ID (an Undo, a script's
        // `--unblock 3`) would then remove a different rule.
        let highest: i64 =
            self.conn
                .query_row("SELECT COALESCE(MAX(id), 0) FROM rules", [], |row| {
                    row.get(0)
                })?;
        let used: i64 = self
            .setting(RULE_ID_SETTING)?
            .and_then(|text| text.parse().ok())
            .unwrap_or(0);
        let id = highest.max(used) + 1;
        let transaction = self.conn.transaction()?;
        transaction.execute(
            "INSERT INTO rules (id, kind, app_path, domain, ip, created) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, kind, app, domain, ip, unix_ms(now)],
        )?;
        transaction.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![RULE_ID_SETTING, id.to_string()],
        )?;
        transaction.commit()?;
        Ok(id)
    }

    /// Deletes a blocking rule. Returns `false` if there was no such rule.
    pub fn remove_rule(&mut self, id: i64) -> Result<bool, StoreError> {
        Ok(self.conn.execute("DELETE FROM rules WHERE id = ?1", [id])? > 0)
    }

    /// All saved blocking rules, oldest first.
    pub fn rules(&self) -> Result<Vec<StoredRule>, StoreError> {
        let mut query = self
            .conn
            .prepare("SELECT id, kind, app_path, domain, ip, created FROM rules ORDER BY id")?;
        let rows = query.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        let mut rules = Vec::new();
        for row in rows {
            let (id, kind, app, domain, ip, created) = row?;
            let target = match (kind.as_str(), app, domain, ip) {
                ("app", Some(path), None, None) => RuleTarget::App { path },
                ("domain", app, Some(name), None) => RuleTarget::Domain { name, app },
                ("address", app, None, Some(ip)) => match ip.parse() {
                    Ok(ip) => RuleTarget::Address { ip, app },
                    Err(_) => continue,
                },
                _ => continue,
            };
            rules.push(StoredRule {
                id,
                target,
                created: from_unix_ms(created),
            });
        }
        Ok(rules)
    }

    /// A saved setting, if set.
    pub fn setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        self.conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    /// Saves a setting.
    pub fn set_setting(&mut self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Deletes a setting. Returns `false` if it was not set.
    pub fn remove_setting(&mut self, key: &str) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .execute("DELETE FROM settings WHERE key = ?1", [key])?
            > 0)
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
    /// first. See [`AppSummary`] for what counts as one app.
    pub fn top_apps(&self, since: SystemTime, limit: usize) -> Result<Vec<AppSummary>, StoreError> {
        // With a single max() in the query, SQLite takes the bare columns
        // (name, path, publisher) from the row holding that maximum: the
        // app's most recent flow.
        let mut query = self.conn.prepare(
            "SELECT app_name, app_path, publisher, max(last_seen),
                    count(*),
                    count(DISTINCT coalesce(domain, remote_ip)),
                    sum(bytes_sent), sum(bytes_received)
             FROM flows WHERE last_seen >= ?1
             GROUP BY CASE WHEN app_path IS NULL THEN 'name:' || lower(app_name)
                           ELSE 'path:' || lower(app_path) END
             ORDER BY sum(bytes_sent) + sum(bytes_received) DESC
             LIMIT ?2",
        )?;
        let rows = query.query_map(
            params![unix_ms(since), i64::try_from(limit).unwrap_or(i64::MAX)],
            |row| {
                Ok(AppSummary {
                    app_name: row.get(0)?,
                    app_path: row.get(1)?,
                    publisher: row.get(2)?,
                    flows: to_u64(row.get(4)?),
                    destinations: to_u64(row.get(5)?),
                    bytes_sent: to_u64(row.get(6)?),
                    bytes_received: to_u64(row.get(7)?),
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
        let alerts_cutoff = unix_ms(now.checked_sub(ALERTS_KEPT_FOR).unwrap_or(UNIX_EPOCH));
        transaction.execute(
            "DELETE FROM alerts WHERE created < ?1",
            params![alerts_cutoff],
        )?;
        transaction.commit()?;
        Ok(RetentionReport {
            flows_summarized: u64::try_from(flows_summarized).unwrap_or(0),
            hourly_deleted: u64::try_from(hourly_deleted).unwrap_or(0),
        })
    }

    /// Writes every stored flow as CSV (a header line, then one line per
    /// flow, oldest stored first) and returns how many flows were written.
    pub fn export_csv(&self, out: &mut impl Write) -> Result<u64, StoreError> {
        writeln!(out, "{}", csv_header())?;
        let mut after = 0;
        let mut written = 0;
        loop {
            let page = self.export_page(after, 1000, usize::MAX)?;
            out.write_all(page.csv.as_bytes())?;
            written += page.rows;
            match page.last_id {
                Some(last) => after = last,
                None => return Ok(written),
            }
        }
    }

    /// One page of the CSV export: flows stored after the flow with ID
    /// `after` (0 for the start), at most `max_rows` of them, and no more
    /// once the text reaches `max_bytes` (at least one flow is always
    /// included). Lines only; the header comes from [`csv_header`].
    pub fn export_page(
        &self,
        after: i64,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<ExportPage, StoreError> {
        let mut query = self.conn.prepare_cached(&format!(
            "SELECT id, {} FROM flows WHERE id > ?1 ORDER BY id LIMIT ?2",
            EXPORT_COLUMNS
                .iter()
                .map(|column| column.trim_end_matches("_unix_ms"))
                .collect::<Vec<_>>()
                .join(", ")
        ))?;
        let limit = i64::try_from(max_rows.max(1)).unwrap_or(i64::MAX);
        let mut rows = query.query(params![after, limit])?;
        let mut page = ExportPage::default();
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let mut fields = Vec::with_capacity(EXPORT_COLUMNS.len());
            for index in 0..EXPORT_COLUMNS.len() {
                let value: rusqlite::types::Value = row.get(index + 1)?;
                fields.push(csv_field(&value));
            }
            page.csv.push_str(&fields.join(","));
            page.csv.push('\n');
            page.rows += 1;
            page.last_id = Some(id);
            if page.csv.len() >= max_bytes {
                break;
            }
        }
        Ok(page)
    }

    /// Deletes every stored flow and hourly total and compacts the file, so
    /// the deleted data is not left behind in free pages or in the log.
    pub fn wipe(&mut self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "DELETE FROM flows; DELETE FROM hourly; DELETE FROM known_apps; DELETE FROM alerts; \
             DELETE FROM profiles; DELETE FROM profile_items; DELETE FROM profile_hours; VACUUM;",
        )?;
        self.empty_log()
    }

    /// Deletes every stored flow and hourly total, but keeps alerts, rules,
    /// known apps and settings, and compacts the file (for turning history
    /// off).
    pub fn delete_history(&mut self) -> Result<(), StoreError> {
        self.conn
            .execute_batch("DELETE FROM flows; DELETE FROM hourly; VACUUM;")?;
        self.empty_log()
    }

    /// Copies everything in the write-ahead log into the database and cuts
    /// the log to nothing, so older copies of deleted pages do not stay in
    /// `<database>-wal`. Waits (up to the busy timeout) for readers of older
    /// data to finish.
    fn empty_log(&self) -> Result<(), StoreError> {
        let busy: i64 = self
            .conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
        if busy == 0 {
            Ok(())
        } else {
            Err(StoreError::LogBusy)
        }
    }
}

/// What a saved blocking rule blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleTarget {
    /// Every connection of a program.
    App {
        /// The program's full path.
        path: String,
    },
    /// A domain and its subdomains, for one program or every program.
    Domain {
        /// The domain, e.g. `tracker.example.com`.
        name: String,
        /// The program's full path, or `None` for every program.
        app: Option<String>,
    },
    /// One remote address, for one program or every program.
    Address {
        /// The remote address.
        ip: IpAddr,
        /// The program's full path, or `None` for every program.
        app: Option<String>,
    },
}

impl RuleTarget {
    fn columns(&self) -> (&'static str, Option<String>, Option<String>, Option<String>) {
        match self {
            Self::App { path } => ("app", Some(path.clone()), None, None),
            Self::Domain { name, app } => ("domain", app.clone(), Some(name.clone()), None),
            Self::Address { ip, app } => ("address", app.clone(), None, Some(ip.to_string())),
        }
    }
}

/// A saved blocking rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRule {
    /// The rule's ID.
    pub id: i64,
    /// What it blocks.
    pub target: RuleTarget,
    /// When it was created.
    pub created: SystemTime,
}

/// Schema version 2 (Whereabouts 0.2): blocking rules and settings.
/// How long alerts are kept.
pub const ALERTS_KEPT_FOR: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// What an alert is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    /// An app contacted a known tracker.
    Tracker,
    /// An app connected to a network on Spamhaus' DROP list.
    BadNetwork,
    /// Events claimed to come from the Windows DNS service but did not.
    FakedDns,
    /// Traffic could not be tied to any process.
    Unattributed,
    /// An app behaved differently from its own usual pattern.
    Behaviour,
}

impl AlertKind {
    /// The stored spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tracker => "tracker",
            Self::BadNetwork => "bad_network",
            Self::FakedDns => "faked_dns",
            Self::Unattributed => "unattributed",
            Self::Behaviour => "behaviour",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [
            Self::Tracker,
            Self::BadNetwork,
            Self::FakedDns,
            Self::Unattributed,
            Self::Behaviour,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == text)
    }
}

/// How much an alert matters (design spec §6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Worth knowing; never notified on its own.
    Info,
    /// Worth a look.
    Medium,
    /// Needs a look.
    High,
    /// Needs a look now.
    Critical,
}

impl Severity {
    /// The stored spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [Self::Info, Self::Medium, Self::High, Self::Critical]
            .into_iter()
            .find(|severity| severity.as_str() == text)
    }
}

/// An alert to save.
#[derive(Debug, Clone, PartialEq)]
pub struct NewAlert {
    /// Identifies the alert: a second alert with the same key is not saved
    /// (e.g. one per app, tracker and day).
    pub key: String,
    /// Identifies alerts like it, for "this is fine" (e.g. app and tracker);
    /// `None` if it cannot be allowed.
    pub allow_key: Option<String>,
    pub kind: AlertKind,
    pub severity: Severity,
    /// Executable file name.
    pub app_name: Option<String>,
    /// The program's full path.
    pub app_path: Option<String>,
    /// The domain or address concerned.
    pub target: Option<String>,
    /// More detail: a company, a listing, a count.
    pub detail: Option<String>,
    /// Why it was raised (behaviour alerts; empty for the others).
    pub reasons: Vec<Reason>,
}

/// A saved alert.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredAlert {
    pub id: i64,
    pub created: SystemTime,
    pub kind: AlertKind,
    pub severity: Severity,
    pub app_name: Option<String>,
    pub app_path: Option<String>,
    pub target: Option<String>,
    pub detail: Option<String>,
    /// Whether the user marked it as seen and fine.
    pub dismissed: bool,
    /// Whether "this is fine" can also stop alerts like it.
    pub can_allow: bool,
    /// Why it was raised (behaviour alerts; empty for the others).
    pub reasons: Vec<Reason>,
    /// How many more times the same behaviour was seen after the alert.
    pub seen_again: u32,
}

/// Reasons as stored: JSON text.
fn reasons_to_json(reasons: &[Reason]) -> String {
    let capped: Vec<Reason> = reasons.iter().cloned().map(Reason::capped).collect();
    serde_json::to_string(&capped).unwrap_or_else(|_| String::from("[]"))
}

/// Reasons from their stored text; text that cannot be read gives none.
fn reasons_from_json(text: &str) -> Vec<Reason> {
    serde_json::from_str(text).unwrap_or_default()
}

/// Schema version 5 (Whereabouts 0.3): alerts get reasons, and per-app
/// behaviour profiles are stored.
const SCHEMA_V5: &str = "
BEGIN;
CREATE TABLE alerts_v5 (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    allow_key TEXT,
    created INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('tracker', 'bad_network', 'faked_dns', 'unattributed', 'behaviour')),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'medium', 'high', 'critical')),
    app_name TEXT,
    app_path TEXT,
    target TEXT,
    detail TEXT,
    dismissed INTEGER NOT NULL DEFAULT 0,
    reasons TEXT NOT NULL DEFAULT '[]',
    seen_again INTEGER NOT NULL DEFAULT 0,
    updated INTEGER
) STRICT;
INSERT INTO alerts_v5 (id, key, allow_key, created, kind, severity, app_name, app_path, target, detail, dismissed)
    SELECT id, key, allow_key, created, kind, severity, app_name, app_path, target, detail, dismissed FROM alerts;
DROP TABLE alerts;
ALTER TABLE alerts_v5 RENAME TO alerts;
CREATE INDEX alerts_created ON alerts (created);
CREATE TABLE profiles (
    key TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    app_name TEXT NOT NULL,
    first_data INTEGER NOT NULL,
    learned_since INTEGER NOT NULL,
    last_data INTEGER NOT NULL,
    active_days INTEGER NOT NULL DEFAULT 0,
    last_active_day INTEGER,
    last_sha256 TEXT,
    last_publisher TEXT,
    goes_anywhere TEXT NOT NULL DEFAULT 'auto' CHECK (goes_anywhere IN ('auto', 'user_on', 'user_off')),
    reset_at INTEGER
) STRICT;
CREATE TABLE profile_items (
    key TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('domain', 'company', 'country', 'port')),
    value TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    seen_on_day INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('learned', 'allowed', 'pending')),
    PRIMARY KEY (key, kind, value)
) STRICT;
CREATE TABLE profile_hours (
    key TEXT NOT NULL,
    hour INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL,
    connections INTEGER NOT NULL,
    PRIMARY KEY (key, hour)
) STRICT;
UPDATE meta SET value = '5' WHERE key = 'schema_version';
COMMIT;
";

/// Schema version 4 (Whereabouts 0.2): alerts, and what the user said is
/// fine.
const SCHEMA_V4: &str = "
BEGIN;
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    allow_key TEXT,
    created INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('tracker', 'bad_network', 'faked_dns', 'unattributed')),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'medium', 'high', 'critical')),
    app_name TEXT,
    app_path TEXT,
    target TEXT,
    detail TEXT,
    dismissed INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX alerts_created ON alerts (created);
CREATE TABLE alert_allows (key TEXT PRIMARY KEY, created INTEGER NOT NULL) STRICT;
UPDATE meta SET value = '4' WHERE key = 'schema_version';
COMMIT;
";

/// How a program path is compared: Windows paths ignore case (ASCII
/// lowercase, the same as SQLite's `lower()`).
pub fn known_app_key(path: &str) -> String {
    path.to_ascii_lowercase()
}

/// Schema version 3 (Whereabouts 0.2): programs that have used the network,
/// so the first use of a new one can be announced. Filled from the saved
/// history when upgrading.
const SCHEMA_V3: &str = "
BEGIN;
CREATE TABLE known_apps (
    key TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    first_seen INTEGER NOT NULL
) STRICT;
INSERT OR IGNORE INTO known_apps (key, path, first_seen)
    SELECT lower(app_path), MIN(app_path), MIN(first_seen) FROM flows
    WHERE app_path IS NOT NULL GROUP BY lower(app_path);
UPDATE meta SET value = '3' WHERE key = 'schema_version';
COMMIT;
";

const SCHEMA_V2: &str = "
BEGIN;
CREATE TABLE rules (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('app', 'domain', 'address')),
    app_path TEXT,
    domain TEXT,
    ip TEXT,
    created INTEGER NOT NULL,
    CHECK ((kind = 'app' AND app_path IS NOT NULL AND domain IS NULL AND ip IS NULL)
        OR (kind = 'domain' AND domain IS NOT NULL AND ip IS NULL)
        OR (kind = 'address' AND ip IS NOT NULL AND domain IS NULL))
) STRICT;
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
UPDATE meta SET value = '2' WHERE key = 'schema_version';
COMMIT;
";

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

/// Columns of the CSV export, in order.
const EXPORT_COLUMNS: [&str; 18] = [
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

/// The CSV export's header line (without a line break).
pub fn csv_header() -> String {
    EXPORT_COLUMNS.join(",")
}

/// One page of the CSV export (see [`Store::export_page`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportPage {
    /// CSV lines, each ending in a line break.
    pub csv: String,
    /// How many flows the page holds.
    pub rows: u64,
    /// ID of the last flow in the page; `None` when there were no more.
    pub last_id: Option<i64>,
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
        assert_eq!(top[0].app_path.as_deref(), Some(r"C:\Apps\a.exe"));
    }

    #[test]
    fn programs_that_share_a_name_get_separate_totals() {
        let path = temp_db("same-name");
        let mut store = Store::open(&path, &key(7)).unwrap();
        let real = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
        let fake = r"C:\Users\me\AppData\Local\Temp\chrome.exe";
        let flow = |app_path: Option<&str>, secs: u64, sent: u64, signature: Signature| {
            let mut flow = record("chrome.exe", "one.example", secs, sent);
            flow.app_path = app_path.map(str::to_owned);
            flow.signature = Some(signature);
            flow
        };
        let google = || Signature::Signed {
            publisher: String::from("Google LLC"),
            via_catalog: false,
        };
        store
            .insert_flows(&[
                flow(Some(real), 100, 100, google()),
                // The same file, spelled with different case.
                flow(Some(&real.to_uppercase()), 200, 100, google()),
                flow(Some(fake), 300, 10, Signature::Unsigned),
                flow(None, 400, 1, Signature::Unsigned),
            ])
            .unwrap();

        let top = store.top_apps(at(0), 10).unwrap();
        assert_eq!(top.len(), 3, "{top:?}");
        assert!(top.iter().all(|app| app.app_name == "chrome.exe"));

        let real_path = top[0].app_path.as_deref().map(str::to_lowercase);
        assert_eq!(real_path, Some(real.to_lowercase()));
        assert_eq!(top[0].flows, 2);
        assert_eq!(top[0].bytes_sent, 200);
        assert_eq!(top[0].publisher.as_deref(), Some("Google LLC"));

        assert_eq!(top[1].app_path.as_deref(), Some(fake));
        assert_eq!(top[1].flows, 1);
        assert_eq!(top[1].bytes_sent, 10);
        assert_eq!(
            top[1].publisher, None,
            "the copy must not borrow Google's name"
        );

        // Flows saved without a path are totalled by name, on their own.
        assert_eq!(top[2].app_path, None);
        assert_eq!(top[2].bytes_sent, 1);
    }

    #[test]
    fn app_totals_name_the_most_recent_flow() {
        let path = temp_db("most-recent");
        let mut store = Store::open(&path, &key(7)).unwrap();
        let mut old = record("tool.exe", "one.example", 100, 10);
        old.signature = Some(Signature::Signed {
            publisher: String::from("Old Name Ltd"),
            via_catalog: false,
        });
        let new = record("tool.exe", "one.example", 200, 10);
        store.insert_flows(&[new, old]).unwrap();
        let top = store.top_apps(at(0), 10).unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].publisher.as_deref(), Some("Example Corp"));
        assert_eq!(top[0].flows, 2);
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
    fn rule_ids_are_never_used_twice() {
        let path = temp_db("rule-ids");
        let mut store = Store::open(&path, &key(7)).unwrap();
        let target = |n: u8| RuleTarget::Address {
            ip: std::net::IpAddr::from([203, 0, 113, n]),
            app: None,
        };
        let first = store.add_rule(&target(1), at(1000)).unwrap();
        let second = store.add_rule(&target(2), at(1001)).unwrap();
        assert!(store.remove_rule(second).unwrap());
        let third = store.add_rule(&target(3), at(1002)).unwrap();
        assert!(
            third > second,
            "the removed rule's ID is not given out again"
        );
        assert!(store.remove_rule(first).unwrap() && store.remove_rule(third).unwrap());
        // Also when every rule is gone.
        let fourth = store.add_rule(&target(4), at(1003)).unwrap();
        assert!(fourth > third);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rules_are_saved_listed_and_removed() {
        let path = temp_db("rules");
        let mut store = Store::open(&path, &key(7)).unwrap();
        let app = RuleTarget::App {
            path: String::from(r"C:\Apps\x.exe"),
        };
        let domain = RuleTarget::Domain {
            name: String::from("tracker.example.com"),
            app: None,
        };
        let address = RuleTarget::Address {
            ip: "203.0.113.5".parse().unwrap(),
            app: Some(String::from(r"C:\Apps\x.exe")),
        };
        let a = store.add_rule(&app, at(1000)).unwrap();
        let d = store.add_rule(&domain, at(1001)).unwrap();
        let i = store.add_rule(&address, at(1002)).unwrap();
        assert_eq!(
            store.add_rule(&domain, at(2000)).unwrap(),
            d,
            "no duplicates"
        );
        let rules = store.rules().unwrap();
        assert_eq!(
            rules
                .iter()
                .map(|r| (r.id, r.target.clone()))
                .collect::<Vec<_>>(),
            vec![(a, app), (d, domain.clone()), (i, address)]
        );
        assert_eq!(rules[1].created, at(1001));
        assert!(store.remove_rule(a).unwrap());
        assert!(!store.remove_rule(a).unwrap());
        drop(store);
        // Rules survive reopening, and deleting the history keeps them.
        let mut store = Store::open(&path, &key(7)).unwrap();
        store.wipe().unwrap();
        assert_eq!(store.rules().unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn settings_are_saved() {
        let path = temp_db("settings");
        let mut store = Store::open(&path, &key(8)).unwrap();
        assert_eq!(store.setting("blocking_paused").unwrap(), None);
        store.set_setting("blocking_paused", "true").unwrap();
        store.set_setting("blocking_paused", "false").unwrap();
        assert_eq!(
            store.setting("blocking_paused").unwrap().as_deref(),
            Some("false")
        );
        assert!(store.remove_setting("blocking_paused").unwrap());
        assert_eq!(store.setting("blocking_paused").unwrap(), None);
        assert!(!store.remove_setting("blocking_paused").unwrap());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    fn tracker_alert(app: &str, day: u64) -> NewAlert {
        NewAlert {
            key: format!("tracker|{app}|ads.example|{day}"),
            allow_key: Some(format!("tracker|{app}|ads.example")),
            kind: AlertKind::Tracker,
            severity: Severity::Info,
            app_name: Some(String::from("chat.exe")),
            app_path: Some(String::from(app)),
            target: Some(String::from("ads.example")),
            detail: Some(String::from("Example Ads")),
            reasons: Vec::new(),
        }
    }

    #[test]
    fn alerts_are_saved_once_per_key_and_this_is_fine_stops_them() {
        let path = temp_db("alerts");
        let mut store = Store::open(&path, &key(11)).unwrap();
        let first = store
            .add_alert(&tracker_alert(r"c:\a.exe", 1), at(10))
            .unwrap();
        assert!(first.is_some());
        assert_eq!(
            store
                .add_alert(&tracker_alert(r"c:\a.exe", 1), at(11))
                .unwrap(),
            None
        );
        store
            .add_alert(&tracker_alert(r"c:\b.exe", 1), at(12))
            .unwrap()
            .unwrap();
        let alerts = store.alerts(at(0), 10).unwrap();
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[1].kind, AlertKind::Tracker);
        assert!(alerts[1].can_allow && !alerts[1].dismissed);
        // "This is fine" for app a: no more alerts like it.
        assert!(store.dismiss_alert(first.unwrap(), true, at(13)).unwrap());
        assert_eq!(
            store
                .add_alert(&tracker_alert(r"c:\a.exe", 2), at(14))
                .unwrap(),
            None
        );
        assert!(
            store
                .add_alert(&tracker_alert(r"c:\b.exe", 2), at(15))
                .unwrap()
                .is_some()
        );
        assert!(!store.dismiss_alert(999, false, at(16)).unwrap());
        // Serious alerts come first even when info alerts fill the limit.
        for day in 10..20 {
            store
                .add_alert(&tracker_alert(r"c:.exe", day), at(20))
                .unwrap();
        }
        let serious = NewAlert {
            key: String::from("faked_dns|1"),
            allow_key: None,
            kind: AlertKind::FakedDns,
            severity: Severity::Medium,
            app_name: None,
            app_path: None,
            target: None,
            detail: None,
            reasons: Vec::new(),
        };
        store.add_alert(&serious, at(5)).unwrap().unwrap();
        let top = store.alerts(at(0), 3).unwrap();
        assert_eq!(top[0].kind, AlertKind::FakedDns);
        // Deleting the history deletes alerts, but keeps "this is fine".
        store.wipe().unwrap();
        assert!(store.alerts(at(0), 10).unwrap().is_empty());
        assert_eq!(
            store
                .add_alert(&tracker_alert(r"c:\a.exe", 3), at(17))
                .unwrap(),
            None
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn known_apps_are_remembered_once_and_deleted_with_the_history() {
        let path = temp_db("known");
        let mut store = Store::open(&path, &key(10)).unwrap();
        assert!(store.known_app_keys().unwrap().is_empty());
        assert!(store.add_known_app(r"C:\Apps\Chat.exe", at(1)).unwrap());
        assert!(
            !store.add_known_app(r"c:\apps\chat.EXE", at(2)).unwrap(),
            "case is ignored"
        );
        assert_eq!(
            store.known_app_keys().unwrap(),
            vec![String::from(r"c:\apps\chat.exe")]
        );
        store.wipe().unwrap();
        assert!(store.known_app_keys().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_version_1_database_is_upgraded_and_keeps_its_history() {
        let path = temp_db("upgrade");
        // A database as Whereabouts 0.1 left it.
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "key", key(9).sqlcipher_literal())
                .unwrap();
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;",
            )
            .unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            conn.execute(
                "INSERT INTO flows (app_name, app_path, signature_confirmed, protocol, remote_ip,                  remote_port, first_seen, last_seen, bytes_sent, bytes_received, connections)                  VALUES ('old.exe', ?1, 0, 'TCP', '203.0.113.1', 443, 1000, 1000, 1, 1, 1)",
                [r"C:\Old\Old.exe"],
            )
            .unwrap();
        }
        let mut store = Store::open(&path, &key(9)).unwrap();
        // Older versions used a rollback journal; it is switched over.
        assert_eq!(journal_mode(&store), "wal");
        // The programs in the history are known apps from the start.
        assert_eq!(
            store.known_app_keys().unwrap(),
            vec![String::from(r"c:\old\old.exe")]
        );
        store
            .insert_flows(&[record("old.exe", "example.com", 1000, 5)])
            .unwrap();
        assert_eq!(store.flow_count().unwrap(), 2);
        let version: String = store
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, "5");
        store
            .add_rule(
                &RuleTarget::App {
                    path: String::from(r"C:\x.exe"),
                },
                at(1),
            )
            .unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn export_pages_cover_every_flow_once() {
        let path = temp_db("pages");
        let mut store = Store::open(&path, &key(5)).unwrap();
        let records: Vec<FlowRecord> = (0..25)
            .map(|i| record(&format!("app{i}.exe"), "example.com", 1000 + i, i))
            .collect();
        store.insert_flows(&records).unwrap();

        let mut lines = Vec::new();
        let mut after = 0;
        let mut pages = 0;
        loop {
            let page = store.export_page(after, 7, usize::MAX).unwrap();
            let Some(last) = page.last_id else { break };
            assert!(page.rows <= 7);
            lines.extend(page.csv.lines().map(str::to_owned));
            after = last;
            pages += 1;
        }
        assert_eq!(pages, 4, "25 flows in pages of 7");
        assert_eq!(lines.len(), 25);
        for i in 0..25 {
            assert_eq!(
                lines
                    .iter()
                    .filter(|l| l.starts_with(&format!("app{i}.exe,")))
                    .count(),
                1,
                "app{i}.exe exactly once"
            );
        }

        // The whole export is the header plus the same lines.
        let mut out = Vec::new();
        assert_eq!(store.export_csv(&mut out).unwrap(), 25);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().next().unwrap(), csv_header());
        assert_eq!(text.lines().skip(1).collect::<Vec<_>>(), lines);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn export_pages_stop_at_the_size_limit_but_never_empty() {
        let path = temp_db("page-size");
        let mut store = Store::open(&path, &key(6)).unwrap();
        let records: Vec<FlowRecord> = (0..5)
            .map(|i| record("big.exe", "example.com", 1000 + i, i))
            .collect();
        store.insert_flows(&records).unwrap();
        // A limit smaller than one line still returns that one line.
        let page = store.export_page(0, 100, 1).unwrap();
        assert_eq!(page.rows, 1);
        let line = page.csv.len();
        // Room for about two lines: stops once the limit is reached.
        let page = store.export_page(0, 100, line + 1).unwrap();
        assert_eq!(page.rows, 2);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
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

    fn wal_of(path: &Path) -> PathBuf {
        let mut name = path.file_name().unwrap().to_owned();
        name.push("-wal");
        path.with_file_name(name)
    }

    fn journal_mode(store: &Store) -> String {
        store
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn saves_go_to_an_encrypted_write_ahead_log() {
        let path = temp_db("wal");
        let mut store = Store::open(&path, &key(7)).unwrap();
        assert_eq!(journal_mode(&store), "wal");
        store
            .insert_flows(&[record("secret-app.exe", "very-private.example", 1, 1)])
            .unwrap();
        // While the store is open, the save is (at least partly) only in
        // the log, and the log is as unreadable as the database.
        let log = std::fs::read(wal_of(&path)).unwrap();
        assert!(!log.is_empty(), "the save went to the log");
        for needle in [&b"secret-app"[..], b"very-private", b"CREATE TABLE"] {
            assert!(
                !log.windows(needle.len()).any(|w| w == needle),
                "{} readable in the log",
                String::from_utf8_lossy(needle)
            );
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_rollback_journal_can_still_be_chosen_for_comparisons() {
        let path = temp_db("rollback");
        let mut store = Store::open_with_journal(&path, &key(7), Journal::Rollback).unwrap();
        assert_eq!(journal_mode(&store), "delete");
        store
            .insert_flows(&[record("a.exe", "x.example", 1, 1)])
            .unwrap();
        assert!(!wal_of(&path).exists());
        drop(store);
        // Opening normally switches it to the write-ahead log.
        let store = Store::open(&path, &key(7)).unwrap();
        assert_eq!(journal_mode(&store), "wal");
        assert_eq!(store.flow_count().unwrap(), 1);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn readers_do_not_hold_up_saving() {
        let path = temp_db("readers");
        let mut writer = Store::open(&path, &key(7)).unwrap();
        writer
            .insert_flows(&[record("a.exe", "x.example", 1, 1)])
            .unwrap();
        // A pipe client's connection in the middle of reading.
        let reader = Store::open(&path, &key(7)).unwrap();
        reader.conn.execute_batch("BEGIN").unwrap();
        assert_eq!(reader.flow_count().unwrap(), 1);

        // With a rollback journal this save would wait for the reader (and
        // give up after the 5-second busy timeout).
        let started = std::time::Instant::now();
        writer
            .insert_flows(&[record("b.exe", "y.example", 2, 1)])
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        // The reader keeps its consistent view until it is done.
        assert_eq!(reader.flow_count().unwrap(), 1);
        reader.conn.execute_batch("COMMIT").unwrap();
        assert_eq!(reader.flow_count().unwrap(), 2);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn deleting_also_empties_the_log() {
        let path = temp_db("wipe-log");
        let mut store = Store::open(&path, &key(7)).unwrap();
        let reader = Store::open(&path, &key(7)).unwrap();
        for delete in [Store::delete_history, Store::wipe] {
            store
                .insert_flows(&[record("a.exe", "x.example", 1, 1)])
                .unwrap();
            assert_eq!(reader.flow_count().unwrap(), 1, "another connection read");
            assert!(std::fs::metadata(wal_of(&path)).unwrap().len() > 0);
            delete(&mut store).unwrap();
            // Still open, so the log file stays, but nothing is left in it.
            assert_eq!(std::fs::metadata(wal_of(&path)).unwrap().len(), 0);
            assert_eq!(store.flow_count().unwrap(), 0);
            assert_eq!(reader.flow_count().unwrap(), 0);
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn saved_flows_survive_a_crash_before_the_log_is_copied() {
        let path = temp_db("crash");
        let mut store = Store::open(&path, &key(7)).unwrap();
        store
            .insert_flows(&[record("a.exe", "x.example", 1, 1)])
            .unwrap();
        // The files as a crash would leave them: the save is still in the
        // log, not yet copied into the database.
        let copy = temp_db("crash-copy");
        std::fs::copy(&path, &copy).unwrap();
        std::fs::copy(wal_of(&path), wal_of(&copy)).unwrap();
        drop(store);
        let reopened = Store::open(&copy, &key(7)).unwrap();
        assert_eq!(reopened.flow_count().unwrap(), 1);
        drop(reopened);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(copy.parent().unwrap());
    }

    #[test]
    fn closing_copies_the_log_into_the_database_and_removes_it() {
        let path = temp_db("close");
        {
            let mut store = Store::open(&path, &key(7)).unwrap();
            store
                .insert_flows(&[record("a.exe", "x.example", 1, 1)])
                .unwrap();
        }
        assert!(!wal_of(&path).exists());
        let store = Store::open(&path, &key(7)).unwrap();
        assert_eq!(store.flow_count().unwrap(), 1);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn deleting_history_keeps_alerts_rules_apps_and_settings() {
        let path = temp_db("delete-history");
        let mut store = Store::open(&path, &key(7)).unwrap();
        store
            .insert_flows(&[
                record("a.exe", "x.example", 1, 1),
                record("b.exe", "y.example", 100 * 24 * 3600, 2),
            ])
            .unwrap();
        // Fold the older flow into an hourly total.
        store
            .apply_retention(at(100 * 24 * 3600), Retention::default())
            .unwrap();
        let hourly = |store: &Store| -> i64 {
            store
                .conn
                .query_row("SELECT count(*) FROM hourly", [], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(hourly(&store), 1);
        store.add_alert(&tracker_alert("a.exe", 1), at(5)).unwrap();
        store
            .add_rule(
                &RuleTarget::App {
                    path: String::from("C:/Apps/a.exe"),
                },
                at(5),
            )
            .unwrap();
        store.add_known_app("C:/Apps/a.exe", at(5)).unwrap();
        store.set_setting("save_history", "false").unwrap();

        store.delete_history().unwrap();
        assert_eq!(store.flow_count().unwrap(), 0);
        assert_eq!(hourly(&store), 0);
        assert_eq!(store.alerts(at(0), 10).unwrap().len(), 1);
        assert_eq!(store.rules().unwrap().len(), 1);
        assert_eq!(store.known_app_keys().unwrap().len(), 1);
        assert_eq!(
            store.setting("save_history").unwrap().as_deref(),
            Some("false")
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
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

    fn behaviour_alert(reasons: Vec<Reason>) -> NewAlert {
        NewAlert {
            key: String::from("behaviour|c:\\a.exe|1"),
            allow_key: None,
            kind: AlertKind::Behaviour,
            severity: Severity::Medium,
            app_name: Some(String::from("a.exe")),
            app_path: Some(String::from(r"C:\a.exe")),
            target: None,
            detail: None,
            reasons,
        }
    }

    fn country(code: &str) -> Reason {
        Reason {
            signal: Signal::NewCountry,
            value: Some(code.to_owned()),
            observed: None,
            usual: None,
            count: None,
        }
    }

    #[test]
    fn v4_alerts_survive_v5_migration() {
        let path = temp_db("v4-to-v5");
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "key", key(3).sqlcipher_literal())
                .unwrap();
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;",
            )
            .unwrap();
            for schema in [SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4] {
                conn.execute_batch(schema).unwrap();
            }
            conn.execute(
                "INSERT INTO alerts (key, allow_key, created, kind, severity, app_name, \
                 app_path, target, detail, dismissed) VALUES ('k', 'ak', 5000, 'tracker', \
                 'info', 'a.exe', 'c:\\a.exe', 'ads.example', 'Example Ads', 1)",
                [],
            )
            .unwrap();
        }
        let store = Store::open(&path, &key(3)).unwrap();
        let version: String = store
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, "5");
        let alerts = store.alerts(UNIX_EPOCH, 10).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::Tracker);
        assert_eq!(alerts[0].severity, Severity::Info);
        assert!(alerts[0].dismissed);
        assert!(alerts[0].can_allow);
        assert!(alerts[0].reasons.is_empty());
        assert_eq!(alerts[0].seen_again, 0);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn behaviour_alert_round_trips_reasons() {
        let path = temp_db("behaviour-alert");
        let mut store = Store::open(&path, &key(4)).unwrap();
        let reasons = vec![country("RU")];
        store
            .add_alert(&behaviour_alert(reasons.clone()), at(10))
            .unwrap()
            .unwrap();
        let alerts = store.alerts(UNIX_EPOCH, 10).unwrap();
        assert_eq!(alerts[0].kind, AlertKind::Behaviour);
        assert_eq!(alerts[0].reasons, reasons);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn is_allowed_after_this_is_fine() {
        let path = temp_db("is-allowed");
        let mut store = Store::open(&path, &key(7)).unwrap();
        let mut alert = behaviour_alert(vec![country("RU")]);
        alert.allow_key = Some(String::from("behaviour|c:\\a.exe|beaconing|c2.example"));
        let id = store.add_alert(&alert, at(10)).unwrap().unwrap();
        let allow = alert.allow_key.as_deref().unwrap();
        assert!(!store.is_allowed(allow).unwrap());
        assert!(store.dismiss_alert(id, true, at(11)).unwrap());
        assert!(store.is_allowed(allow).unwrap());
        assert!(
            !store
                .is_allowed("behaviour|c:\\a.exe|beaconing|other")
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn update_alert_merges_reasons_and_keeps_higher_severity() {
        let path = temp_db("update-alert");
        let mut store = Store::open(&path, &key(6)).unwrap();
        let id = store
            .add_alert(&behaviour_alert(vec![country("RU")]), at(10))
            .unwrap()
            .unwrap();
        let spike = Reason {
            signal: Signal::UploadSpike,
            value: None,
            observed: Some(3.4e8),
            usual: Some(5e6),
            count: None,
        };
        assert!(
            store
                .update_alert(id, &[spike], Severity::High, 2, at(20))
                .unwrap()
        );
        let alert = &store.alerts(UNIX_EPOCH, 10).unwrap()[0];
        assert_eq!(alert.reasons.len(), 2);
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.seen_again, 2);
        assert!(
            store
                .update_alert(id, &[country("RU")], Severity::Medium, 3, at(30))
                .unwrap()
        );
        let alert = &store.alerts(UNIX_EPOCH, 10).unwrap()[0];
        assert_eq!(alert.reasons.len(), 2);
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.seen_again, 3);
        assert!(
            !store
                .update_alert(999, &[], Severity::Info, 0, at(40))
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn unreadable_or_oversized_reasons_are_handled() {
        let path = temp_db("reason-edges");
        let mut store = Store::open(&path, &key(8)).unwrap();
        let long = Reason {
            value: Some("a".repeat(400)),
            ..country("RU")
        };
        let id = store
            .add_alert(&behaviour_alert(vec![long]), at(10))
            .unwrap()
            .unwrap();
        let alert = &store.alerts(UNIX_EPOCH, 10).unwrap()[0];
        assert_eq!(
            alert.reasons[0].value.as_ref().map(|v| v.chars().count()),
            Some(REASON_VALUE_MAX_CHARS)
        );
        store
            .conn
            .execute("UPDATE alerts SET reasons = 'not json' WHERE id = ?1", [id])
            .unwrap();
        assert!(store.alerts(UNIX_EPOCH, 10).unwrap()[0].reasons.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn wipe_clears_profiles_but_delete_history_keeps_them() {
        let path = temp_db("wipe-profiles");
        let mut store = Store::open(&path, &key(2)).unwrap();
        store
            .conn
            .execute_batch(
                "INSERT INTO profiles (key, path, app_name, first_data, learned_since, last_data) \
                 VALUES ('c:\\a.exe', 'C:\\a.exe', 'a.exe', 1, 1, 1); \
                 INSERT INTO profile_items (key, kind, value, first_seen, last_seen, seen_on_day, state) \
                 VALUES ('c:\\a.exe', 'domain', 'example.com', 1, 1, 1, 'learned'); \
                 INSERT INTO profile_hours (key, hour, bytes_sent, bytes_received, connections) \
                 VALUES ('c:\\a.exe', 1, 1, 1, 1);",
            )
            .unwrap();
        let counts = |store: &Store| -> Vec<i64> {
            ["profiles", "profile_items", "profile_hours"]
                .iter()
                .map(|table| {
                    store
                        .conn
                        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                            row.get(0)
                        })
                        .unwrap()
                })
                .collect()
        };
        store.delete_history().unwrap();
        assert_eq!(counts(&store), vec![1, 1, 1]);
        store.wipe().unwrap();
        assert_eq!(counts(&store), vec![0, 0, 0]);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
