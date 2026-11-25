//! Per-app behaviour profiles: what each program normally talks to, and
//! when. The tables are created by the layout version 5 migration.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};

use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension, Row, params};
use whereabouts_core::dns::LabelSource;
use whereabouts_core::flow::OVERFLOW_REMOTE;

use super::{Store, StoreError, UNIX_EPOCH, clamp, from_unix_ms, known_app_key, to_u64, unix_ms};

/// Most items of one kind (domains, companies, ...) kept per app.
pub const MAX_ITEMS_PER_KIND: usize = 5_000;

/// An item is forgotten once the app has been active on this many days
/// without using it.
pub const ITEM_ACTIVE_DAYS: u32 = 30;

/// How long the per-hour traffic totals are kept.
pub const PROFILE_HOURS_KEPT: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// A profile is deleted after this long without any traffic from the app.
pub const PROFILE_IDLE_LIMIT: Duration = Duration::from_secs(180 * 24 * 60 * 60);

const SECS_PER_HOUR: u64 = 3_600;
const SECS_PER_HOUR_I64: i64 = 3_600;
const SECS_PER_DAY: i64 = 86_400;

/// Whether an app is expected to talk to anywhere (a web browser).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoesAnywhere {
    /// Decided automatically from the app and its signature.
    Auto,
    /// The user said this app goes anywhere.
    UserOn,
    /// The user said this app does not go anywhere.
    UserOff,
}

impl GoesAnywhere {
    /// The stored spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::UserOn => "user_on",
            Self::UserOff => "user_off",
        }
    }

    /// Reads the stored spelling.
    pub fn parse(text: &str) -> Option<Self> {
        [Self::Auto, Self::UserOn, Self::UserOff]
            .into_iter()
            .find(|value| value.as_str() == text)
    }
}

/// What kind of destination a profile item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemKind {
    /// A registrable domain.
    Domain,
    /// The company that owns the network.
    Company,
    /// A country code.
    Country,
    /// A remote port.
    Port,
}

impl ItemKind {
    /// The stored spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Company => "company",
            Self::Country => "country",
            Self::Port => "port",
        }
    }

    /// Reads the stored spelling.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.as_str() == text)
    }

    const ALL: [Self; 4] = [Self::Domain, Self::Company, Self::Country, Self::Port];
}

/// How an item came to be in a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemState {
    /// Seen during normal behaviour.
    Learned,
    /// The user said this is fine.
    Allowed,
    /// Raised an alert and is not part of the normal profile.
    Pending,
}

impl ItemState {
    /// The stored spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Learned => "learned",
            Self::Allowed => "allowed",
            Self::Pending => "pending",
        }
    }

    /// Reads the stored spelling.
    pub fn parse(text: &str) -> Option<Self> {
        [Self::Learned, Self::Allowed, Self::Pending]
            .into_iter()
            .find(|value| value.as_str() == text)
    }
}

/// The summary line of one app's profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRow {
    /// The app's key (`known_app_key` of its path).
    pub key: String,
    /// The program path.
    pub path: String,
    /// The program name.
    pub app_name: String,
    /// When traffic from the app was first seen.
    pub first_data: SystemTime,
    /// When learning started (changes on reset).
    pub learned_since: SystemTime,
    /// When traffic from the app was last seen.
    pub last_data: SystemTime,
    /// Local days on which the app had traffic.
    pub active_days: u32,
    /// The last local day number counted in `active_days`.
    pub last_active_day: Option<i64>,
    /// Hash of the program file when last seen.
    pub last_sha256: Option<String>,
    /// Signing publisher when last seen.
    pub last_publisher: Option<String>,
    /// Whether the app is expected to go anywhere.
    pub goes_anywhere: GoesAnywhere,
    /// When the user last reset the profile.
    pub reset_at: Option<SystemTime>,
}

/// One destination in a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileItem {
    /// What the value is.
    pub kind: ItemKind,
    /// The domain, company, country code or port.
    pub value: String,
    /// When the app first used it.
    pub first_seen: SystemTime,
    /// When the app last used it.
    pub last_seen: SystemTime,
    /// The profile's `active_days` when the item was last seen.
    pub seen_on_day: u32,
    /// How the item came to be here.
    pub state: ItemState,
}

/// Traffic totals for one hour (hour number since the Unix epoch, UTC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HourRow {
    /// Unix hour number.
    pub hour: i64,
    /// Bytes sent in the hour.
    pub bytes_sent: u64,
    /// Bytes received in the hour.
    pub bytes_received: u64,
    /// Connections seen in the hour.
    pub connections: u64,
}

/// A whole profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredProfile {
    /// The summary line.
    pub row: ProfileRow,
    /// The destinations.
    pub items: Vec<ProfileItem>,
    /// The per-hour totals, oldest first.
    pub hours: Vec<HourRow>,
}

/// How much [`Store::expire_profiles`] deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProfileExpiry {
    /// Items deleted.
    pub items: u64,
    /// Hour rows deleted.
    pub hours: u64,
    /// Whole profiles deleted.
    pub profiles: u64,
}

const ROW_COLUMNS: &str = "key, path, app_name, first_data, learned_since, last_data, \
     active_days, last_active_day, last_sha256, last_publisher, goes_anywhere, reset_at";

fn bad_value(column: usize, text: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        Type::Text,
        format!("unknown stored value {text:?}").into(),
    )
}

fn read_row(row: &Row<'_>) -> rusqlite::Result<ProfileRow> {
    let goes: String = row.get(10)?;
    Ok(ProfileRow {
        key: row.get(0)?,
        path: row.get(1)?,
        app_name: row.get(2)?,
        first_data: from_unix_ms(row.get(3)?),
        learned_since: from_unix_ms(row.get(4)?),
        last_data: from_unix_ms(row.get(5)?),
        active_days: u32::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
        last_active_day: row.get(7)?,
        last_sha256: row.get(8)?,
        last_publisher: row.get(9)?,
        goes_anywhere: GoesAnywhere::parse(&goes).ok_or_else(|| bad_value(10, &goes))?,
        reset_at: row.get::<_, Option<i64>>(11)?.map(from_unix_ms),
    })
}

fn read_item(row: &Row<'_>) -> rusqlite::Result<ProfileItem> {
    let kind: String = row.get(0)?;
    let state: String = row.get(5)?;
    Ok(ProfileItem {
        kind: ItemKind::parse(&kind).ok_or_else(|| bad_value(0, &kind))?,
        value: row.get(1)?,
        first_seen: from_unix_ms(row.get(2)?),
        last_seen: from_unix_ms(row.get(3)?),
        seen_on_day: u32::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
        state: ItemState::parse(&state).ok_or_else(|| bad_value(5, &state))?,
    })
}

/// Runs a DELETE and returns how many rows it removed.
fn delete(conn: &Connection, sql: &str, params: impl rusqlite::Params) -> Result<u64, StoreError> {
    Ok(u64::try_from(conn.execute(sql, params)?).unwrap_or(0))
}

/// Writes a profile's summary line, replacing any earlier one.
fn write_row(conn: &Connection, row: &ProfileRow) -> Result<(), StoreError> {
    conn.execute(
        &format!(
            "INSERT OR REPLACE INTO profiles ({ROW_COLUMNS}) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
        ),
        params![
            row.key,
            row.path,
            row.app_name,
            unix_ms(row.first_data),
            unix_ms(row.learned_since),
            unix_ms(row.last_data),
            i64::from(row.active_days),
            row.last_active_day,
            row.last_sha256,
            row.last_publisher,
            row.goes_anywhere.as_str(),
            row.reset_at.map(unix_ms),
        ],
    )?;
    Ok(())
}

/// Upserts items and trims each kind to [`MAX_ITEMS_PER_KIND`]; see
/// [`Store::save_items`].
fn write_items(
    conn: &Connection,
    key: &str,
    items: &[ProfileItem],
    keep_state: bool,
) -> Result<(), StoreError> {
    let mut upsert = conn.prepare_cached(
        "INSERT INTO profile_items \
           (key, kind, value, first_seen, last_seen, seen_on_day, state) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
         ON CONFLICT (key, kind, value) DO UPDATE SET \
           first_seen = MIN(first_seen, excluded.first_seen), \
           last_seen = MAX(last_seen, excluded.last_seen), \
           seen_on_day = MAX(seen_on_day, excluded.seen_on_day), \
           state = CASE WHEN ?8 OR state = 'allowed' THEN state ELSE excluded.state END",
    )?;
    for item in items {
        upsert.execute(params![
            key,
            item.kind.as_str(),
            item.value,
            unix_ms(item.first_seen),
            unix_ms(item.last_seen),
            i64::from(item.seen_on_day),
            item.state.as_str(),
            keep_state,
        ])?;
    }
    let mut counted =
        conn.prepare_cached("SELECT COUNT(*) FROM profile_items WHERE key = ?1 AND kind = ?2")?;
    let mut evict = conn.prepare_cached(
        "DELETE FROM profile_items WHERE rowid IN ( \
           SELECT rowid FROM profile_items \
           WHERE key = ?1 AND kind = ?2 AND state != 'allowed' \
           ORDER BY last_seen ASC, rowid ASC LIMIT ?3)",
    )?;
    for kind in ItemKind::ALL {
        let total: i64 = counted.query_row(params![key, kind.as_str()], |r| r.get(0))?;
        let excess = total - clamp(MAX_ITEMS_PER_KIND as u64);
        if excess > 0 {
            evict.execute(params![key, kind.as_str(), excess])?;
        }
    }
    Ok(())
}

/// Adds traffic to the per-hour totals; see [`Store::add_hours`].
fn write_hours(conn: &Connection, key: &str, hours: &[HourRow]) -> Result<(), StoreError> {
    let mut add = conn.prepare_cached(
        "INSERT INTO profile_hours (key, hour, bytes_sent, bytes_received, connections) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT (key, hour) DO UPDATE SET \
           bytes_sent = MIN(bytes_sent + excluded.bytes_sent, 9223372036854775807), \
           bytes_received = MIN(bytes_received + excluded.bytes_received, 9223372036854775807), \
           connections = MIN(connections + excluded.connections, 9223372036854775807)",
    )?;
    for hour in hours {
        add.execute(params![
            key,
            hour.hour,
            clamp(hour.bytes_sent),
            clamp(hour.bytes_received),
            clamp(hour.connections),
        ])?;
    }
    Ok(())
}

/// Setting that remembers how far the saved history has been turned into
/// profiles: the ID of the last flow processed, or `"done"`.
pub const BACKFILL_SETTING: &str = "profiles_backfilled";

const BACKFILL_DONE: &str = "done";

/// A flow that spans more hours than this is spread over its last hours
/// only, so a corrupt row cannot make a huge number of hour rows.
const MAX_SPREAD_HOURS: i64 = 24 * 366;

/// How far [`Store::backfill_profiles`] got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackfillProgress {
    /// Flows read in this call (including ones without a program path).
    pub flows_read: u64,
    /// Whether every saved flow has now been processed.
    pub done: bool,
}

/// Where a saved flow went, as [`Store::backfill_profiles`] hands it to the
/// caller's rule for what a profile learns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackfillFlow<'a> {
    /// The remote address (unspecified if the saved text is not one).
    pub remote_ip: IpAddr,
    /// The remote port.
    pub remote_port: u16,
    /// The saved domain name (for web browsers, already the registrable
    /// domain).
    pub domain: Option<&'a str>,
    /// How the domain name was learned.
    pub domain_source: Option<LabelSource>,
}

/// What a behaviour profile learns about where a flow went. Each value
/// becomes a profile item of its kind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestinationFacts {
    /// The registrable domain.
    pub domain: Option<String>,
    /// The company that owns the remote network.
    pub company: Option<String>,
    /// The remote country code.
    pub country: Option<String>,
}

/// The columns of a saved flow that profiles are built from.
struct SavedFlow {
    id: i64,
    path: Option<String>,
    app_name: String,
    sha256: Option<String>,
    publisher: Option<String>,
    domain: Option<String>,
    domain_source: Option<LabelSource>,
    remote_ip: IpAddr,
    port: i64,
    first_ms: i64,
    last_ms: i64,
    sent: u64,
    received: u64,
    connections: u64,
}

/// What a backfill batch has learned about one app so far.
struct Learning {
    row: ProfileRow,
    items: HashMap<(ItemKind, String), ProfileItem>,
    hours: BTreeMap<i64, HourRow>,
    /// When the SHA-256 and publisher in `row` were seen.
    sha_at: Option<SystemTime>,
    publisher_at: Option<SystemTime>,
}

impl Learning {
    fn new(row: ProfileRow) -> Self {
        let known = Some(row.last_data);
        Self {
            sha_at: row.last_sha256.as_ref().and(known),
            publisher_at: row.last_publisher.as_ref().and(known),
            row,
            items: HashMap::new(),
            hours: BTreeMap::new(),
        }
    }

    /// Adds one saved flow; `facts` is what the caller's rule learned about
    /// where it went.
    fn add_flow(&mut self, flow: &SavedFlow, facts: &DestinationFacts, local_offset_secs: i32) {
        let first = from_unix_ms(flow.first_ms);
        let last = from_unix_ms(flow.last_ms);
        let row = &mut self.row;
        row.first_data = row.first_data.min(first);
        row.learned_since = row.learned_since.min(first);
        row.last_data = row.last_data.max(last);
        self.spread_over_hours(flow);
        // A process's flow-limit overflow went to many places: its bytes
        // count (so many flows cannot hide an upload), but no destination
        // is learned from it, as with live traffic.
        if flow.is_overflow() {
            return;
        }

        let row = &mut self.row;
        if let Some(sha) = &flow.sha256
            && self.sha_at.is_none_or(|at| last >= at)
        {
            row.last_sha256 = Some(sha.clone());
            self.sha_at = Some(last);
        }
        if let Some(publisher) = &flow.publisher
            && self.publisher_at.is_none_or(|at| last >= at)
        {
            row.last_publisher = Some(publisher.clone());
            self.publisher_at = Some(last);
        }

        // A day only counts when it is later than the last one counted.
        let day = (flow.first_ms.div_euclid(1_000) + i64::from(local_offset_secs))
            .div_euclid(SECS_PER_DAY);
        if row.last_active_day.is_none_or(|seen| day > seen) {
            row.active_days = row.active_days.saturating_add(1);
            row.last_active_day = Some(day);
        }
        let seen_on_day = row.active_days;

        let port = flow.port.to_string();
        let values = [
            (ItemKind::Domain, facts.domain.as_deref()),
            (ItemKind::Company, facts.company.as_deref()),
            (ItemKind::Country, facts.country.as_deref()),
            (ItemKind::Port, Some(port.as_str())),
        ];
        for (kind, value) in values {
            let Some(value) = value.filter(|v| !v.is_empty()) else {
                continue;
            };
            let item = self
                .items
                .entry((kind, value.to_owned()))
                .or_insert_with(|| ProfileItem {
                    kind,
                    value: value.to_owned(),
                    first_seen: first,
                    last_seen: last,
                    seen_on_day,
                    state: ItemState::Learned,
                });
            item.first_seen = item.first_seen.min(first);
            item.last_seen = item.last_seen.max(last);
            item.seen_on_day = item.seen_on_day.max(seen_on_day);
        }
    }

    /// Splits the flow's traffic evenly over the UTC hours it covers; the
    /// last hour gets the remainder so the totals stay exact.
    fn spread_over_hours(&mut self, flow: &SavedFlow) {
        let hour_of = |ms: i64| ms.div_euclid(1_000).div_euclid(SECS_PER_HOUR_I64);
        let last_hour = hour_of(flow.last_ms.max(flow.first_ms));
        let first_hour = hour_of(flow.first_ms).max(last_hour - MAX_SPREAD_HOURS + 1);
        let count = u64::try_from(last_hour - first_hour + 1).unwrap_or(1);
        for (index, hour) in (first_hour..=last_hour).enumerate() {
            let is_last = index as u64 + 1 == count;
            let share = |total: u64| total / count + if is_last { total % count } else { 0 };
            let row = self.hours.entry(hour).or_insert(HourRow {
                hour,
                bytes_sent: 0,
                bytes_received: 0,
                connections: 0,
            });
            row.bytes_sent = row.bytes_sent.saturating_add(share(flow.sent));
            row.bytes_received = row.bytes_received.saturating_add(share(flow.received));
            row.connections = row.connections.saturating_add(share(flow.connections));
        }
    }
}

impl SavedFlow {
    /// Whether this is a process's flow-limit overflow row ("many
    /// destinations"), saved with the overflow's remote address.
    fn is_overflow(&self) -> bool {
        self.remote_ip == OVERFLOW_REMOTE.ip() && self.port == i64::from(OVERFLOW_REMOTE.port())
    }

    /// The flow as the caller's rule sees it.
    fn destination(&self) -> BackfillFlow<'_> {
        BackfillFlow {
            remote_ip: self.remote_ip,
            remote_port: u16::try_from(self.port).unwrap_or(0),
            domain: self.domain.as_deref(),
            domain_source: self.domain_source,
        }
    }
}

/// How a saved domain name was learned, from its stored spelling.
fn label_source(text: &str) -> Option<LabelSource> {
    match text {
        "verified" => Some(LabelSource::Verified),
        "unverified" => Some(LabelSource::Unverified),
        "inferred" => Some(LabelSource::Inferred),
        _ => None,
    }
}

fn read_flow(row: &Row<'_>) -> rusqlite::Result<SavedFlow> {
    Ok(SavedFlow {
        id: row.get(0)?,
        path: row.get(1)?,
        app_name: row.get(2)?,
        sha256: row.get(3)?,
        publisher: row.get(4)?,
        domain: row.get(5)?,
        domain_source: row
            .get::<_, Option<String>>(6)?
            .as_deref()
            .and_then(label_source),
        remote_ip: row
            .get::<_, String>(7)?
            .parse()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        port: row.get(8)?,
        first_ms: row.get(9)?,
        last_ms: row.get(10)?,
        sent: to_u64(row.get(11)?),
        received: to_u64(row.get(12)?),
        connections: to_u64(row.get(13)?),
    })
}

impl Store {
    /// Reads one app's whole profile, or `None` if it has none.
    pub fn profile(&self, key: &str) -> Result<Option<StoredProfile>, StoreError> {
        let row = self
            .conn
            .query_row(
                &format!("SELECT {ROW_COLUMNS} FROM profiles WHERE key = ?1"),
                [key],
                read_row,
            )
            .optional()?;
        let Some(row) = row else {
            return Ok(None);
        };
        let items = self
            .conn
            .prepare(
                "SELECT kind, value, first_seen, last_seen, seen_on_day, state \
                 FROM profile_items WHERE key = ?1 ORDER BY kind, value",
            )?
            .query_map([key], read_item)?
            .collect::<Result<Vec<_>, _>>()?;
        let hours = self
            .conn
            .prepare(
                "SELECT hour, bytes_sent, bytes_received, connections \
                 FROM profile_hours WHERE key = ?1 ORDER BY hour",
            )?
            .query_map([key], |r| {
                Ok(HourRow {
                    hour: r.get(0)?,
                    bytes_sent: to_u64(r.get(1)?),
                    bytes_received: to_u64(r.get(2)?),
                    connections: to_u64(r.get(3)?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(StoredProfile { row, items, hours }))
    }

    /// Reads the summary line of every profile.
    pub fn profile_rows(&self) -> Result<Vec<ProfileRow>, StoreError> {
        let rows = self
            .conn
            .prepare(&format!("SELECT {ROW_COLUMNS} FROM profiles ORDER BY key"))?
            .query_map([], read_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Saves a profile's summary line, replacing any earlier one. Every
    /// column is written as given.
    pub fn save_profile_row(&mut self, row: &ProfileRow) -> Result<(), StoreError> {
        let transaction = self.conn.transaction()?;
        write_row(&transaction, row)?;
        transaction.commit()?;
        Ok(())
    }

    /// Saves items: new ones are added. Known ones merge: the earliest
    /// `first_seen`, the latest `last_seen` and the highest `seen_on_day`
    /// win, so a stale copy cannot move an item back in time. The state is
    /// replaced, except that an `allowed` item stays allowed (only
    /// [`Store::set_item_state`] changes it). Then
    /// each kind is trimmed to [`MAX_ITEMS_PER_KIND`] by dropping the items
    /// seen longest ago. Allowed items are never dropped.
    pub fn save_items(&mut self, key: &str, items: &[ProfileItem]) -> Result<(), StoreError> {
        let transaction = self.conn.transaction()?;
        write_items(&transaction, key, items, false)?;
        transaction.commit()?;
        Ok(())
    }

    /// Adds traffic to the per-hour totals (existing hours are added to, not
    /// replaced).
    pub fn add_hours(&mut self, key: &str, hours: &[HourRow]) -> Result<(), StoreError> {
        let transaction = self.conn.transaction()?;
        write_hours(&transaction, key, hours)?;
        transaction.commit()?;
        Ok(())
    }

    /// Changes the state of one item. Returns `false` if there is no such
    /// item.
    pub fn set_item_state(
        &mut self,
        key: &str,
        kind: ItemKind,
        value: &str,
        state: ItemState,
    ) -> Result<bool, StoreError> {
        let transaction = self.conn.transaction()?;
        let changed = transaction.execute(
            "UPDATE profile_items SET state = ?4 WHERE key = ?1 AND kind = ?2 AND value = ?3",
            params![key, kind.as_str(), value, state.as_str()],
        )?;
        transaction.commit()?;
        Ok(changed > 0)
    }

    /// Changes whether an app is expected to go anywhere. Returns `false` if
    /// there is no such profile.
    pub fn set_goes_anywhere(
        &mut self,
        key: &str,
        value: GoesAnywhere,
    ) -> Result<bool, StoreError> {
        let transaction = self.conn.transaction()?;
        let changed = transaction.execute(
            "UPDATE profiles SET goes_anywhere = ?2 WHERE key = ?1",
            params![key, value.as_str()],
        )?;
        transaction.commit()?;
        Ok(changed > 0)
    }

    /// Forgets what was learned about an app and starts learning again from
    /// `now`. The goes-anywhere choice is kept. Returns `false` if there is
    /// no such profile.
    pub fn reset_profile(&mut self, key: &str, now: SystemTime) -> Result<bool, StoreError> {
        let transaction = self.conn.transaction()?;
        let ms = unix_ms(now);
        let changed = transaction.execute(
            "UPDATE profiles SET first_data = ?2, learned_since = ?2, active_days = 0, \
             reset_at = ?2 WHERE key = ?1",
            params![key, ms],
        )?;
        if changed > 0 {
            transaction.execute("DELETE FROM profile_items WHERE key = ?1", [key])?;
            transaction.execute("DELETE FROM profile_hours WHERE key = ?1", [key])?;
        }
        transaction.commit()?;
        Ok(changed > 0)
    }

    /// Deletes what has aged out: items the app has not used in
    /// [`ITEM_ACTIVE_DAYS`] active days, hours older than
    /// [`PROFILE_HOURS_KEPT`], and whole profiles with no traffic for
    /// [`PROFILE_IDLE_LIMIT`] (with their items and hours, which are
    /// included in the counts).
    pub fn expire_profiles(&mut self, now: SystemTime) -> Result<ProfileExpiry, StoreError> {
        let transaction = self.conn.transaction()?;
        let mut expiry = ProfileExpiry::default();

        let idle_before = unix_ms(now.checked_sub(PROFILE_IDLE_LIMIT).unwrap_or(UNIX_EPOCH));
        let idle = "SELECT key FROM profiles WHERE last_data < ?1";
        expiry.items += delete(
            &transaction,
            &format!("DELETE FROM profile_items WHERE key IN ({idle})"),
            [idle_before],
        )?;
        expiry.hours += delete(
            &transaction,
            &format!("DELETE FROM profile_hours WHERE key IN ({idle})"),
            [idle_before],
        )?;
        expiry.profiles = delete(
            &transaction,
            "DELETE FROM profiles WHERE last_data < ?1",
            [idle_before],
        )?;

        // Active days, not calendar days: a quiet month does not age items.
        // A `seen_on_day` ahead of `active_days` (after a reset) never expires.
        expiry.items += delete(
            &transaction,
            "DELETE FROM profile_items WHERE EXISTS ( \
               SELECT 1 FROM profiles p WHERE p.key = profile_items.key \
               AND p.active_days > profile_items.seen_on_day \
               AND p.active_days - profile_items.seen_on_day >= ?1)",
            [i64::from(ITEM_ACTIVE_DAYS)],
        )?;

        let cutoff_hour = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.saturating_sub(PROFILE_HOURS_KEPT).as_secs() / SECS_PER_HOUR)
            .unwrap_or(0);
        expiry.hours += delete(
            &transaction,
            "DELETE FROM profile_hours WHERE hour < ?1",
            [clamp(cutoff_hour)],
        )?;

        transaction.commit()?;
        Ok(expiry)
    }

    /// Builds profiles from the saved flows, a batch at a time, so the first
    /// start after an upgrade can learn from the history without a long
    /// stall. Call it until it reports `done`. Each call reads up to `batch`
    /// flows after the last one processed and saves the profile changes and
    /// its place in one transaction, so an interrupted call is not counted
    /// twice. Flows without a program path are skipped. `local_offset_secs`
    /// is the local time zone's offset from UTC, used to count active days.
    ///
    /// `facts` is the caller's rule for what a profile learns about where a
    /// flow went: the same rule live learning uses, so a profile built from
    /// history matches one built live. A process's flow-limit overflow row
    /// adds its bytes to the app's hours, but no destination.
    ///
    /// Items that already exist keep their state (a pending warning stays
    /// pending); flows from before a profile's reset are ignored.
    ///
    /// There is no upper flow ID: it reads to the end of `flows`, including
    /// flows saved while it runs. So it must reach `done` before live learning
    /// writes profiles; the caller enforces this, otherwise flows could be
    /// counted twice.
    pub fn backfill_profiles(
        &mut self,
        batch: usize,
        local_offset_secs: i32,
        facts: impl Fn(&BackfillFlow<'_>) -> DestinationFacts,
    ) -> Result<BackfillProgress, StoreError> {
        let after = match self.setting(BACKFILL_SETTING)?.as_deref() {
            Some(BACKFILL_DONE) => {
                return Ok(BackfillProgress {
                    flows_read: 0,
                    done: true,
                });
            }
            Some(text) => text.parse::<i64>().map_err(|_| bad_value(0, text))?,
            None => 0,
        };
        let batch = batch.max(1);

        let transaction = self.conn.transaction()?;
        let mut flows = transaction
            .prepare(
                "SELECT id, app_path, app_name, app_sha256, publisher, domain, domain_source, \
                        remote_ip, remote_port, first_seen, last_seen, bytes_sent, bytes_received, \
                        connections \
                 FROM flows WHERE id > ?1 ORDER BY id LIMIT ?2",
            )?
            .query_map(params![after, clamp(batch as u64)], read_flow)?
            .collect::<Result<Vec<_>, _>>()?;

        let mut apps: BTreeMap<String, Learning> = BTreeMap::new();
        for flow in &mut flows {
            let Some(path) = flow.path.as_deref().filter(|p| !p.is_empty()) else {
                continue;
            };
            let key = known_app_key(path);
            if !apps.contains_key(&key) {
                let row = transaction
                    .query_row(
                        &format!("SELECT {ROW_COLUMNS} FROM profiles WHERE key = ?1"),
                        [&key],
                        read_row,
                    )
                    .optional()?
                    .unwrap_or_else(|| ProfileRow {
                        key: key.clone(),
                        path: path.to_owned(),
                        app_name: flow.app_name.clone(),
                        first_data: from_unix_ms(flow.first_ms),
                        learned_since: from_unix_ms(flow.first_ms),
                        last_data: from_unix_ms(flow.last_ms),
                        active_days: 0,
                        last_active_day: None,
                        last_sha256: None,
                        last_publisher: None,
                        goes_anywhere: GoesAnywhere::Auto,
                        reset_at: None,
                    });
                apps.insert(key.clone(), Learning::new(row));
            }
            if let Some(app) = apps.get_mut(&key) {
                // Never relearn what a reset forgot.
                if let Some(reset) = app.row.reset_at.map(unix_ms) {
                    if flow.last_ms < reset {
                        continue;
                    }
                    flow.first_ms = flow.first_ms.max(reset);
                }
                let learned = if flow.is_overflow() {
                    DestinationFacts::default()
                } else {
                    facts(&flow.destination())
                };
                app.add_flow(flow, &learned, local_offset_secs);
            }
        }

        for (key, app) in &apps {
            write_row(&transaction, &app.row)?;
            let items: Vec<_> = app.items.values().cloned().collect();
            write_items(&transaction, key, &items, true)?;
            let hours: Vec<_> = app.hours.values().cloned().collect();
            write_hours(&transaction, key, &hours)?;
        }

        let done = flows.len() < batch;
        let progress = match flows.last() {
            Some(last) if !done => last.id.to_string(),
            _ => BACKFILL_DONE.to_owned(),
        };
        transaction.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![BACKFILL_SETTING, progress],
        )?;
        transaction.commit()?;
        Ok(BackfillProgress {
            flows_read: flows.len() as u64,
            done,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KEY_LEN, Key};
    use std::time::UNIX_EPOCH;

    const DAY: u64 = 24 * 60 * 60;

    fn store(name: &str) -> Store {
        let dir = std::env::temp_dir().join(format!(
            "whereabouts-profiles-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Store::open(&dir.join("test.db"), &Key::from_bytes([7; KEY_LEN])).unwrap()
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn row(key: &str) -> ProfileRow {
        ProfileRow {
            key: key.to_owned(),
            path: format!(r"C:\Apps\{key}.exe"),
            app_name: format!("{key}.exe"),
            first_data: at(1_000),
            learned_since: at(1_000),
            last_data: at(2_000),
            active_days: 3,
            last_active_day: Some(20_000),
            last_sha256: Some("ab".repeat(32)),
            last_publisher: Some(String::from("Example Corp")),
            goes_anywhere: GoesAnywhere::Auto,
            reset_at: None,
        }
    }

    fn item(kind: ItemKind, value: &str, last_seen: u64, state: ItemState) -> ProfileItem {
        ProfileItem {
            kind,
            value: value.to_owned(),
            first_seen: at(last_seen),
            last_seen: at(last_seen),
            seen_on_day: 1,
            state,
        }
    }

    fn hour(hour: i64, sent: u64) -> HourRow {
        HourRow {
            hour,
            bytes_sent: sent,
            bytes_received: sent * 2,
            connections: 1,
        }
    }

    #[test]
    fn profile_round_trip() {
        let mut store = store("round-trip");
        let saved = row("app");
        store.save_profile_row(&saved).unwrap();
        let items = vec![
            item(ItemKind::Country, "US", 1_600, ItemState::Pending),
            item(ItemKind::Domain, "example.com", 1_500, ItemState::Learned),
        ];
        store.save_items("app", &items).unwrap();
        store.add_hours("app", &[hour(100, 5)]).unwrap();

        let profile = store.profile("app").unwrap().unwrap();
        assert_eq!(profile.row, saved);
        // Items come back ordered by kind then value.
        assert_eq!(profile.items, items.clone());
        assert_eq!(profile.hours, vec![hour(100, 5)]);
        assert!(store.profile("other").unwrap().is_none());
        assert_eq!(store.profile_rows().unwrap(), vec![saved]);
    }

    #[test]
    fn save_profile_row_replaces_existing() {
        let mut store = store("upsert-row");
        store.save_profile_row(&row("app")).unwrap();
        let mut changed = row("app");
        changed.active_days = 9;
        changed.reset_at = Some(at(5));
        store.save_profile_row(&changed).unwrap();
        assert_eq!(store.profile_rows().unwrap(), vec![changed]);
    }

    #[test]
    fn add_hours_adds_to_existing_hour() {
        let mut store = store("add-hours");
        store.save_profile_row(&row("app")).unwrap();
        store.add_hours("app", &[hour(100, 5)]).unwrap();
        store.add_hours("app", &[hour(100, 5)]).unwrap();
        let hours = store.profile("app").unwrap().unwrap().hours;
        assert_eq!(hours.len(), 1);
        assert_eq!(hours[0].bytes_sent, 10);
        assert_eq!(hours[0].bytes_received, 20);
        assert_eq!(hours[0].connections, 2);
    }

    #[test]
    fn save_items_keeps_first_seen_and_updates_last_seen() {
        let mut store = store("first-seen");
        store.save_profile_row(&row("app")).unwrap();
        let first = item(ItemKind::Domain, "example.com", 1_000, ItemState::Learned);
        store.save_items("app", &[first]).unwrap();
        let mut later = item(ItemKind::Domain, "example.com", 5_000, ItemState::Learned);
        later.seen_on_day = 4;
        store.save_items("app", &[later]).unwrap();

        let items = store.profile("app").unwrap().unwrap().items;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].first_seen, at(1_000));
        assert_eq!(items[0].last_seen, at(5_000));
        assert_eq!(items[0].seen_on_day, 4);
    }

    #[test]
    fn allowed_survives_later_saves_and_stale_times_do_not_win() {
        let mut store = store("sticky");
        store.save_profile_row(&row("app")).unwrap();
        let mut allowed = item(ItemKind::Domain, "a.example", 5_000, ItemState::Allowed);
        allowed.seen_on_day = 4;
        store.save_items("app", &[allowed]).unwrap();
        let mut stale = item(ItemKind::Domain, "a.example", 2_000, ItemState::Learned);
        stale.seen_on_day = 2;
        store.save_items("app", &[stale]).unwrap();

        let items = store.profile("app").unwrap().unwrap().items;
        assert_eq!(items[0].state, ItemState::Allowed);
        assert_eq!(items[0].last_seen, at(5_000));
        assert_eq!(items[0].seen_on_day, 4);

        // set_item_state is still the way to change it.
        store
            .set_item_state("app", ItemKind::Domain, "a.example", ItemState::Learned)
            .unwrap();
        assert_eq!(
            store.profile("app").unwrap().unwrap().items[0].state,
            ItemState::Learned
        );
    }

    #[test]
    fn items_capped_per_kind() {
        let mut store = store("cap");
        store.save_profile_row(&row("app")).unwrap();
        let mut items = vec![item(
            ItemKind::Domain,
            "keep.example",
            1,
            ItemState::Allowed,
        )];
        items.extend((0..MAX_ITEMS_PER_KIND as u64).map(|n| {
            item(
                ItemKind::Domain,
                &format!("d{n}.example"),
                100 + n,
                ItemState::Learned,
            )
        }));
        assert_eq!(items.len(), MAX_ITEMS_PER_KIND + 1);
        store.save_items("app", &items).unwrap();

        let kept = store.profile("app").unwrap().unwrap().items;
        assert_eq!(kept.len(), MAX_ITEMS_PER_KIND);
        assert!(kept.iter().any(|i| i.value == "keep.example"));
        assert!(!kept.iter().any(|i| i.value == "d0.example"));
        assert!(kept.iter().any(|i| i.value == "d1.example"));
    }

    #[test]
    fn expiry_counts_active_days_not_calendar_days() {
        let mut store = store("expiry-days");
        let now = at(100 * DAY);
        let mut profile = row("app");
        profile.active_days = 40;
        profile.last_data = now;
        store.save_profile_row(&profile).unwrap();
        let mut old = item(
            ItemKind::Domain,
            "old.example",
            40 * DAY,
            ItemState::Learned,
        );
        old.seen_on_day = 5;
        let mut recent = item(
            ItemKind::Domain,
            "recent.example",
            40 * DAY,
            ItemState::Learned,
        );
        recent.seen_on_day = 15;
        // Ahead of active_days (as after a reset): must not underflow or expire.
        let mut ahead = item(
            ItemKind::Domain,
            "ahead.example",
            40 * DAY,
            ItemState::Learned,
        );
        ahead.seen_on_day = 90;
        store.save_items("app", &[old, recent, ahead]).unwrap();

        let expiry = store.expire_profiles(now).unwrap();
        assert_eq!(
            expiry,
            ProfileExpiry {
                items: 1,
                hours: 0,
                profiles: 0
            }
        );
        let values: Vec<_> = store
            .profile("app")
            .unwrap()
            .unwrap()
            .items
            .into_iter()
            .map(|i| i.value)
            .collect();
        assert_eq!(values, vec!["ahead.example", "recent.example"]);
    }

    #[test]
    fn old_hours_expire() {
        let mut store = store("expiry-hours");
        let now = at(100 * DAY);
        let mut profile = row("app");
        profile.last_data = now;
        store.save_profile_row(&profile).unwrap();
        let now_hour = i64::try_from(100 * DAY / 3_600).unwrap();
        store
            .add_hours(
                "app",
                &[hour(now_hour - 31 * 24, 1), hour(now_hour - 29 * 24, 1)],
            )
            .unwrap();
        let expiry = store.expire_profiles(now).unwrap();
        assert_eq!(expiry.hours, 1);
        let hours = store.profile("app").unwrap().unwrap().hours;
        assert_eq!(hours, vec![hour(now_hour - 29 * 24, 1)]);
    }

    #[test]
    fn idle_profile_deleted_after_180_days() {
        let mut store = store("idle");
        let now = at(400 * DAY);
        let mut idle = row("idle");
        idle.last_data = at(400 * DAY - 181 * DAY);
        let mut busy = row("busy");
        busy.last_data = now;
        store.save_profile_row(&idle).unwrap();
        store.save_profile_row(&busy).unwrap();
        let now_hour = i64::try_from(400 * DAY / 3_600).unwrap();
        for key in ["idle", "busy"] {
            store
                .save_items(key, &[item(ItemKind::Port, "443", 1, ItemState::Learned)])
                .unwrap();
            store.add_hours(key, &[hour(now_hour, 1)]).unwrap();
        }

        let expiry = store.expire_profiles(now).unwrap();
        assert_eq!(expiry.profiles, 1);
        assert_eq!(expiry.items, 1);
        assert_eq!(expiry.hours, 1);
        assert!(store.profile("idle").unwrap().is_none());
        let busy = store.profile("busy").unwrap().unwrap();
        assert_eq!(busy.items.len(), 1);
        assert_eq!(busy.hours.len(), 1);
    }

    #[test]
    fn reset_keeps_goes_anywhere_and_restarts_learning() {
        let mut store = store("reset");
        let mut profile = row("app");
        profile.goes_anywhere = GoesAnywhere::UserOn;
        store.save_profile_row(&profile).unwrap();
        store
            .save_items(
                "app",
                &[item(ItemKind::Domain, "a.example", 1, ItemState::Allowed)],
            )
            .unwrap();
        store.add_hours("app", &[hour(1, 1)]).unwrap();

        assert!(store.reset_profile("app", at(9_000)).unwrap());
        let after = store.profile("app").unwrap().unwrap();
        assert!(after.items.is_empty());
        assert!(after.hours.is_empty());
        assert_eq!(after.row.first_data, at(9_000));
        assert_eq!(after.row.learned_since, at(9_000));
        assert_eq!(after.row.active_days, 0);
        assert_eq!(after.row.reset_at, Some(at(9_000)));
        assert_eq!(after.row.goes_anywhere, GoesAnywhere::UserOn);
        assert!(!store.reset_profile("missing", at(9_000)).unwrap());
    }

    #[test]
    fn set_goes_anywhere_reports_missing_profile() {
        let mut store = store("goes");
        store.save_profile_row(&row("app")).unwrap();
        assert!(
            store
                .set_goes_anywhere("app", GoesAnywhere::UserOff)
                .unwrap()
        );
        assert_eq!(
            store.profile("app").unwrap().unwrap().row.goes_anywhere,
            GoesAnywhere::UserOff
        );
        assert!(
            !store
                .set_goes_anywhere("none", GoesAnywhere::UserOn)
                .unwrap()
        );
    }

    #[test]
    fn set_item_state_reports_missing_item() {
        let mut store = store("item-state");
        store.save_profile_row(&row("app")).unwrap();
        store
            .save_items(
                "app",
                &[item(ItemKind::Domain, "a.example", 1, ItemState::Pending)],
            )
            .unwrap();
        assert!(
            store
                .set_item_state("app", ItemKind::Domain, "a.example", ItemState::Allowed)
                .unwrap()
        );
        assert_eq!(
            store.profile("app").unwrap().unwrap().items[0].state,
            ItemState::Allowed
        );
        assert!(
            !store
                .set_item_state("app", ItemKind::Domain, "nope.example", ItemState::Allowed)
                .unwrap()
        );
    }

    const APP: &str = r"C:\A\app.exe";
    const BASE: u64 = 20_000 * DAY;

    fn flow(
        path: Option<&str>,
        domain: &str,
        first: u64,
        last: u64,
        sent: u64,
    ) -> crate::FlowRecord {
        crate::FlowRecord {
            app_name: String::from("app.exe"),
            app_path: path.map(str::to_owned),
            app_sha256: None,
            signature: None,
            signature_confirmed: false,
            protocol: whereabouts_core::model::Protocol::Tcp,
            remote_ip: "203.0.113.5".parse().unwrap(),
            remote_port: 443,
            domain: Some(domain.to_owned()),
            domain_source: None,
            owner: Some(String::from("X")),
            country: Some(String::from("US")),
            first_seen: at(first),
            last_seen: at(last),
            bytes_sent: sent,
            bytes_received: sent * 2,
            connections: 3,
        }
    }

    /// An address the test rule places in Germany.
    const IN_GERMANY: &str = "198.51.100.7";

    /// A simple rule for what a profile learns: the saved domain as it is,
    /// company "X", and the country by address.
    fn facts(flow: &BackfillFlow<'_>) -> DestinationFacts {
        let germany: IpAddr = IN_GERMANY.parse().unwrap();
        DestinationFacts {
            domain: flow.domain.map(str::to_owned),
            company: Some(String::from("X")),
            country: Some(String::from(if flow.remote_ip == germany {
                "DE"
            } else {
                "US"
            })),
        }
    }

    #[test]
    fn backfill_builds_profile_from_flows() {
        let mut store = store("backfill-builds");
        let mut second = flow(Some(APP), "b.com", BASE + 5 * DAY, BASE + 5 * DAY, 10);
        second.remote_ip = IN_GERMANY.parse().unwrap();
        store
            .insert_flows(&[
                flow(Some(APP), "a.com", BASE + 100, BASE + 200, 10),
                second,
                flow(Some(APP), "a.com", BASE + 10 * DAY, BASE + 10 * DAY, 10),
                flow(None, "z.com", BASE + 300, BASE + 400, 10),
            ])
            .unwrap();

        let progress = store.backfill_profiles(1_000, 0, facts).unwrap();
        assert!(progress.done);
        assert_eq!(progress.flows_read, 4);

        let rows = store.profile_rows().unwrap();
        assert_eq!(rows.len(), 1, "no profile for the flow without a path");
        let profile = store.profile(&crate::known_app_key(APP)).unwrap().unwrap();
        assert_eq!(profile.row.learned_since, at(BASE + 100));
        assert_eq!(profile.row.first_data, at(BASE + 100));
        assert_eq!(profile.row.last_data, at(BASE + 10 * DAY));
        assert_eq!(profile.row.active_days, 3);
        let of = |kind| {
            profile
                .items
                .iter()
                .filter(|i| i.kind == kind)
                .collect::<Vec<_>>()
        };
        assert_eq!(of(ItemKind::Domain).len(), 2);
        assert_eq!(of(ItemKind::Company).len(), 1);
        assert_eq!(of(ItemKind::Country).len(), 2);
        assert_eq!(of(ItemKind::Port)[0].value, "443");
        assert!(profile.items.iter().all(|i| i.state == ItemState::Learned));
        let a = of(ItemKind::Domain)[0];
        assert_eq!((a.value.as_str(), a.seen_on_day), ("a.com", 3));
        assert_eq!(a.first_seen, at(BASE + 100));
    }

    #[test]
    fn backfill_spreads_bytes_over_hours() {
        let mut store = store("backfill-hours");
        let first = BASE + 10 * 3_600;
        let last = BASE + 12 * 3_600 + 3_599;
        store
            .insert_flows(&[flow(Some(APP), "a.com", first, last, 3_000)])
            .unwrap();
        store.backfill_profiles(1_000, 0, facts).unwrap();
        let hours = store
            .profile(&crate::known_app_key(APP))
            .unwrap()
            .unwrap()
            .hours;
        let first_hour = i64::try_from(first / 3_600).unwrap();
        assert_eq!(
            hours.iter().map(|h| h.hour).collect::<Vec<_>>(),
            vec![first_hour, first_hour + 1, first_hour + 2]
        );
        assert!(hours.iter().all(|h| h.bytes_sent == 1_000));
        assert!(hours.iter().all(|h| h.bytes_received == 2_000));
        assert!(hours.iter().all(|h| h.connections == 1));
    }

    #[test]
    fn backfill_remainder_goes_to_last_hour() {
        let mut store = store("backfill-remainder");
        let first = BASE + 10 * 3_600;
        let last = BASE + 11 * 3_600;
        store
            .insert_flows(&[flow(Some(APP), "a.com", first, last, 11)])
            .unwrap();
        store.backfill_profiles(1_000, 0, facts).unwrap();
        let hours = store
            .profile(&crate::known_app_key(APP))
            .unwrap()
            .unwrap()
            .hours;
        assert_eq!(
            hours.iter().map(|h| h.bytes_sent).collect::<Vec<_>>(),
            [5, 6]
        );
        assert_eq!(hours.iter().map(|h| h.connections).sum::<u64>(), 3);
    }

    #[test]
    fn backfill_runs_in_batches() {
        let flows: Vec<_> = (0..25)
            .map(|i| {
                let t = BASE + i * 3 * 3_600;
                flow(Some(APP), &format!("d{}.com", i % 7), t, t + 100, 100 + i)
            })
            .collect();
        let mut batched = store("backfill-batched");
        batched.insert_flows(&flows).unwrap();
        let mut whole = store("backfill-whole");
        whole.insert_flows(&flows).unwrap();

        let done: Vec<bool> = (0..3)
            .map(|_| batched.backfill_profiles(10, 0, facts).unwrap().done)
            .collect();
        assert_eq!(done, [false, false, true]);
        assert!(whole.backfill_profiles(1_000, 0, facts).unwrap().done);

        let key = crate::known_app_key(APP);
        assert_eq!(batched.profile(&key).unwrap(), whole.profile(&key).unwrap());
    }

    #[test]
    fn backfill_learns_what_the_rule_says_not_the_saved_display_text() {
        let mut store = store("backfill-rule");
        let mut saved = flow(Some(APP), "api.chat.example", BASE, BASE + 10, 10);
        saved.domain_source = Some(LabelSource::Unverified);
        saved.owner = Some(String::from("Google · analytics"));
        store.insert_flows(&[saved]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        store
            .backfill_profiles(1_000, 0, |flow| {
                seen.borrow_mut().push((
                    flow.remote_ip,
                    flow.remote_port,
                    flow.domain.map(str::to_owned),
                    flow.domain_source,
                ));
                DestinationFacts::default()
            })
            .unwrap();
        assert_eq!(
            seen.into_inner(),
            [(
                "203.0.113.5".parse::<IpAddr>().unwrap(),
                443,
                Some(String::from("api.chat.example")),
                Some(LabelSource::Unverified),
            )]
        );
        let items = store
            .profile(&crate::known_app_key(APP))
            .unwrap()
            .unwrap()
            .items;
        // Only the port: the rule learned nothing else, and the saved
        // owner text is never used.
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(
            (items[0].kind, items[0].value.as_str()),
            (ItemKind::Port, "443")
        );
    }

    #[test]
    fn backfill_counts_overflow_bytes_but_learns_no_destination() {
        let mut store = store("backfill-overflow");
        let mut overflow = flow(Some(APP), "-", BASE, BASE, 700);
        overflow.domain = None;
        overflow.remote_ip = OVERFLOW_REMOTE.ip();
        overflow.remote_port = OVERFLOW_REMOTE.port();
        overflow.owner = Some(String::from("(many destinations)"));
        store.insert_flows(&[overflow]).unwrap();
        let asked = std::cell::Cell::new(0);
        store
            .backfill_profiles(1_000, 0, |flow| {
                asked.set(asked.get() + 1);
                facts(flow)
            })
            .unwrap();
        assert_eq!(asked.get(), 0, "no destination to ask about");
        let profile = store.profile(&crate::known_app_key(APP)).unwrap().unwrap();
        assert!(profile.items.is_empty(), "{:?}", profile.items);
        assert_eq!(profile.hours.iter().map(|h| h.bytes_sent).sum::<u64>(), 700);
    }

    #[test]
    fn backfill_is_not_repeated() {
        let mut store = store("backfill-once");
        store
            .insert_flows(&[flow(Some(APP), "a.com", BASE, BASE + 1, 10)])
            .unwrap();
        assert!(store.backfill_profiles(1_000, 0, facts).unwrap().done);
        let again = store.backfill_profiles(1_000, 0, facts).unwrap();
        assert_eq!(again.flows_read, 0);
        assert!(again.done);
        let key = crate::known_app_key(APP);
        assert_eq!(
            store.profile(&key).unwrap().unwrap().hours[0].bytes_sent,
            10
        );
    }

    #[test]
    fn backfill_counts_days_by_local_time_and_ignores_older_days() {
        let mut store = store("backfill-days");
        // At UTC+2, 22:00 and 23:00 UTC are both local day 20_001.
        let at_hour = |h: u64| BASE + h * 3_600;
        store
            .insert_flows(&[
                flow(Some(APP), "a.com", at_hour(1), at_hour(1), 1),
                flow(Some(APP), "a.com", at_hour(22), at_hour(22), 1),
                flow(Some(APP), "a.com", at_hour(23), at_hour(23), 1),
                // An older day arriving late does not count again.
                flow(Some(APP), "b.com", at_hour(2), at_hour(2), 1),
            ])
            .unwrap();
        store.backfill_profiles(1_000, 2 * 3_600, facts).unwrap();
        let profile = store.profile(&crate::known_app_key(APP)).unwrap().unwrap();
        assert_eq!(profile.row.active_days, 2);
        assert_eq!(profile.row.last_active_day, Some(20_001));
    }

    #[test]
    fn backfill_reads_flows_saved_between_batches() {
        let mut store = store("backfill-growing");
        let flows: Vec<_> = (0..4)
            .map(|i| flow(Some(APP), "a.com", BASE + i * 100, BASE + i * 100, 10))
            .collect();
        store.insert_flows(&flows[..2]).unwrap();
        assert!(!store.backfill_profiles(2, 0, facts).unwrap().done);
        store.insert_flows(&flows[2..]).unwrap();
        let progress = store.backfill_profiles(2, 0, facts).unwrap();
        assert_eq!(progress.flows_read, 2);
        assert!(!progress.done);
        assert!(store.backfill_profiles(2, 0, facts).unwrap().done);
        let hours = store
            .profile(&crate::known_app_key(APP))
            .unwrap()
            .unwrap()
            .hours;
        assert_eq!(hours.iter().map(|h| h.bytes_sent).sum::<u64>(), 40);
    }

    #[test]
    fn backfill_keeps_state_of_existing_items() {
        let mut store = store("backfill-pending");
        let key = crate::known_app_key(APP);
        let mut existing = row(&key);
        existing.path = APP.to_owned();
        store.save_profile_row(&existing).unwrap();
        store
            .save_items(
                &key,
                &[
                    item(ItemKind::Domain, "a.com", 1_000, ItemState::Pending),
                    item(ItemKind::Country, "US", 1_000, ItemState::Allowed),
                ],
            )
            .unwrap();
        store
            .insert_flows(&[flow(Some(APP), "a.com", BASE, BASE + 10, 1)])
            .unwrap();
        store.backfill_profiles(1_000, 0, facts).unwrap();
        let items = store.profile(&key).unwrap().unwrap().items;
        let state = |kind, value: &str| {
            items
                .iter()
                .find(|i| i.kind == kind && i.value == value)
                .map(|i| (i.state, i.last_seen))
                .unwrap()
        };
        assert_eq!(
            state(ItemKind::Domain, "a.com"),
            (ItemState::Pending, at(BASE + 10))
        );
        assert_eq!(state(ItemKind::Country, "US").0, ItemState::Allowed);
        assert_eq!(state(ItemKind::Company, "X").0, ItemState::Learned);
    }

    #[test]
    fn backfill_does_not_undo_a_reset() {
        let mut store = store("backfill-reset");
        let key = crate::known_app_key(APP);
        let mut existing = row(&key);
        existing.path = APP.to_owned();
        store.save_profile_row(&existing).unwrap();
        let reset = at(BASE + 5_000);
        assert!(store.reset_profile(&key, reset).unwrap());
        store
            .insert_flows(&[
                flow(Some(APP), "old.com", BASE, BASE + 100, 10),
                // Straddles the reset: counted only from the reset on.
                flow(Some(APP), "new.com", BASE + 4_000, BASE + 6_000, 10),
            ])
            .unwrap();
        store.backfill_profiles(1_000, 0, facts).unwrap();
        let profile = store.profile(&key).unwrap().unwrap();
        assert_eq!(profile.row.first_data, reset);
        assert_eq!(profile.row.learned_since, reset);
        let domains: Vec<_> = profile
            .items
            .iter()
            .filter(|i| i.kind == ItemKind::Domain)
            .map(|i| i.value.as_str())
            .collect();
        assert_eq!(domains, ["new.com"]);
        assert!(profile.items.iter().all(|i| i.first_seen >= reset));
    }
}
