//! One writer, bounded journal/outbox. SQLite commits the observation, baseline
//! and generated event together before shipment.
//!
//! Record states: `pending` (in the outbox, retried with backoff after ACK
//! `0x02` or a transport failure), `done` (ACK `0x01`, or an observation with no
//! event) and `refused` (ACK `0x00`, permanent). A refused record is terminal: it
//! is never resent, never blocks other records and is not pending, but stays in
//! the journal as evidence. Terminal rows (`done` and `refused`) share the
//! retention rules: they expire after `retention_days`, and when the journal is
//! full the oldest `done` row is evicted first, then the oldest `refused` row.
//! Every refused row that leaves the journal is counted (`refused_expired`,
//! `refused_evicted`). Pending rows are never evicted. Only an explicit operator
//! `requeue-refused` ([`Store::requeue_refused`]) moves a refused row back to
//! `pending`.
use crate::{
    Result, fs,
    model::{Observation, detection},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{fs::File, path::Path};
/// Upper bound on `--event-id` arguments to one `requeue-refused`.
pub const MAX_REQUEUE_IDS: usize = 256;
/// An event ID as Darkapple generates it: a canonical lowercase hyphenated UUID.
pub fn valid_event_id(id: &str) -> bool {
    uuid::Uuid::try_parse(id).is_ok_and(|u| u.hyphenated().to_string() == id)
}
pub struct Store {
    db: Connection,
    _lock: File,
    capacity: usize,
    hidden_allow: Vec<String>,
}
impl Store {
    pub fn open(dir: &Path, capacity: usize) -> Result<Self> {
        fs::private_dir(dir)?;
        let lock = fs::lock(&dir.join("writer.lock"))?;
        let path = dir.join("events.db");
        fs::private_file(&path)?;
        for suffix in ["events.db-wal", "events.db-shm", "events.db-journal"] {
            let p = dir.join(suffix);
            if p.symlink_metadata().is_ok() {
                fs::private_file(&p)?;
            }
        }
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=65536;
            CREATE TABLE IF NOT EXISTS baseline(key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, seen INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY, observed INTEGER NOT NULL, observation TEXT NOT NULL, event TEXT, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value INTEGER NOT NULL);")?;
        Ok(Self {
            db,
            _lock: lock,
            capacity,
            hidden_allow: crate::config::default_hidden_dir_allowlist(),
        })
    }
    /// Dot-directories directly under a user home that do not raise
    /// `macos.process.hidden_executable` (see `Config::hidden_dir_allowlist`).
    pub fn set_hidden_allowlist(&mut self, list: Vec<String>) {
        self.hidden_allow = list;
    }
    pub fn observe(&mut self, o: &Observation) -> Result<bool> {
        o.validate()?;
        let tx = self.db.transaction()?;
        let key = o.key();
        let fp = o.fingerprint()?;
        let prev: Option<String> = tx
            .query_row(
                "SELECT fingerprint FROM baseline WHERE key=?",
                [&key],
                |r| r.get(0),
            )
            .optional()?;
        if prev.as_deref() == Some(&fp) {
            tx.commit()?;
            return Ok(false);
        }
        let count: i64 = tx.query_row("SELECT count(*) FROM records", [], |r| r.get(0))?;
        if count >= self.capacity as i64 {
            let removed=tx.execute("DELETE FROM records WHERE id=(SELECT id FROM records WHERE state='done' ORDER BY id LIMIT 1)",[])?;
            let removed = if removed == 0 {
                let r = tx.execute("DELETE FROM records WHERE id=(SELECT id FROM records WHERE state='refused' ORDER BY id LIMIT 1)",[])?;
                if r > 0 {
                    tx.execute("INSERT INTO meta VALUES('refused_evicted',1) ON CONFLICT(key) DO UPDATE SET value=value+1",[])?;
                }
                r
            } else {
                removed
            };
            if removed == 0 {
                tx.execute("INSERT INTO meta VALUES('lost',1) ON CONFLICT(key) DO UPDATE SET value=value+1",[])?;
                tx.commit()?;
                return Ok(false);
            }
        }
        let directory_ready = if o.kind == "launchd.file" {
            if let Some(parent) = o.path.as_deref().and_then(|p| Path::new(p).parent()) {
                let mut marker =
                    crate::sources::observation("launchd", "launchd.baseline", "ready".into());
                marker.path = Some(parent.to_string_lossy().into());
                tx.query_row("SELECT 1 FROM baseline WHERE key=?", [marker.key()], |_| {
                    Ok(())
                })
                .optional()?
                .is_some()
            } else {
                false
            }
        } else {
            false
        };
        let event = detection(o, prev.is_some() || directory_ready, &self.hidden_allow)
            .map(|e| serde_json::to_string(&e))
            .transpose()?;
        tx.execute(
            "INSERT INTO records(observed,observation,event,state) VALUES(?,?,?,?)",
            params![
                o.observed_at_ms,
                serde_json::to_string(o)?,
                event,
                if event.is_some() { "pending" } else { "done" }
            ],
        )?;
        tx.execute("INSERT INTO baseline VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET fingerprint=excluded.fingerprint,seen=excluded.seen",params![key,fp,o.observed_at_ms])?;
        // Bound baseline storage as well; oldest entries can be re-observed.
        tx.execute("DELETE FROM baseline WHERE key IN (SELECT key FROM baseline ORDER BY seen DESC LIMIT -1 OFFSET ?)",[self.capacity as i64])?;
        tx.commit()?;
        Ok(true)
    }
    pub fn pending(&self, now: i64) -> Result<Vec<(i64, Value, u32)>> {
        let mut q=self.db.prepare("SELECT id,event,attempts FROM records WHERE state='pending' AND next_try<=? ORDER BY id LIMIT 32")?;
        let rows = q.query_map([now], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u32>(2)?,
            ))
        })?;
        rows.map(|r| {
            let (id, s, a) = r?;
            Ok((id, serde_json::from_str(&s)?, a))
        })
        .collect()
    }
    pub fn acknowledge(&self, id: i64) -> Result<()> {
        self.db
            .execute("UPDATE records SET state='done' WHERE id=?", [id])?;
        self.bump("acknowledged")
    }
    /// ACK `0x00`: move a pending record to the terminal `refused` state. It is
    /// kept as evidence and never resent.
    pub fn refuse(&self, id: i64) -> Result<()> {
        self.db.execute(
            "UPDATE records SET state='refused',attempts=min(attempts+1,1000000) WHERE id=? AND state='pending'",
            [id],
        )?;
        self.bump("refused")
    }
    /// Transient failure: keep the record pending and back off. `explicit` is
    /// true for an ACK `0x02` (counted `retried`), false for no/unknown byte,
    /// I/O error or timeout (counted `transport_errors`).
    pub fn retry(&self, id: i64, attempts: u32, now: i64, explicit: bool) -> Result<()> {
        let delay = (1000_i64.saturating_mul(1_i64 << attempts.min(9))).min(300_000);
        self.db.execute(
            "UPDATE records SET attempts=min(attempts+1,1000000),next_try=? WHERE id=? AND state='pending'",
            params![now.saturating_add(delay), id],
        )?;
        self.bump(if explicit {
            "retried"
        } else {
            "transport_errors"
        })
    }
    /// Operator recovery: moves `refused` rows back to `pending` (attempts 0, due
    /// at `now`) in one transaction, keeping the stored event body, and with it
    /// the stable `event_id` Darksignal deduplicates on. `None` requeues every
    /// refused row; `Some(ids)` only refused rows with those event IDs. Rows in
    /// any other state are never touched. Returns the number requeued and the
    /// requested IDs that were not (unknown or not refused). IDs are validated
    /// before any change: canonical lowercase UUIDs, 1 to
    /// [`MAX_REQUEUE_IDS`].
    pub fn requeue_refused(
        &mut self,
        ids: Option<&[String]>,
        now: i64,
    ) -> Result<(usize, Vec<String>)> {
        let mut wanted: Vec<&str> = Vec::new();
        if let Some(ids) = ids {
            if ids.is_empty() || ids.len() > MAX_REQUEUE_IDS {
                return Err(format!("between 1 and {MAX_REQUEUE_IDS} event IDs required").into());
            }
            for id in ids {
                if !valid_event_id(id) {
                    return Err(format!("invalid event ID {id:?}").into());
                }
                if !wanted.contains(&id.as_str()) {
                    wanted.push(id);
                }
            }
        }
        const REQUEUE: &str =
            "UPDATE records SET state='pending',attempts=0,next_try=? WHERE state='refused'";
        let tx = self.db.transaction()?;
        let mut missing = Vec::new();
        let requeued = if ids.is_none() {
            tx.execute(REQUEUE, [now])?
        } else {
            let mut n = 0;
            for id in wanted {
                let changed = tx.execute(
                    &format!("{REQUEUE} AND json_extract(event,'$.event_id')=?"),
                    params![now, id],
                )?;
                if changed == 0 {
                    missing.push(id.to_string());
                }
                n += changed;
            }
            n
        };
        if requeued > 0 {
            tx.execute(
                "INSERT INTO meta VALUES('requeued',?) ON CONFLICT(key) DO UPDATE SET value=value+excluded.value",
                [requeued as i64],
            )?;
        }
        tx.commit()?;
        Ok((requeued, missing))
    }
    pub fn bump(&self, key: &str) -> Result<()> {
        self.db.execute(
            "INSERT INTO meta VALUES(?,1) ON CONFLICT(key) DO UPDATE SET value=value+1",
            [key],
        )?;
        Ok(())
    }
    pub fn prune(&self, now: i64, days: u32) -> Result<()> {
        let cutoff = now.saturating_sub(i64::from(days) * 86_400_000);
        self.db.execute(
            "DELETE FROM records WHERE state='done' AND observed<?",
            [cutoff],
        )?;
        let expired = self.db.execute(
            "DELETE FROM records WHERE state='refused' AND observed<?",
            [cutoff],
        )?;
        if expired > 0 {
            self.db.execute(
                "INSERT INTO meta VALUES('refused_expired',?) ON CONFLICT(key) DO UPDATE SET value=value+excluded.value",
                [expired as i64],
            )?;
        }
        Ok(())
    }
    pub fn status(&self) -> Result<Value> {
        let count: i64 = self
            .db
            .query_row("SELECT count(*) FROM records", [], |r| r.get(0))?;
        let pending: i64 = self.db.query_row(
            "SELECT count(*) FROM records WHERE state='pending'",
            [],
            |r| r.get(0),
        )?;
        let refused: i64 = self.db.query_row(
            "SELECT count(*) FROM records WHERE state='refused'",
            [],
            |r| r.get(0),
        )?;
        let mut counters = serde_json::Map::new();
        let mut q = self.db.prepare("SELECT key,value FROM meta")?;
        for r in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (k, v) = r?;
            counters.insert(k, json!(v));
        }
        Ok(
            json!({"records":count,"pending":pending,"refused":refused,"capacity":self.capacity,"counters":counters}),
        )
    }
    pub fn loss(&self) -> Result<i64> {
        Ok(self
            .db
            .query_row("SELECT value FROM meta WHERE key='lost'", [], |r| r.get(0))
            .optional()?
            .unwrap_or(0))
    }
}
