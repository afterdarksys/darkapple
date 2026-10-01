//! One writer, bounded journal/outbox; refusal retains the record. SQLite commits
//! the observation, baseline and generated event together before shipment.
use crate::{
    Result, fs,
    model::{Observation, detection},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{fs::File, path::Path};
pub struct Store {
    db: Connection,
    _lock: File,
    capacity: usize,
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
        })
    }
    pub fn observe(&mut self, o: &Observation) -> Result<bool> {
        o.validate()?;
        let tx = self.db.transaction()?;
        let key = o.key();
        let fp = o.fingerprint();
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
        let event = detection(o, prev.is_some() || directory_ready)
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
    pub fn retry(&self, id: i64, attempts: u32, now: i64, refused: bool) -> Result<()> {
        let delay = (1000_i64.saturating_mul(1_i64 << attempts.min(9))).min(300_000);
        self.db.execute(
            "UPDATE records SET attempts=min(attempts+1,1000000),next_try=? WHERE id=?",
            params![now.saturating_add(delay), id],
        )?;
        self.bump(if refused {
            "refused"
        } else {
            "transport_errors"
        })
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
        let mut counters = serde_json::Map::new();
        let mut q = self.db.prepare("SELECT key,value FROM meta")?;
        for r in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (k, v) = r?;
            counters.insert(k, json!(v));
        }
        Ok(json!({"records":count,"pending":pending,"capacity":self.capacity,"counters":counters}))
    }
    pub fn loss(&self) -> Result<i64> {
        Ok(self
            .db
            .query_row("SELECT value FROM meta WHERE key='lost'", [], |r| r.get(0))
            .optional()?
            .unwrap_or(0))
    }
}
