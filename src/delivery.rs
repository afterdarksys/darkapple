//! Applies Darksignal's acks to the outbox. Shared by `ship`, the run loop and
//! the final drain so all three follow one ack table:
//!
//! | Ack | Record | Counter |
//! | --- | --- | --- |
//! | `0x01` | `done` | `acknowledged` |
//! | `0x00` | `refused` (terminal, kept as evidence, logged with event_id and rule) | `refused` |
//! | `0x02` | stays `pending`, backoff | `retried` |
//! | no/unknown byte, I/O error, timeout | stays `pending`, backoff | `transport_errors` |
//!
//! `ship` stops at the first ack other than `0x01` (see [`ship_due`]).
//!
//! Health frames are never stored; each ack is only counted (`health_*`), and
//! a refused health frame is logged.
use crate::{
    Result,
    config::Config,
    store::Store,
    transport::{self, Ack, Retry},
};
use serde_json::Value;
use std::thread::JoinHandle;
/// `ship` exit code when at least one record was permanently refused.
pub const EXIT_REFUSED: i32 = 3;
/// `ship` exit code when records were retained for retry (and none refused).
pub const EXIT_RETAINED: i32 = 2;
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    pub accepted: u32,
    pub refused: u32,
    pub retained: u32,
    /// Due records left pending and unsent because `ship` stopped early.
    pub unattempted: u32,
}
impl Tally {
    /// 0: every due record was accepted (records still in backoff are not
    /// attempted). 3: a record was refused; refusal is permanent and needs an
    /// operator, so it takes precedence. 2: a record was retained for a later
    /// retry. In both nonzero cases the remaining due records are unattempted.
    pub fn exit_code(&self) -> i32 {
        if self.refused > 0 {
            EXIT_REFUSED
        } else if self.retained > 0 {
            EXIT_RETAINED
        } else {
            0
        }
    }
    fn add(&mut self, ack: &Ack) {
        match ack {
            Ack::Accepted => self.accepted += 1,
            Ack::Refused => self.refused += 1,
            Ack::Retry(_) => self.retained += 1,
        }
    }
}
fn field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key).and_then(Value::as_str).unwrap_or("?")
}
/// Applies one event ack to its outbox record.
pub fn settle(store: &Store, id: i64, attempts: u32, ack: &Ack, body: &Value) -> Result<()> {
    match ack {
        Ack::Accepted => store.acknowledge(id),
        Ack::Refused => {
            store.refuse(id)?;
            // Identity only; never the event body.
            eprintln!(
                "darkapple: darksignal REFUSED event_id={:?} rule={:?} (ack 0x00, permanent); kept in the journal as state=refused and not resent",
                field(body, "event_id"),
                field(body, "rule_id"),
            );
            Ok(())
        }
        Ack::Retry(r) => store.retry(id, attempts, crate::now_ms(), matches!(r, Retry::Ack)),
    }
}
/// Counts the ack of a health frame. Health is regenerated every cycle and is
/// never resent, so a refusal is counted and logged, not retried.
pub fn settle_health(store: &Store, ack: &Ack) -> Result<()> {
    if *ack == Ack::Refused {
        eprintln!(
            "darkapple: darksignal REFUSED a health frame (ack 0x00, permanent); check the darksignal producer config for this host, uid and executable"
        );
    }
    store.bump(match ack {
        Ack::Accepted => "health_acknowledged",
        Ack::Refused => "health_refused",
        Ack::Retry(Retry::Ack) => "health_retried",
        Ack::Retry(Retry::Transport(_)) => "health_transport_errors",
    })
}
/// The `ship` command: sends due records (up to 32) in order and stops at the
/// first one that is not accepted. A refusal stops because `ship` sends no
/// health frame first and Darksignal answers `0x00` to a producer identity
/// mismatch (wrong executable or uid) exactly as to a bad record: continuing
/// would refuse the whole queue, while stopping caps the damage at one record
/// per `ship` (recoverable with `requeue-refused`). A transient failure stops
/// as in the `run` loop. The records after the stop stay pending and
/// unattempted: not sent, attempts and backoff unchanged.
pub fn ship_due(c: &Config, store: &Store) -> Result<Tally> {
    let mut tally = Tally::default();
    let due = store.pending(crate::now_ms())?;
    let total = due.len();
    for (n, (id, body, attempts)) in due.into_iter().enumerate() {
        let ack = transport::send(c, &body);
        settle(store, id, attempts, &ack, &body)?;
        tally.add(&ack);
        if ack != Ack::Accepted {
            tally.unattempted = (total - n - 1) as u32;
            break;
        }
    }
    Ok(tally)
}
/// Joins the delivery worker. A panic is an error, never discarded.
pub fn join_worker(worker: JoinHandle<()>) -> Result<()> {
    worker.join().map_err(|p| {
        let why = p
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".into());
        format!("delivery worker panicked: {why}").into()
    })
}
