use darkapple::{
    config::Config,
    delivery, fs,
    model::Observation,
    sources::observation,
    store::{self, Store},
    transport::{self, Ack, Retry},
};
use serde_json::json;
use std::{
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
fn temp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("darkapple-test-")
        .tempdir_in("/private/tmp")
        .unwrap()
}
fn process(pid: u32, start: u64, exe: &str) -> Observation {
    let mut o = observation("process", "process.observed", "present".into());
    o.pid = Some(pid);
    o.start_us = Some(start);
    o.exe = Some(exe.into());
    o
}
#[test]
fn durable_replay_preserves_event_and_pid_reuse_is_new() {
    let d = temp();
    let state = d.path().join("state");
    let mut s = Store::open(&state, 100).unwrap();
    let o = process(42, 100, "/opt/.cache/miner");
    assert!(s.observe(&o).unwrap());
    assert!(!s.observe(&o).unwrap());
    let first = s.pending(i64::MAX).unwrap()[0].1.clone();
    drop(s);
    let mut s = Store::open(&state, 100).unwrap();
    assert_eq!(first, s.pending(i64::MAX).unwrap()[0].1);
    s.observe(&process(42, 200, "/opt/.cache/miner")).unwrap();
    assert_eq!(s.pending(i64::MAX).unwrap().len(), 2);
}
#[test]
fn queue_full_retains_pending_and_counts_loss_then_recovers() {
    let d = temp();
    let mut s = Store::open(&d.path().join("state"), 2).unwrap();
    s.observe(&process(1, 1, "/tmp/a")).unwrap();
    s.observe(&process(2, 1, "/tmp/b")).unwrap();
    assert!(!s.observe(&process(3, 1, "/tmp/c")).unwrap());
    assert_eq!(s.loss().unwrap(), 1);
    let row = s.pending(i64::MAX).unwrap()[0].clone();
    s.acknowledge(row.0).unwrap();
    assert!(s.observe(&process(3, 1, "/tmp/c")).unwrap());
    assert_eq!(s.status().unwrap()["pending"], 2);
}
#[test]
fn baseline_launchd_is_quiet_change_is_signal() {
    let d = temp();
    let mut s = Store::open(&d.path().join("state"), 100).unwrap();
    let mut o = observation("launchd", "launchd.file", "hash1".into());
    o.path = Some("/Library/LaunchDaemons/x.plist".into());
    s.observe(&o).unwrap();
    assert!(s.pending(i64::MAX).unwrap().is_empty());
    o.value = "hash2".into();
    s.observe(&o).unwrap();
    assert_eq!(
        s.pending(i64::MAX).unwrap()[0].1["rule_id"],
        "macos.persistence.launchd_changed"
    );
}
#[test]
fn retry_ack_keeps_record_and_backs_off_without_changing_id() {
    let d = temp();
    let mut s = Store::open(&d.path().join("state"), 100).unwrap();
    s.observe(&process(1, 1, "/tmp/a")).unwrap();
    let row = s.pending(0).unwrap()[0].clone();
    s.retry(row.0, 0, 10, true).unwrap();
    assert!(s.pending(11).unwrap().is_empty());
    assert_eq!(s.pending(1010).unwrap()[0].1, row.1);
    s.retry(row.0, 1, 1010, false).unwrap();
    let st = s.status().unwrap();
    assert_eq!(st["counters"]["retried"], 1);
    assert_eq!(st["counters"]["transport_errors"], 1);
    assert!(st["counters"].get("refused").is_none());
    assert_eq!(st["pending"], 1);
    assert_eq!(st["refused"], 0);
}
fn state(dir: &std::path::Path, id: i64) -> String {
    let db = rusqlite::Connection::open(dir.join("events.db")).unwrap();
    db.query_row("SELECT state FROM records WHERE id=?", [id], |r| r.get(0))
        .unwrap()
}
#[test]
fn refused_record_is_terminal_kept_as_evidence_and_never_blocks_others() {
    let d = temp();
    let dir = d.path().join("state");
    let mut s = Store::open(&dir, 100).unwrap();
    s.observe(&process(1, 1, "/tmp/a")).unwrap();
    s.observe(&process(2, 1, "/tmp/b")).unwrap();
    let rows = s.pending(0).unwrap();
    s.refuse(rows[0].0).unwrap();
    // Never resent, at any time, and the next record is still due.
    let due = s.pending(i64::MAX).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].0, rows[1].0);
    // A late retry/ack for a refused row cannot resurrect it.
    s.retry(rows[0].0, 0, 0, true).unwrap();
    assert_eq!(s.pending(i64::MAX).unwrap().len(), 1);
    let st = s.status().unwrap();
    assert_eq!(st["refused"], 1);
    assert_eq!(st["pending"], 1);
    assert_eq!(st["records"], 2);
    assert_eq!(st["counters"]["refused"], 1);
    drop(s);
    assert_eq!(state(&dir, rows[0].0), "refused");
}
#[test]
fn refused_rows_do_not_hold_capacity_and_leaving_is_counted() {
    let d = temp();
    let mut s = Store::open(&d.path().join("state"), 2).unwrap();
    s.observe(&process(1, 1, "/tmp/a")).unwrap();
    s.observe(&process(2, 1, "/tmp/b")).unwrap();
    for (id, _, _) in s.pending(0).unwrap() {
        s.refuse(id).unwrap();
    }
    assert!(s.observe(&process(3, 1, "/tmp/c")).unwrap());
    assert_eq!(s.loss().unwrap(), 0);
    let st = s.status().unwrap();
    assert_eq!(st["counters"]["refused_evicted"], 1);
    assert_eq!(
        (st["refused"].clone(), st["pending"].clone()),
        (1.into(), 1.into())
    );
    // Refused rows follow the completed-row expiry, counted.
    s.prune(i64::MAX, 1).unwrap();
    let st = s.status().unwrap();
    assert_eq!(st["refused"], 0);
    assert_eq!(st["pending"], 1);
    assert_eq!(st["counters"]["refused_expired"], 1);
}
#[test]
fn health_refusal_is_counted_not_stored() {
    let d = temp();
    let s = Store::open(&d.path().join("state"), 100).unwrap();
    delivery::settle_health(&s, &Ack::Refused).unwrap();
    delivery::settle_health(&s, &Ack::Retry(Retry::Ack)).unwrap();
    delivery::settle_health(&s, &Ack::Accepted).unwrap();
    let st = s.status().unwrap();
    assert_eq!(st["counters"]["health_refused"], 1);
    assert_eq!(st["counters"]["health_retried"], 1);
    assert_eq!(st["counters"]["health_acknowledged"], 1);
    assert_eq!(st["records"], 0);
}
#[test]
fn ship_exit_codes() {
    let t = |accepted, refused, retained| {
        delivery::Tally {
            accepted,
            refused,
            retained,
            unattempted: 0,
        }
        .exit_code()
    };
    assert_eq!(t(0, 0, 0), 0);
    assert_eq!(t(3, 0, 0), 0);
    assert_eq!(t(1, 0, 1), delivery::EXIT_RETAINED);
    assert_eq!(t(1, 1, 0), delivery::EXIT_REFUSED);
    assert_eq!(t(0, 1, 1), delivery::EXIT_REFUSED);
    // Records left unattempted never change the code on their own.
    let left = |refused, retained| {
        delivery::Tally {
            refused,
            retained,
            unattempted: 5,
            ..Default::default()
        }
        .exit_code()
    };
    assert_eq!(left(1, 0), delivery::EXIT_REFUSED);
    assert_eq!(left(0, 1), delivery::EXIT_RETAINED);
    assert_eq!((delivery::EXIT_RETAINED, delivery::EXIT_REFUSED), (2, 3));
}
#[test]
fn worker_panic_is_reported() {
    let h = std::thread::spawn(|| panic!("boom"));
    let e = delivery::join_worker(h).unwrap_err().to_string();
    assert!(e.contains("boom"), "{e}");
    assert!(delivery::join_worker(std::thread::spawn(|| {})).is_ok());
}
#[test]
fn rejects_symlinks_and_concurrent_writers() {
    let d = temp();
    let state = d.path().join("state");
    let _s = Store::open(&state, 100).unwrap();
    assert!(Store::open(&state, 100).is_err());
    std::os::unix::fs::symlink(&state, d.path().join("link")).unwrap();
    assert!(Store::open(&d.path().join("link"), 100).is_err());
    let other = d.path().join("other");
    fs::private_dir(&other).unwrap();
    std::os::unix::fs::symlink(state.join("events.db"), other.join("events.db")).unwrap();
    assert!(Store::open(&other, 100).is_err());
}
#[test]
fn strict_config_and_frame_limit() {
    assert!(!darkapple::config::valid_host("mac..local"));
    assert!(darkapple::config::valid_host("mac.local"));
    assert!(transport::frame("mac", &json!({"payload":"x".repeat(65536)})).is_err());
    let o: Result<Observation, _> = serde_json::from_value(
        json!({"source":"process","kind":"process.observed","observed_at_ms":1,"value":"present","argv":["secret"]}),
    );
    assert!(o.is_err());
}
fn lab(d: &tempfile::TempDir) -> (Config, UnixListener) {
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock = d.path().join("s");
    let listener = UnixListener::bind(&sock).unwrap();
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cfg = Config {
        host: "mac1".into(),
        state_dir: d.path().join("state"),
        darksignal_socket: sock,
        interval_seconds: 1,
        capacity: 100,
        retention_days: 1,
        endpoint_helper: None,
        launch_dirs: vec![],
        hidden_dir_allowlist: darkapple::config::default_hidden_dir_allowlist(),
    };
    (cfg, listener)
}
/// Answers each connection with the next scripted byte; `None` closes without one.
fn fake_darksignal(
    listener: UnixListener,
    acks: Vec<Option<u8>>,
) -> std::thread::JoinHandle<Vec<serde_json::Value>> {
    std::thread::spawn(move || {
        let mut bodies = Vec::new();
        for ack in acks {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut len = [0; 4];
            s.read_exact(&mut len).unwrap();
            let mut body = vec![0; u32::from_le_bytes(len) as usize];
            s.read_exact(&mut body).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["tool"], "darkapple");
            assert_eq!(v["host"], "mac1");
            bodies.push(v["body"].clone());
            if let Some(b) = ack {
                s.write_all(&[b]).unwrap();
            }
        }
        bodies
    })
}
#[test]
fn socket_frame_and_ack_semantics() {
    let d = temp();
    let (cfg, listener) = lab(&d);
    let server = fake_darksignal(listener, vec![Some(1), Some(0), Some(2), Some(9), None]);
    assert_eq!(transport::send(&cfg, &json!({})), Ack::Accepted);
    assert_eq!(transport::send(&cfg, &json!({})), Ack::Refused);
    assert_eq!(transport::send(&cfg, &json!({})), Ack::Retry(Retry::Ack));
    assert!(matches!(
        transport::send(&cfg, &json!({})),
        Ack::Retry(Retry::Transport(_))
    ));
    assert!(matches!(
        transport::send(&cfg, &json!({})),
        Ack::Retry(Retry::Transport(_))
    ));
    server.join().unwrap();
    std::fs::remove_file(&cfg.darksignal_socket).unwrap();
    assert!(matches!(
        transport::send(&cfg, &json!({})),
        Ack::Retry(Retry::Transport(_))
    ));
    // A frame that can never fit is a permanent refusal, not an endless retry.
    assert_eq!(
        transport::send(&cfg, &json!({"x":"y".repeat(65536)})),
        Ack::Refused
    );
}
/// Like [`fake_darksignal`], but stops accepting once `done` is set, so a test
/// can script more acks than it expects to be used and count the frames sent.
fn scripted_darksignal(
    listener: UnixListener,
    acks: Vec<u8>,
) -> (
    Arc<AtomicBool>,
    std::thread::JoinHandle<Vec<serde_json::Value>>,
) {
    let done = Arc::new(AtomicBool::new(false));
    let stop = done.clone();
    listener.set_nonblocking(true).unwrap();
    let h = std::thread::spawn(move || {
        let mut bodies = Vec::new();
        let mut acks = acks.into_iter();
        loop {
            let (mut s, _) = match listener.accept() {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if stop.load(Ordering::SeqCst) {
                        return bodies;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("{e}"),
            };
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut len = [0; 4];
            s.read_exact(&mut len).unwrap();
            let mut body = vec![0; u32::from_le_bytes(len) as usize];
            s.read_exact(&mut body).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            bodies.push(v["body"].clone());
            if let Some(b) = acks.next() {
                s.write_all(&[b]).unwrap();
            }
        }
    });
    (done, h)
}
fn attempts(dir: &std::path::Path, id: i64) -> (String, u32, i64) {
    let db = rusqlite::Connection::open(dir.join("events.db")).unwrap();
    db.query_row(
        "SELECT state,attempts,next_try FROM records WHERE id=?",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .unwrap()
}
#[test]
fn ship_stops_at_first_refusal_and_leaves_the_rest_unattempted() {
    let d = temp();
    let (cfg, listener) = lab(&d);
    let mut s = Store::open(&cfg.state_dir, 100).unwrap();
    for pid in 1..=2 {
        s.observe(&process(pid, 1, "/tmp/x")).unwrap();
    }
    let rows = s.pending(0).unwrap();
    // The fake would accept the second record; ship must not send it.
    let (done, server) = scripted_darksignal(listener, vec![0x00, 0x01]);
    let tally = delivery::ship_due(&cfg, &s).unwrap();
    done.store(true, Ordering::SeqCst);
    let bodies = server.join().unwrap();
    assert_eq!(bodies.len(), 1, "exactly one frame sent");
    assert_eq!(bodies[0], rows[0].1);
    assert_eq!(
        tally,
        delivery::Tally {
            refused: 1,
            unattempted: 1,
            ..Default::default()
        }
    );
    assert_eq!(tally.exit_code(), delivery::EXIT_REFUSED);
    let st = s.status().unwrap();
    assert_eq!(
        (st["refused"].clone(), st["pending"].clone()),
        (1.into(), 1.into())
    );
    assert_eq!(st["counters"]["refused"], 1);
    assert!(st["counters"].get("acknowledged").is_none());
    // Still due now, with the same body: no attempt and no backoff recorded.
    let due = s.pending(0).unwrap();
    assert_eq!((due.len(), due[0].0, &due[0].1), (1, rows[1].0, &rows[1].1));
    drop(s);
    assert_eq!(attempts(&cfg.state_dir, rows[0].0).0, "refused");
    assert_eq!(
        attempts(&cfg.state_dir, rows[1].0),
        ("pending".into(), 0, 0)
    );
}
#[test]
fn ship_retry_stops_the_batch_and_is_retained() {
    let d = temp();
    let (cfg, listener) = lab(&d);
    let mut s = Store::open(&cfg.state_dir, 100).unwrap();
    for pid in 1..=3 {
        s.observe(&process(pid, 1, "/tmp/x")).unwrap();
    }
    let ids: Vec<i64> = s.pending(0).unwrap().iter().map(|r| r.0).collect();
    // Accept the first, retry the second; the third is never sent.
    let server = fake_darksignal(listener, vec![Some(1), Some(2)]);
    let tally = delivery::ship_due(&cfg, &s).unwrap();
    let bodies = server.join().unwrap();
    assert_eq!(bodies.len(), 2);
    assert_eq!(
        tally,
        delivery::Tally {
            accepted: 1,
            retained: 1,
            unattempted: 1,
            ..Default::default()
        }
    );
    assert_eq!(tally.exit_code(), delivery::EXIT_RETAINED);
    let st = s.status().unwrap();
    assert_eq!(
        (st["refused"].clone(), st["pending"].clone()),
        (0.into(), 2.into())
    );
    assert_eq!(st["counters"]["retried"], 1);
    assert!(st["counters"].get("transport_errors").is_none());
    let due = s.pending(i64::MAX).unwrap();
    assert_eq!(due[0].0, ids[1]);
    assert_eq!(due[0].1, bodies[1]);
    drop(s);
    assert_eq!(state(&cfg.state_dir, ids[0]), "done");
    assert_eq!(attempts(&cfg.state_dir, ids[1]).1, 1);
    assert_eq!(attempts(&cfg.state_dir, ids[2]), ("pending".into(), 0, 0));
}
fn event_id(s: &Store, id: i64) -> String {
    s.pending(i64::MAX)
        .unwrap()
        .into_iter()
        .find(|r| r.0 == id)
        .unwrap()
        .1["event_id"]
        .as_str()
        .unwrap()
        .to_string()
}
#[test]
fn requeue_refused_restores_pending_with_same_event_and_reset_attempts() {
    let d = temp();
    let dir = d.path().join("state");
    let mut s = Store::open(&dir, 100).unwrap();
    for pid in 1..=4 {
        s.observe(&process(pid, 1, "/tmp/x")).unwrap();
    }
    let rows = s.pending(0).unwrap();
    let eids: Vec<String> = rows.iter().map(|r| event_id(&s, r.0)).collect();
    // rows[0], rows[1]: refused after retries; rows[2]: done; rows[3]: pending.
    for r in &rows[..2] {
        s.retry(r.0, 0, 0, true).unwrap();
        s.retry(r.0, 1, 0, true).unwrap();
        s.refuse(r.0).unwrap();
    }
    s.acknowledge(rows[2].0).unwrap();
    s.retry(rows[3].0, 0, 0, false).unwrap();
    let pending_before = attempts(&dir, rows[3].0);
    assert_eq!(attempts(&dir, rows[0].0).1, 3);
    let unknown = "00000000-0000-4000-8000-000000000001".to_string();
    let ask = vec![
        eids[0].clone(),
        eids[0].clone(),
        unknown.clone(),
        eids[2].clone(),
        eids[3].clone(),
    ];
    let (n, missing) = s.requeue_refused(Some(&ask), 5_000).unwrap();
    assert_eq!(n, 1);
    assert_eq!(missing, vec![unknown, eids[2].clone(), eids[3].clone()]);
    // Requeued: pending, attempts reset, due now, identical stored event.
    assert_eq!(attempts(&dir, rows[0].0), ("pending".into(), 0, 5_000));
    let due = s.pending(5_000).unwrap();
    let back = due.iter().find(|r| r.0 == rows[0].0).unwrap();
    assert_eq!((&back.1, back.2), (&rows[0].1, 0));
    // Not named, not requeued; done and pending rows untouched.
    assert_eq!(attempts(&dir, rows[1].0).0, "refused");
    assert_eq!(attempts(&dir, rows[2].0).0, "done");
    assert_eq!(attempts(&dir, rows[3].0), pending_before);
    let st = s.status().unwrap();
    assert_eq!(
        (st["refused"].clone(), st["pending"].clone()),
        (1.into(), 2.into())
    );
    assert_eq!(st["counters"]["requeued"], 1);
    // --all takes every refused row and only those.
    let (n, missing) = s.requeue_refused(None, 6_000).unwrap();
    assert_eq!((n, missing.len()), (1, 0));
    assert_eq!(attempts(&dir, rows[1].0), ("pending".into(), 0, 6_000));
    assert_eq!(attempts(&dir, rows[2].0).0, "done");
    assert_eq!(attempts(&dir, rows[0].0), ("pending".into(), 0, 5_000));
    assert_eq!(s.requeue_refused(None, 7_000).unwrap(), (0, vec![]));
    let st = s.status().unwrap();
    assert_eq!(
        (st["refused"].clone(), st["pending"].clone()),
        (0.into(), 3.into())
    );
    assert_eq!(st["counters"]["requeued"], 2);
}
#[test]
fn requeue_refused_validates_ids_before_changing_anything() {
    let d = temp();
    let dir = d.path().join("state");
    let mut s = Store::open(&dir, 100).unwrap();
    s.observe(&process(1, 1, "/tmp/x")).unwrap();
    let row = s.pending(0).unwrap()[0].clone();
    let good = event_id(&s, row.0);
    s.refuse(row.0).unwrap();
    let too_many: Vec<String> = (0..=store::MAX_REQUEUE_IDS)
        .map(|i| format!("00000000-0000-4000-8000-{i:012x}"))
        .collect();
    for bad in [
        vec![],
        vec![good.clone(), "not-a-uuid".into()],
        vec![good.to_uppercase()],
        vec![good.replace('-', "")],
        vec![format!("{good}' OR 1=1 --")],
        too_many,
    ] {
        assert!(s.requeue_refused(Some(&bad), 1).is_err(), "{bad:?}");
    }
    assert_eq!(attempts(&dir, row.0).0, "refused");
    assert!(s.status().unwrap()["counters"].get("requeued").is_none());
    assert!(store::valid_event_id(&good));
    assert_eq!(s.requeue_refused(Some(&[good]), 1).unwrap(), (1, vec![]));
}
/// Runs the real CLI against a lab config.
fn cli(cfg: &Config, args: &[&str]) -> std::process::Output {
    let path = cfg.state_dir.with_file_name("config.json");
    std::fs::write(&path, serde_json::to_vec(cfg).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::process::Command::new(env!("CARGO_BIN_EXE_darkapple"))
        .arg(args[0])
        .arg("--config")
        .arg(&path)
        .args(&args[1..])
        .arg("--json")
        .output()
        .unwrap()
}
#[test]
fn requeue_refused_cli_flags_exit_codes_and_writer_lock() {
    let d = temp();
    let (cfg, _listener) = lab(&d);
    let mut s = Store::open(&cfg.state_dir, 100).unwrap();
    for pid in 1..=2 {
        s.observe(&process(pid, 1, "/tmp/x")).unwrap();
    }
    let rows = s.pending(0).unwrap();
    let eids: Vec<String> = rows.iter().map(|r| event_id(&s, r.0)).collect();
    for r in &rows {
        s.refuse(r.0).unwrap();
    }
    // While another writer (here the test; in production `run`) holds the lock.
    let o = cli(&cfg, &["requeue-refused", "--all"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("another darkapple writer"),
        "{o:?}"
    );
    drop(s);
    assert_eq!(state(&cfg.state_dir, rows[0].0), "refused");
    // Neither or both selectors: refused before touching state.
    for args in [
        &["requeue-refused"][..],
        &["requeue-refused", "--all", "--event-id", &eids[0]],
        &["requeue-refused", "--all", "--all"],
    ] {
        let o = cli(&cfg, args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
    }
    let o = cli(&cfg, &["requeue-refused", "--event-id", "nope"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("invalid event ID"));
    assert_eq!(state(&cfg.state_dir, rows[0].0), "refused");
    // One requeued, one unknown: exit 2, both reported.
    let unknown = "00000000-0000-4000-8000-000000000009";
    let o = cli(
        &cfg,
        &[
            "requeue-refused",
            "--event-id",
            &eids[0],
            "--event-id",
            unknown,
        ],
    );
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    let out: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(out["kind"], "darkapple.requeue_refused");
    assert_eq!(
        (&out["requeued"], &out["not_requeued"]),
        (&json!(1), &json!([unknown]))
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains(unknown));
    // A no-longer-refused id is reported too.
    let o = cli(&cfg, &["requeue-refused", "--event-id", &eids[0]]);
    assert_eq!(o.status.code(), Some(2));
    // --all requeues the rest, exit 0, counted in the published status.
    let o = cli(&cfg, &["requeue-refused", "--all"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let out: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(out["kind"], "darkapple.requeue_refused");
    assert_eq!(
        (&out["requeued"], &out["not_requeued"]),
        (&json!(1), &json!([]))
    );
    let st: serde_json::Value = serde_json::from_slice(&cli(&cfg, &["status"]).stdout).unwrap();
    assert_eq!(st["store"]["pending"], 2);
    assert_eq!(st["store"]["counters"]["requeued"], 2);
}
#[test]
fn hidden_executable_allowlist_both_directions() {
    let d = temp();
    let mut s = Store::open(&d.path().join("state"), 100).unwrap();
    let quiet = [
        "/Users/dev/.vscode/extensions/ms-x/bin/tool",
        "/Users/dev/.cargo/bin/cargo",
        "/Users/dev/.rustup/toolchains/1.97.1/bin/rustc",
        "/Users/dev/.npm/_npx/1/node_modules/x/cli",
        "/Users/dev/.nvm/versions/node/v20/bin/node",
        "/Users/dev/.local/bin/uv",
        "/Users/dev/.docker/cli-plugins/docker-buildx",
        "/Users/dev/.pyenv/shims/python",
        "/Users/dev/.bun/bin/bun",
    ];
    let loud = [
        "/opt/.cache/miner",
        "/Users/dev/.hidden-random/x",
        "/Users/Shared/.cargo/bin/x",
        "/Users/dev/.cargo/.evil/x",
        "/Users/dev/.npm/_npx/1/node_modules/.bin/x",
        "/Users/dev/Library/.x/y",
        "/Users/.cargo/bin/x",
        "/private/var/root/.cargo/bin/x",
    ];
    let mut pid = 0;
    let mut rules = |s: &mut Store, exe: &str| {
        pid += 1;
        let before = s.pending(i64::MAX).unwrap().len();
        s.observe(&process(pid, 1, exe)).unwrap();
        let after = s.pending(i64::MAX).unwrap();
        (after.len() > before).then(|| after.last().unwrap().1["rule_id"].clone())
    };
    for exe in quiet {
        assert_eq!(rules(&mut s, exe), None, "{exe}");
    }
    // Only the first hidden component can be excused; a nested one still fires.
    for exe in loud {
        assert_eq!(
            rules(&mut s, exe),
            Some(json!("macos.process.hidden_executable")),
            "{exe}"
        );
    }
    assert_eq!(
        rules(&mut s, "/tmp/.x"),
        Some(json!("macos.process.temporary_executable"))
    );
    // An empty allowlist restores detection for toolchain directories.
    s.set_hidden_allowlist(vec![]);
    assert_eq!(
        rules(&mut s, "/Users/dev/.cargo/bin/cargo"),
        Some(json!("macos.process.hidden_executable"))
    );
}
#[test]
fn hidden_dir_allowlist_config_is_validated() {
    let base = json!({"host":"mac1","state_dir":"/private/tmp/s","darksignal_socket":"/private/tmp/x.sock"});
    let parse = |extra: serde_json::Value| {
        let mut v = base.clone();
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value::<Config>(v)
            .map_err(|e| e.to_string())
            .and_then(|c| c.validate().map(|_| c).map_err(|e| e.to_string()))
    };
    let c = parse(json!({})).unwrap();
    assert!(c.hidden_dir_allowlist.contains(&".cargo".to_string()));
    assert_eq!(
        parse(json!({"hidden_dir_allowlist":[".cargo"]}))
            .unwrap()
            .hidden_dir_allowlist,
        vec![".cargo"]
    );
    assert!(parse(json!({"hidden_dir_allowlist":[]})).is_ok());
    for bad in [
        "cargo",
        ".",
        "..",
        ".a/b",
        "",
        ".x y",
        &format!(".{}", "a".repeat(64)),
    ] {
        assert!(
            parse(json!({"hidden_dir_allowlist":[bad]})).is_err(),
            "{bad:?}"
        );
    }
    let many: Vec<String> = (0..65).map(|i| format!(".d{i}")).collect();
    assert!(parse(json!({"hidden_dir_allowlist":many})).is_err());
    assert!(parse(json!({"hidden_dir_allow":[".cargo"]})).is_err());
}

#[test]
fn new_launchd_file_after_completed_directory_baseline_is_detected() {
    let d = temp();
    let directory = d.path().join("LaunchAgents");
    std::fs::create_dir(&directory).unwrap();
    let mut store = Store::open(&d.path().join("state"), 100).unwrap();
    let (first, coverage) = darkapple::sources::launchd(std::slice::from_ref(&directory));
    assert_eq!(coverage.status, "available");
    for o in first {
        store.observe(&o).unwrap();
    }
    std::fs::write(directory.join("new.plist"), b"fixture").unwrap();
    let (next, _) = darkapple::sources::launchd(&[directory]);
    for o in next {
        store.observe(&o).unwrap();
    }
    assert_eq!(
        store.pending(i64::MAX).unwrap()[0].1["rule_id"],
        "macos.persistence.launchd_changed"
    );
}
#[test]
fn hostile_launchd_names_and_symlinks_report_partial_without_stopping() {
    let d = temp();
    let directory = d.path().join("LaunchAgents");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("line\nbreak.plist"), b"fixture").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", directory.join("link.plist")).unwrap();
    let (events, coverage) = darkapple::sources::launchd(&[directory]);
    assert_eq!(coverage.status, "partial");
    assert!(events.is_empty());
}
