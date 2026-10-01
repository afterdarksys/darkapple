use darkapple::{
    config::Config, fs, model::Observation, sources::observation, store::Store, transport,
};
use serde_json::json;
use std::{
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
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
fn refusal_retries_without_deleting_or_changing_id() {
    let d = temp();
    let mut s = Store::open(&d.path().join("state"), 100).unwrap();
    s.observe(&process(1, 1, "/tmp/a")).unwrap();
    let row = s.pending(0).unwrap()[0].clone();
    s.retry(row.0, 0, 10, true).unwrap();
    assert!(s.pending(11).unwrap().is_empty());
    assert_eq!(s.pending(1010).unwrap()[0].1, row.1);
    assert_eq!(s.status().unwrap()["counters"]["refused"], 1);
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
#[test]
fn socket_frame_and_ack_semantics() {
    let d = temp();
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
    };
    let server = std::thread::spawn(move || {
        for ack in [1u8, 0, 9] {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut len = [0; 4];
            s.read_exact(&mut len).unwrap();
            let mut body = vec![0; u32::from_le_bytes(len) as usize];
            s.read_exact(&mut body).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["tool"], "darkapple");
            assert_eq!(v["host"], "mac1");
            s.write_all(&[ack]).unwrap();
        }
    });
    assert!(transport::send(&cfg, &json!({})).unwrap());
    assert!(!transport::send(&cfg, &json!({})).unwrap());
    assert!(transport::send(&cfg, &json!({})).is_err());
    server.join().unwrap();
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
