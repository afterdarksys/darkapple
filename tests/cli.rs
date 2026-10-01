//! The After Dark CLI output contract (docs/output-contract.md) for the
//! `darkapple` binary: envelopes, JSON errors, help, and status staleness.
use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};
const COMMANDS: [&str; 8] = [
    "version",
    "check",
    "once",
    "run",
    "status",
    "replay",
    "ship",
    "requeue-refused",
];
struct Lab {
    _dir: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    state: PathBuf,
}
/// A private lab with a config whose Darksignal socket does not exist, so
/// delivery fails as a transport error without a live peer.
fn lab() -> Lab {
    let dir = tempfile::Builder::new()
        .prefix("darkapple-cli-")
        .tempdir_in("/private/tmp")
        .unwrap();
    let root = dir.path().to_path_buf();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.join("state");
    let config = root.join("config.json");
    private_write(
        &config,
        &json!({"host":"mac1","state_dir":state,"darksignal_socket":root.join("absent.sock"),
            "interval_seconds":1,"capacity":100,"retention_days":1,"launch_dirs":[]})
        .to_string(),
    );
    Lab {
        _dir: dir,
        root,
        config,
        state,
    }
}
fn private_write(p: &Path, s: &str) {
    std::fs::write(p, s).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn da(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_darkapple"))
        .args(args)
        .output()
        .unwrap()
}
fn cfg<'a>(l: &'a Lab, cmd: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut v = vec![cmd, "--config", l.config.to_str().unwrap()];
    v.extend(extra);
    v
}
/// Asserts the success envelope: one compact line, envelope fields first and
/// correct, and the documented exit code.
fn envelope(o: &Output, kind: &str, code: i32) -> Value {
    assert_eq!(o.status.code(), Some(code), "{o:?}");
    let out = String::from_utf8(o.stdout.clone()).unwrap();
    assert!(out.ends_with('\n') && out.lines().count() == 1, "{out:?}");
    let prefix = format!(
        "{{\"schema_version\":1,\"kind\":\"darkapple.{kind}\",\"tool\":\"darkapple\",\"tool_version\":\"{}\",",
        env!("CARGO_PKG_VERSION")
    );
    assert!(out.starts_with(&prefix), "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(v.is_object());
    v
}
/// Asserts one JSON error line on stderr with the six base fields, empty
/// stdout, and an exit code matching `exit_code`.
fn json_error(o: &Output, category: &str, command: Option<&str>) -> Value {
    assert!(o.stdout.is_empty(), "stdout must be empty: {o:?}");
    let err = String::from_utf8(o.stderr.clone()).unwrap();
    assert!(err.ends_with('\n') && err.lines().count() == 1, "{err:?}");
    let v: Value = serde_json::from_str(&err).unwrap();
    assert_eq!(v["schema_version"], 1, "{v}");
    assert_eq!(v["kind"], "error");
    assert_eq!(v["tool"], "darkapple");
    assert_eq!(v["command"], json!(command), "{v}");
    assert_eq!(v["category"], category, "{v}");
    assert!(v["message"].as_str().is_some_and(|m| !m.is_empty()));
    assert_eq!(v["exit_code"], 2);
    assert_eq!(o.status.code(), Some(2));
    v
}
fn fixture(l: &Lab) -> PathBuf {
    let p = l.root.join("observations.jsonl");
    std::fs::write(
        &p,
        json!({"source":"process","kind":"process.observed","observed_at_ms":1780000000000_i64,
            "pid":4242,"start_us":1234567,"exe":"/opt/.cache/example","value":"present"})
        .to_string()
            + "\n",
    )
    .unwrap();
    p
}
#[test]
fn every_subcommand_prints_one_envelope_with_json() {
    let l = lab();
    let v = envelope(&da(&["version", "--json"]), "version", 0);
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    envelope(&da(&["--version", "--json"]), "version", 0);
    let v = envelope(&da(&cfg(&l, "check", &["--json"])), "check", 0);
    assert_eq!((&v["ok"], &v["host"]), (&json!(true), &json!("mac1")));
    // Empty queue: nothing due, exit 0.
    let v = envelope(&da(&cfg(&l, "ship", &["--json"])), "ship", 0);
    assert_eq!(v["tally"]["accepted"], 0);
    let input = fixture(&l);
    let v = envelope(
        &da(&cfg(
            &l,
            "replay",
            &["--input", input.to_str().unwrap(), "--json"],
        )),
        "replay",
        0,
    );
    assert_eq!((&v["replayed"], &v["pending"]), (&json!(1), &json!(1)));
    let v = envelope(&da(&cfg(&l, "status", &["--json"])), "status", 0);
    assert_eq!(v["schema"], "darkapple.status.v1");
    assert_eq!(
        (&v["stale"], &v["store"]["pending"]),
        (&json!(false), &json!(1))
    );
    // Absent socket: transport failure, record retained, exit 2 with a payload.
    let o = da(&cfg(&l, "ship", &["--json"]));
    let v = envelope(&o, "ship", 2);
    assert_eq!(
        (&v["tally"]["retained"], &v["pending"]),
        (&json!(1), &json!(1))
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("retained for retry"));
    let v = envelope(
        &da(&cfg(&l, "requeue-refused", &["--all", "--json"])),
        "requeue_refused",
        0,
    );
    assert_eq!(v["requeued"], 0);
    let v = envelope(&da(&cfg(&l, "once", &["--json"])), "once", 0);
    assert!(v["store"]["records"].as_i64().unwrap() >= 1 && v["coverage"].is_object());
    // `--format json` is an alias, also before the command.
    envelope(&da(&cfg(&l, "check", &["--format", "json"])), "check", 0);
    envelope(&da(&["--format", "json", "version"]), "version", 0);
    // run is a daemon: no stdout, the envelope goes to status.json.
    let started = darkapple::now_ms();
    let mut child = Command::new(env!("CARGO_BIN_EXE_darkapple"))
        .args(cfg(&l, "run", &["--json"]))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let file: Option<Value> = std::fs::read(l.state.join("status.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        if file.is_some_and(|f| f["updated_at_ms"].as_i64() > Some(started)) {
            break;
        }
        assert!(Instant::now() < deadline, "run never published status");
        std::thread::sleep(Duration::from_millis(100));
    }
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "run did not stop");
        std::thread::sleep(Duration::from_millis(100));
    }
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(o.stdout.is_empty(), "{o:?}");
    let raw = std::fs::read_to_string(l.state.join("status.json")).unwrap();
    assert!(raw.starts_with("{\"schema_version\":1,\"kind\":\"darkapple.status\",\"tool\":\"darkapple\",\"tool_version\":"), "{raw}");
    let v: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["schema"], "darkapple.status.v1");
    assert!(v["coverage"].is_object() && v["store"]["counters"].is_object());
}
#[test]
fn default_output_is_human_text() {
    let l = lab();
    for (args, needle) in [
        (
            vec!["version"],
            format!("darkapple {}", env!("CARGO_PKG_VERSION")),
        ),
        (
            cfg(&l, "check", &[]),
            "configuration ok for host mac1".into(),
        ),
        (cfg(&l, "ship", &[]), "ship: 0 accepted".into()),
        (
            cfg(&l, "status", &[]),
            "darkapple status for host mac1".into(),
        ),
        (
            cfg(&l, "check", &["--format", "text"]),
            "configuration ok".into(),
        ),
    ] {
        let o = da(&args);
        assert_eq!(o.status.code(), Some(0), "{args:?} {o:?}");
        let out = String::from_utf8(o.stdout).unwrap();
        assert!(out.contains(&needle), "{args:?}: {out}");
        assert!(serde_json::from_str::<Value>(&out).is_err(), "{out}");
    }
    // Text-mode errors are one plain line.
    let o = da(&[
        "check",
        "--config",
        "/private/tmp/darkapple-no-such-config.json",
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(o.stdout.is_empty());
    let err = String::from_utf8(o.stderr).unwrap();
    assert!(
        err.starts_with("darkapple: config ") && err.lines().count() == 1,
        "{err}"
    );
}
#[test]
fn json_errors_go_to_stderr_with_the_six_fields() {
    let l = lab();
    // Usage errors, including before a command is known.
    json_error(&da(&["--json"]), "usage", None);
    json_error(&da(&["bogus", "--json"]), "usage", None);
    json_error(
        &da(&["--json", "version", "extra"]),
        "usage",
        Some("version"),
    );
    json_error(&da(&["ship", "--json"]), "usage", Some("ship"));
    json_error(
        &da(&cfg(&l, "check", &["--bogus", "--json"])),
        "usage",
        Some("check"),
    );
    json_error(
        &da(&cfg(&l, "check", &["--json", "--format", "text"])),
        "usage",
        Some("check"),
    );
    let v = json_error(
        &da(&cfg(&l, "requeue-refused", &["--json"])),
        "usage",
        Some("requeue-refused"),
    );
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("requires --event-id")
    );
    json_error(
        &da(&cfg(
            &l,
            "requeue-refused",
            &["--event-id", "nope", "--json"],
        )),
        "usage",
        Some("requeue-refused"),
    );
    // Config errors: missing file, invalid content.
    json_error(
        &da(&[
            "check",
            "--config",
            "/private/tmp/darkapple-no-such-config.json",
            "--json",
        ]),
        "config",
        Some("check"),
    );
    private_write(
        &l.config,
        r#"{"host":"bad..host","state_dir":"/x","darksignal_socket":"/y"}"#,
    );
    json_error(&da(&cfg(&l, "check", &["--json"])), "config", Some("check"));
    // Control and bidi characters never reach the terminal raw.
    let v = json_error(&da(&["bogus\u{202e}\u{1b}[2J", "--json"]), "usage", None);
    let m = v["message"].as_str().unwrap();
    assert!(
        !m.contains('\u{202e}') && !m.contains('\u{1b}') && m.contains("\\u{202e}"),
        "{m}"
    );
    let o = da(&["bogus\u{202e}"]);
    assert!(!String::from_utf8_lossy(&o.stderr).contains('\u{202e}'));
}
#[test]
fn status_reports_io_error_and_staleness_without_the_writer_lock() {
    let l = lab();
    // No status published yet.
    json_error(&da(&cfg(&l, "status", &["--json"])), "io", Some("status"));
    // A writer holds the lock; status still reads.
    let input = fixture(&l);
    assert_eq!(
        da(&cfg(&l, "replay", &["--input", input.to_str().unwrap()]))
            .status
            .code(),
        Some(0)
    );
    let _lock = darkapple::store::Store::open(&l.state, 100).unwrap();
    let v = envelope(&da(&cfg(&l, "status", &["--json"])), "status", 0);
    assert_eq!(
        (&v["stale"], &v["stale_after_ms"]),
        (&json!(false), &json!(3000))
    );
    assert!(v["age_ms"].as_i64().unwrap() >= 0);
    // Injected old, future and missing timestamps are stale; existing fields kept.
    let file = l.state.join("status.json");
    let mut st: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    let now = darkapple::now_ms();
    for (updated, stale) in [
        (json!(now - 3_600_000), true),
        (json!(now + 3_600_000), true),
        (Value::Null, true),
        (json!(now - 1000), false),
    ] {
        st["updated_at_ms"] = updated.clone();
        private_write(&file, &st.to_string());
        let v = envelope(&da(&cfg(&l, "status", &["--json"])), "status", 0);
        assert_eq!(v["stale"], stale, "{updated}");
        assert_eq!(v["host"], "mac1");
        let text = String::from_utf8(da(&cfg(&l, "status", &[])).stdout).unwrap();
        assert_eq!(text.contains("STALE"), stale, "{text}");
    }
}
#[test]
fn help_exits_zero_and_covers_every_command() {
    for args in [&["--help"][..], &["-h"], &["help"], &["--json", "help"]] {
        let o = da(args);
        assert_eq!(o.status.code(), Some(0), "{args:?}");
        let out = String::from_utf8(o.stdout).unwrap();
        for c in COMMANDS {
            assert!(out.contains(c), "{args:?} lacks {c}");
        }
        assert!(out.contains("Exit codes"));
    }
    for c in COMMANDS {
        for args in [vec![c, "--help"], vec![c, "-h"], vec!["help", c]] {
            let o = da(&args);
            assert_eq!(o.status.code(), Some(0), "{args:?}");
            let out = String::from_utf8(o.stdout).unwrap();
            assert!(
                out.contains(&format!("darkapple {c}")) && out.contains("Exit codes"),
                "{out}"
            );
            assert!(out.contains("--json"));
        }
    }
    let ship = String::from_utf8(da(&["ship", "--help"]).stdout).unwrap();
    assert!(ship.contains("3 a record permanently refused"), "{ship}");
}
