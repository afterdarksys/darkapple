use darkapple::{
    Result,
    config::Config,
    delivery,
    model::{Coverage, Observation},
    sources,
    store::{self, Store},
    transport,
};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    fmt::Display,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, TryRecvError},
    },
    time::{Duration, Instant},
};
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: i32) {
    STOP.store(true, Ordering::Relaxed);
}
const TOOL: &str = "darkapple";
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Every failure exits 2. The suite contract reserves 1 for runtime failures
/// and 2 for usage/config errors; darkapple keeps its documented 2 for all
/// failures (see docs/output-contract.md section 4 and the README).
const EXIT_FAILURE: i32 = 2;
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
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Text,
    Json,
}
/// A failure with its contract category (docs/output-contract.md section 3).
struct Fail {
    category: &'static str,
    message: String,
}
impl Fail {
    fn new(category: &'static str, message: impl Display) -> Self {
        Self {
            category,
            message: message.to_string(),
        }
    }
}
impl From<Box<dyn std::error::Error + Send + Sync>> for Fail {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Fail::new("io", e)
    }
}
fn cat<E: Display>(category: &'static str) -> impl FnOnce(E) -> Fail {
    move |e| Fail::new(category, e)
}
fn usage(message: impl Display) -> Fail {
    Fail::new(
        "usage",
        format!("{message} (run `darkapple help` for usage)"),
    )
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(f) => {
            let command = normalize(&args);
            let command = command
                .first()
                .map(|a| if a == "--version" { "version" } else { a })
                .filter(|a| COMMANDS.contains(a));
            report(&f, wants_json(&args), command);
            std::process::exit(EXIT_FAILURE);
        }
    }
}
/// Decides the error format before (or when) parsing fails, so even usage
/// errors are JSON when the caller asked for JSON.
fn wants_json(args: &[String]) -> bool {
    args.iter().any(|a| a == "--json") || args.windows(2).any(|w| w == ["--format", "json"])
}
fn report(f: &Fail, json: bool, command: Option<&str>) {
    let message = clean(&f.message);
    if json {
        eprintln!(
            "{}",
            ordered(
                &[
                    ("schema_version", json!(1)),
                    ("kind", json!("error")),
                    ("tool", json!(TOOL)),
                    ("command", json!(command)),
                    ("category", json!(f.category)),
                    ("message", json!(message)),
                    ("exit_code", json!(EXIT_FAILURE)),
                ],
                &Map::new(),
            )
        );
    } else {
        eprintln!("{TOOL}: {message}");
    }
}
/// Escapes control and bidi characters so messages and text output never
/// carry raw terminal or direction-override bytes from untrusted input.
fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control()
            || matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}
/// Serializes `head` first, in order, then the remaining `rest` fields (sorted).
/// Keys present in `head` are taken from `head` only.
fn ordered(head: &[(&str, Value)], rest: &Map<String, Value>) -> String {
    let mut fields: Vec<String> = head
        .iter()
        .map(|(k, v)| format!("{}:{v}", Value::from(*k)))
        .collect();
    fields.extend(
        rest.iter()
            .filter(|(k, _)| !head.iter().any(|(h, _)| h == k))
            .map(|(k, v)| format!("{}:{v}", Value::from(k.as_str()))),
    );
    format!("{{{}}}", fields.join(","))
}
/// The success envelope (contract section 2) around an object payload.
fn envelope(kind: &str, payload: &Value) -> String {
    let empty = Map::new();
    ordered(
        &[
            ("schema_version", json!(1)),
            ("kind", json!(format!("{TOOL}.{kind}"))),
            ("tool", json!(TOOL)),
            ("tool_version", json!(VERSION)),
        ],
        payload.as_object().unwrap_or(&empty),
    )
}
/// Prints the envelope in JSON mode, the human rendering otherwise.
fn emit(mode: Mode, kind: &str, payload: &Value, text: impl FnOnce() -> String) {
    match mode {
        Mode::Json => println!("{}", envelope(kind, payload)),
        Mode::Text => println!("{}", text()),
    }
}
const EXITS_COMMON: &str =
    "Exit codes: 0 success; 2 usage, configuration, I/O or any other failure.";
fn help(cmd: Option<&str>) -> String {
    let (synopsis, about, exits) = match cmd {
        Some("version") => (
            "darkapple version [--json]",
            "Print the version.",
            EXITS_COMMON,
        ),
        Some("check") => (
            "darkapple check --config PATH [--json]",
            "Validate configuration and helper-path trust without collecting, creating state or sending.",
            EXITS_COMMON,
        ),
        Some("once") => (
            "darkapple once --config PATH [--json]",
            "Collect once and journal the observations; no shipment.",
            EXITS_COMMON,
        ),
        Some("run") => (
            "darkapple run --config PATH [--json]",
            "Collect continuously and ship independently until SIGINT/SIGTERM. Writes no stdout; publishes STATE_DIR/status.json every interval_seconds and on shutdown. --json only makes failures JSON on stderr.",
            "Exit codes: 0 clean shutdown; 2 failure (including a delivery-worker failure).",
        ),
        Some("status") => (
            "darkapple status --config PATH [--json]",
            "Read STATE_DIR/status.json (never takes the writer lock). stale is true when updated_at_ms is older than 3 x interval_seconds (or missing or in the future by as much).",
            EXITS_COMMON,
        ),
        Some("replay") => (
            "darkapple replay --config PATH --input JSONL [--json]",
            "Validate a fixture of observations completely, then journal it.",
            EXITS_COMMON,
        ),
        Some("ship") => (
            "darkapple ship --config PATH [--json]",
            "Send up to 32 due records in order, stopping at the first that is not accepted. A summary goes to stdout and the reason for a stop to stderr.",
            "Exit codes: 0 every due record accepted; 2 a record retained for retry (0x02 or transport failure), or any failure; 3 a record permanently refused (0x00).",
        ),
        Some("requeue-refused") => (
            "darkapple requeue-refused --config PATH (--event-id ID ... | --all) [--json]",
            "Move refused records back to pending (attempts reset, due now). --event-id takes canonical lowercase UUIDs (at most 256); exactly one of --event-id or --all.",
            "Exit codes: 0 every named ID requeued (or --all); 2 an ID was unknown or not refused (the result still goes to stdout, the IDs to stderr), or any failure.",
        ),
        _ => {
            return format!(
                "darkapple {VERSION}: continuous macOS sensor for the After Dark ecosystem

Usage: darkapple COMMAND [FLAGS]

Commands:
  version          print the version
  check            validate configuration only
  once             collect once and journal
  run              collect and ship continuously (daemon)
  status           read the published status.json and report staleness
  replay           journal a validated observation fixture
  ship             send due records once
  requeue-refused  move refused records back to pending
  help [COMMAND]   show help (also --help / -h on any command)

Output: human text by default; --json (or --format json) prints one JSON
envelope on stdout and JSON errors on stderr. --format text selects text.

Exit codes: 0 success; 2 usage, configuration, I/O or any other failure;
ship also uses 2 (retained for retry) and 3 (permanently refused).
Run `darkapple help COMMAND` for a command's flags and exit codes."
            );
        }
    };
    format!(
        "Usage: {synopsis}

{about}

Flags:
  --config PATH      absolute path to the JSON config (all commands except version)
  --json             one JSON envelope on stdout; errors as one JSON line on stderr
  --format json|text alias for --json / select human text (default)
  -h, --help         show this help

{exits}"
    )
}
struct Args {
    cmd: String,
    help: bool,
    mode: Mode,
    config: Option<PathBuf>,
    input: Option<PathBuf>,
    event_ids: Vec<String>,
    all: bool,
}
/// Global output flags may also precede the command: moves them after it.
fn normalize(args: &[String]) -> Vec<String> {
    let mut lead = 0;
    while let Some(a) = args.get(lead) {
        lead += match a.as_str() {
            "--json" => 1,
            "--format" => 2,
            _ => break,
        };
    }
    let lead = lead.min(args.len());
    args[lead..]
        .iter()
        .take(1)
        .chain(&args[..lead])
        .chain(args[lead..].iter().skip(1))
        .cloned()
        .collect()
}
fn parse(args: &[String]) -> std::result::Result<Args, Fail> {
    let args = normalize(args);
    let first = args
        .first()
        .filter(|f| *f != "--json" && *f != "--format")
        .ok_or_else(|| usage("missing command"))?;
    let mut a = Args {
        cmd: String::new(),
        help: false,
        mode: Mode::Text,
        config: None,
        input: None,
        event_ids: Vec::new(),
        all: false,
    };
    if ["help", "--help", "-h"].contains(&first.as_str()) {
        a.help = true;
        let rest: Vec<&String> = args[1..].iter().filter(|a| *a != "--json").collect();
        match rest[..] {
            [] => {}
            [c] if COMMANDS.contains(&c.as_str()) => a.cmd = c.clone(),
            _ => return Err(usage("help takes at most one known command")),
        }
        return Ok(a);
    }
    a.cmd = match first.as_str() {
        "--version" => "version".into(),
        c if COMMANDS.contains(&c) => c.into(),
        other => {
            return Err(usage(format!(
                "unknown command `{}`",
                other.chars().take(64).collect::<String>()
            )));
        }
    };
    let cmd = a.cmd.as_str();
    let requeue = cmd == "requeue-refused";
    let (mut json, mut format) = (false, None);
    let mut i = 1;
    while i < args.len() {
        let flag = args[i].as_str();
        match flag {
            "--help" | "-h" => a.help = true,
            "--json" if !json => json = true,
            "--all" if requeue && !a.all => a.all = true,
            "--config" | "--input" | "--event-id" | "--format" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| usage(format!("{flag} needs a value")))?;
                match flag {
                    "--config" if cmd != "version" && a.config.is_none() => {
                        a.config = Some(PathBuf::from(val))
                    }
                    "--input" if cmd == "replay" && a.input.is_none() => {
                        a.input = Some(PathBuf::from(val))
                    }
                    // Count and format are validated below and by Store::requeue_refused.
                    "--event-id" if requeue => a.event_ids.push(val.clone()),
                    "--format" if format.is_none() => {
                        format = Some(match val.as_str() {
                            "json" => Mode::Json,
                            "text" => Mode::Text,
                            _ => return Err(usage("--format must be json or text")),
                        })
                    }
                    _ => return Err(usage(format!("{flag} not allowed here for {cmd}"))),
                }
                i += 1;
            }
            other => {
                return Err(usage(format!(
                    "unknown or repeated argument `{}` for {cmd}",
                    other.chars().take(64).collect::<String>()
                )));
            }
        }
        i += 1;
    }
    a.mode = match (json, format) {
        (true, Some(Mode::Text)) => return Err(usage("--json conflicts with --format text")),
        (true, _) | (_, Some(Mode::Json)) => Mode::Json,
        _ => Mode::Text,
    };
    if a.help || cmd == "version" {
        return Ok(a);
    }
    if a.config.is_none() {
        return Err(usage(format!("{cmd} requires --config PATH")));
    }
    if cmd == "replay" && a.input.is_none() {
        return Err(usage("replay requires --input JSONL"));
    }
    if requeue {
        // No silent mass action: name the records, or say --all, never both.
        if a.all == !a.event_ids.is_empty() || a.event_ids.len() > store::MAX_REQUEUE_IDS {
            return Err(usage(format!(
                "requeue-refused requires --event-id ID (up to {}) or --all, not both",
                store::MAX_REQUEUE_IDS
            )));
        }
        if let Some(bad) = a.event_ids.iter().find(|id| !store::valid_event_id(id)) {
            return Err(usage(format!(
                "invalid event ID {:?}",
                bad.chars().take(64).collect::<String>()
            )));
        }
    }
    Ok(a)
}
fn store_line(s: &Value) -> String {
    format!(
        "store: {} records, {} pending, {} refused (capacity {})",
        s["records"], s["pending"], s["refused"], s["capacity"]
    )
}
fn coverage_lines(coverage: &Value) -> String {
    let mut out = String::from("coverage:");
    if let Some(m) = coverage.as_object() {
        for (source, h) in m {
            let status = h["status"].as_str().unwrap_or("?");
            let detail = h["detail"].as_str().unwrap_or("");
            out.push_str(&format!("\n  {}: {}", clean(source), clean(status)));
            if !detail.is_empty() {
                out.push_str(&format!(" ({})", clean(detail)));
            }
        }
    }
    out
}
fn counters_line(store: &Value) -> String {
    let counters = store["counters"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| format!("{}={v}", clean(k)))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    format!(
        "counters: {}",
        if counters.is_empty() {
            "none"
        } else {
            &counters
        }
    )
}
/// True when a status snapshot cannot be trusted as current: no timestamp, or
/// one more than 3 write intervals in the past (or in the future).
fn is_stale(updated_at_ms: Option<i64>, now_ms: i64, interval_seconds: u64) -> bool {
    let limit = 3 * 1000 * interval_seconds as i64;
    updated_at_ms.is_none_or(|u| now_ms.saturating_sub(u).saturating_abs() > limit)
}
/// Returns the process exit code; only `ship` (see `delivery::Tally::exit_code`)
/// and `requeue-refused` return a nonzero `Ok`.
fn run(args: &[String]) -> std::result::Result<i32, Fail> {
    let a = parse(args)?;
    if a.help {
        println!("{}", help((!a.cmd.is_empty()).then_some(a.cmd.as_str())));
        return Ok(0);
    }
    let (cmd, mode) = (a.cmd.as_str(), a.mode);
    if cmd == "version" {
        emit(mode, "version", &json!({ "version": VERSION }), || {
            format!("darkapple {VERSION}")
        });
        return Ok(0);
    }
    let Some(config) = a.config else {
        return Err(usage("missing --config PATH"));
    };
    let c = Config::load(&config)
        .map_err(|e| Fail::new("config", format!("config {}: {e}", config.display())))?;
    if cmd == "check" {
        let helper = c.endpoint_helper.is_some();
        let note = "Configuration only; does not verify Apple permissions or delivery";
        emit(
            mode,
            "check",
            &json!({"ok":true,"host":c.host,"endpoint_helper_configured":helper,"note":note}),
            || {
                format!(
                    "configuration ok for host {}\nendpoint helper: {}\nnote: {note}",
                    c.host,
                    if helper {
                        "configured"
                    } else {
                        "not configured"
                    }
                )
            },
        );
        return Ok(0);
    }
    if cmd == "status" {
        let path = c.state_dir.join("status.json");
        let b = darkapple::fs::read(&path, 65536, true)
            .map_err(|e| Fail::new("io", format!("cannot read {}: {e}", path.display())))?;
        let mut st: Map<String, Value> = serde_json::from_slice(&b)
            .map_err(|e| Fail::new("io", format!("status.json is not a JSON object: {e}")))?;
        let now = darkapple::now_ms();
        let updated = st.get("updated_at_ms").and_then(Value::as_i64);
        let stale = is_stale(updated, now, c.interval_seconds);
        let stale_after_ms = 3 * 1000 * c.interval_seconds;
        st.insert("stale".into(), json!(stale));
        st.insert("stale_after_ms".into(), json!(stale_after_ms));
        st.insert("age_ms".into(), json!(updated.map(|u| now - u)));
        let st = Value::Object(st);
        emit(mode, "status", &st, || {
            let age = match updated {
                Some(u) => format!("updated {} s ago", (now - u) / 1000),
                None => "no updated_at_ms".into(),
            };
            let verdict = if stale {
                format!(
                    "STALE (no update within {} s; the writer may be stopped)",
                    stale_after_ms / 1000
                )
            } else {
                "fresh".into()
            };
            format!(
                "darkapple status for host {}\n{age}: {verdict}\n{}\n{}\n{}",
                clean(st["host"].as_str().unwrap_or("?")),
                store_line(&st["store"]),
                counters_line(&st["store"]),
                coverage_lines(&st["coverage"])
            )
        });
        return Ok(0);
    }
    let mut store = Store::open(&c.state_dir, c.capacity)?;
    store.set_hidden_allowlist(c.hidden_dir_allowlist.clone());
    if cmd == "replay" {
        let Some(path) = a.input else {
            return Err(usage("replay requires --input JSONL"));
        };
        let bytes = darkapple::fs::read(&path, 8 * 1024 * 1024, false)?;
        // Validate the complete fixture before mutating durable state.
        let records: Vec<Observation> = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(serde_json::from_slice)
            .collect::<std::result::Result<_, _>>()
            .map_err(cat("usage"))?;
        if records.len() > 4096 {
            return Err(Fail::new("usage", "fixture record limit"));
        }
        for o in &records {
            o.validate().map_err(cat("usage"))?;
        }
        let n = records.len();
        for o in records {
            store.observe(&o)?;
        }
        status(&c, &store, &BTreeMap::new())?;
        let mut st = store.status()?;
        st["replayed"] = json!(n);
        emit(mode, "replay", &st, || {
            format!("replayed {n} observation(s)\n{}", store_line(&st))
        });
        return Ok(0);
    }
    if cmd == "requeue-refused" {
        // Store::open above holds the exclusive writer lock, so this refuses to
        // run while `run`, `ship` or another writer has the state directory.
        let ids = a.event_ids;
        let (n, missing) =
            store.requeue_refused((!a.all).then_some(ids.as_slice()), darkapple::now_ms())?;
        status(&c, &store, &BTreeMap::new())?;
        emit(
            mode,
            "requeue_refused",
            &json!({"requeued":n,"not_requeued":missing}),
            || {
                format!(
                    "requeued {n} refused record(s); {} not requeued",
                    missing.len()
                )
            },
        );
        if !missing.is_empty() {
            eprintln!(
                "darkapple: {} event ID(s) not requeued (unknown, or not in state refused): {}",
                missing.len(),
                missing.join(" ")
            );
            return Ok(2);
        }
        return Ok(0);
    }
    if cmd == "ship" {
        let tally = delivery::ship_due(&c, &store)?;
        status(&c, &store, &BTreeMap::new())?;
        let mut st = store.status()?;
        st["tally"] = json!({"accepted":tally.accepted,"refused":tally.refused,"retained":tally.retained,"unattempted":tally.unattempted});
        emit(mode, "ship", &st, || {
            format!(
                "ship: {} accepted, {} refused, {} retained for retry, {} unattempted\n{}",
                tally.accepted,
                tally.refused,
                tally.retained,
                tally.unattempted,
                store_line(&st)
            )
        });
        if tally.refused > 0 {
            eprintln!(
                "darkapple: ship stopped at a permanent refusal (record kept as state=refused); {} accepted, {} later due record(s) left pending and unattempted. Darksignal also refuses a wrong producer executable or uid; after fixing the cause run `darkapple requeue-refused --config PATH --all` (or --event-id ID) and ship again",
                tally.accepted, tally.unattempted
            );
        } else if tally.retained > 0 {
            eprintln!(
                "darkapple: ship stopped at a transient failure; {} accepted, {} retained for retry, {} later due record(s) left pending and unattempted; inspect status",
                tally.accepted, tally.retained, tally.unattempted
            );
        }
        return Ok(tally.exit_code());
    }
    collect(&c, &mut store, cmd == "once", mode)
}
/// `once` and `run`: the collection loop. `run` writes nothing to stdout.
fn collect(
    c: &Config,
    store: &mut Store,
    once: bool,
    mode: Mode,
) -> std::result::Result<i32, Fail> {
    // Signals interrupt the collection loop; helper is reaped by Drop.
    unsafe {
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
    }
    let mut coverage = BTreeMap::new();
    let mut native = match c
        .endpoint_helper
        .as_ref()
        .map(|p| darkapple::native::Native::start(p))
        .transpose()
    {
        Ok(n) => n,
        Err(e) => {
            coverage.insert(
                "endpoint_security".into(),
                Coverage::new("endpoint_security", "unavailable", &e.to_string()),
            );
            None
        }
    };
    if native.is_none() {
        coverage
            .entry("endpoint_security".into())
            .or_insert_with(|| {
                Coverage::new(
                    "endpoint_security",
                    "unavailable",
                    "No running Endpoint Security helper; snapshots remain enabled",
                )
            });
    }
    let (tx, rx) = mpsc::sync_channel::<Vec<(i64, Value, u32)>>(1);
    let (done_tx, done_rx) = mpsc::channel::<Vec<(i64, u32, transport::Ack, Value)>>();
    let cfg = c.clone();
    let worker = std::thread::spawn(move || {
        while let Ok(batch) = rx.recv() {
            let mut results = Vec::new();
            for (id, body, a) in batch {
                let ack = transport::send(&cfg, &body);
                // A refusal is per record and does not stop the batch, except for
                // the health frame sent first: its body is always valid, so its
                // refusal means the envelope or producer identity is refused
                // (wrong host, uid or executable). The events then stay pending,
                // unattempted, instead of being refused one by one.
                let stop = matches!(ack, transport::Ack::Retry(_))
                    || (id < 0 && ack == transport::Ack::Refused);
                results.push((id, a, ack, body));
                if stop {
                    break;
                }
            }
            if done_tx.send(results).is_err() {
                break;
            }
        }
    });
    let mut worker_lost = false;
    let mut inflight = false;
    let mut next = Instant::now();
    let mut next_ship = Instant::now();
    loop {
        match done_rx.try_recv() {
            Ok(results) => {
                settle_all(store, results)?;
                inflight = false;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                worker_lost = true;
                break;
            }
        }
        if let Some(n) = &mut native {
            let (events, health) = n.drain();
            for o in events {
                store.observe(&o)?;
            }
            coverage.insert(health.source.clone(), health);
        }
        if Instant::now() >= next {
            for (events, health) in [
                sources::processes(),
                sources::launchd(&c.launch_dirs),
                sources::posture(),
            ] {
                for o in events {
                    store.observe(&o)?;
                }
                coverage.insert(health.source.clone(), health);
            }
            // Refresh helper startup/exit state after collection before publishing status.
            if once {
                std::thread::sleep(Duration::from_millis(100));
            }
            if let Some(n) = &mut native {
                let (events, health) = n.drain();
                for o in events {
                    store.observe(&o)?;
                }
                coverage.insert(health.source.clone(), health);
            }
            for health in coverage.values() {
                let o =
                    sources::observation(&health.source, "sensor.coverage", health.status.clone());
                store.observe(&o)?;
            }
            let loss = store.loss()?;
            if loss > 0 {
                store.observe(&sources::observation(
                    "outbox",
                    "sensor.loss",
                    loss.to_string(),
                ))?;
            }
            store.prune(darkapple::now_ms(), c.retention_days)?;
            status(c, store, &coverage)?;
            next = Instant::now() + Duration::from_secs(c.interval_seconds);
            if once {
                let out = json!({"store":store.status()?,"coverage":coverage});
                emit(mode, "once", &out, || {
                    format!(
                        "{}\n{}",
                        store_line(&out["store"]),
                        coverage_lines(&out["coverage"])
                    )
                });
                break;
            }
        }
        if !inflight && Instant::now() >= next_ship {
            let mut batch = vec![(
                -1,
                json!({"schema":"darkapple.health.v1","observed_at_ms":darkapple::now_ms(),"status":if coverage.values().all(|h|h.status=="available"){"available"}else{"degraded"}}),
                0,
            )];
            batch.extend(store.pending(darkapple::now_ms())?);
            if tx.send(batch).is_err() {
                worker_lost = true;
                break;
            }
            inflight = true;
            next_ship = Instant::now() + Duration::from_secs(10);
        }
        if STOP.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(tx);
    let joined = delivery::join_worker(worker);
    // Consume final ACKs before exiting; a crash before this commit safely replays.
    while let Ok(results) = done_rx.try_recv() {
        settle_all(store, results)?;
    }
    let failure = match joined {
        Err(e) => Some(e.to_string()),
        Ok(()) if worker_lost => Some("delivery worker stopped unexpectedly".to_string()),
        Ok(()) => None,
    };
    if let Some(why) = &failure {
        store.bump("worker_failures")?;
        coverage.insert(
            "delivery".into(),
            Coverage::new("delivery", "unavailable", why),
        );
    }
    status(c, store, &coverage)?;
    match failure {
        Some(why) => Err(Fail::new("internal", why)),
        None => Ok(0),
    }
}
fn settle_all(store: &Store, results: Vec<(i64, u32, transport::Ack, Value)>) -> Result<()> {
    for (id, a, ack, body) in results {
        if id < 0 {
            delivery::settle_health(store, &ack)?;
        } else {
            delivery::settle(store, id, a, &ack, &body)?;
        }
    }
    Ok(())
}
fn status(c: &Config, s: &Store, coverage: &BTreeMap<String, Coverage>) -> Result<()> {
    use std::io::Write;
    let tmp = c.state_dir.join("status.tmp");
    let mut f = darkapple::fs::private_file(&tmp)?;
    f.set_len(0)?;
    // Contract envelope (kind darkapple.status) plus the existing fields.
    let body = envelope(
        "status",
        &json!({"schema":"darkapple.status.v1","host":c.host,"updated_at_ms":darkapple::now_ms(),"store":s.status()?,"coverage":coverage,"delivery":"Acknowledged means handled locally, not delivered upstream"}),
    );
    f.write_all(body.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    std::fs::rename(tmp, c.state_dir.join("status.json"))?;
    std::fs::File::open(Path::new(&c.state_dir))?.sync_all()?;
    Ok(())
}
