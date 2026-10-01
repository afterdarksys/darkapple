use darkapple::{
    Result,
    config::Config,
    model::{Coverage, Observation},
    sources,
    store::Store,
    transport,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: i32) {
    STOP.store(true, Ordering::Relaxed);
}
fn main() {
    if let Err(e) = run() {
        eprintln!("darkapple: {e}");
        std::process::exit(2);
    }
}
fn usage() -> &'static str {
    "darkapple version | check|once|run|status|ship --config PATH | replay --config PATH --input JSONL"
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["version"] {
        println!("darkapple {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args == ["--help"] {
        println!("{}", usage());
        return Ok(());
    }
    let cmd = args.first().ok_or(usage())?;
    if !["check", "once", "run", "status", "ship", "replay"].contains(&cmd.as_str()) {
        return Err(usage().into());
    }
    let mut config = None;
    let mut input = None;
    let mut i = 1;
    while i < args.len() {
        let val = args.get(i + 1).ok_or(usage())?;
        match args[i].as_str() {
            "--config" if config.is_none() => config = Some(PathBuf::from(val)),
            "--input" if input.is_none() && cmd == "replay" => input = Some(PathBuf::from(val)),
            _ => return Err(usage().into()),
        }
        i += 2;
    }
    let c = Config::load(&config.ok_or(usage())?)?;
    if cmd == "check" {
        println!(
            "{}",
            json!({"ok":true,"host":c.host,"endpoint_helper_configured":c.endpoint_helper.is_some(),"note":"Configuration only; does not verify Apple permissions or delivery"})
        );
        return Ok(());
    }
    if cmd == "status" {
        let b = darkapple::fs::read(&c.state_dir.join("status.json"), 65536, true)?;
        println!("{}", String::from_utf8(b)?);
        return Ok(());
    }
    let mut store = Store::open(&c.state_dir, c.capacity)?;
    if cmd == "replay" {
        let path = input.ok_or("replay requires --input")?;
        let bytes = darkapple::fs::read(&path, 8 * 1024 * 1024, false)?;
        // Validate the complete fixture before mutating durable state.
        let records: Vec<Observation> = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(serde_json::from_slice)
            .collect::<std::result::Result<_, _>>()?;
        if records.len() > 4096 {
            return Err("fixture record limit".into());
        }
        for o in &records {
            o.validate()?;
        }
        for o in records {
            store.observe(&o)?;
        }
        status(&c, &store, &BTreeMap::new())?;
        println!("{}", store.status()?);
        return Ok(());
    }
    if cmd == "ship" {
        let mut failed = false;
        for (id, body, a) in store.pending(darkapple::now_ms())? {
            match transport::send(&c, &body) {
                Ok(true) => store.acknowledge(id)?,
                r => {
                    store.retry(id, a, darkapple::now_ms(), matches!(r, Ok(false)))?;
                    failed = true;
                }
            }
        }
        status(&c, &store, &BTreeMap::new())?;
        println!("{}", store.status()?);
        if failed {
            return Err("records retained for retry; inspect status".into());
        }
        return Ok(());
    }
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
    let (done_tx, done_rx) = mpsc::channel();
    let cfg = c.clone();
    let worker = std::thread::spawn(move || {
        while let Ok(batch) = rx.recv() {
            let mut results = Vec::new();
            for (id, body, a) in batch {
                let outcome = transport::send(&cfg, &body).map_err(|_| ());
                let failed = outcome.is_err();
                results.push((id, a, outcome));
                if failed {
                    break;
                }
            }
            if done_tx.send(results).is_err() {
                break;
            }
        }
    });
    let mut inflight = false;
    let mut next = Instant::now();
    let mut next_ship = Instant::now();
    loop {
        if let Ok(results) = done_rx.try_recv() {
            for (id, a, r) in results {
                if id < 0 {
                    store.bump(match r {
                        Ok(true) => "health_acknowledged",
                        Ok(false) => "health_refused",
                        Err(()) => "health_transport_errors",
                    })?;
                    continue;
                }
                match r {
                    Ok(true) => store.acknowledge(id)?,
                    r => store.retry(id, a, darkapple::now_ms(), matches!(r, Ok(false)))?,
                }
            }
            inflight = false;
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
            if cmd == "once" {
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
            status(&c, &store, &coverage)?;
            next = Instant::now() + Duration::from_secs(c.interval_seconds);
            if cmd == "once" {
                println!("{}", json!({"store":store.status()?,"coverage":coverage}));
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
            tx.send(batch)?;
            inflight = true;
            next_ship = Instant::now() + Duration::from_secs(10);
        }
        if STOP.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(tx);
    let _ = worker.join();
    // Consume final ACKs before exiting; a crash before this commit safely replays.
    if let Ok(results) = done_rx.try_recv() {
        for (id, a, r) in results {
            if id >= 0 {
                match r {
                    Ok(true) => store.acknowledge(id)?,
                    r => store.retry(id, a, darkapple::now_ms(), matches!(r, Ok(false)))?,
                }
            }
        }
    }
    status(&c, &store, &coverage)?;
    Ok(())
}
fn status(c: &Config, s: &Store, coverage: &BTreeMap<String, Coverage>) -> Result<()> {
    use std::io::Write;
    let tmp = c.state_dir.join("status.tmp");
    let mut f = darkapple::fs::private_file(&tmp)?;
    f.set_len(0)?;
    serde_json::to_writer(
        &mut f,
        &json!({"schema":"darkapple.status.v1","host":c.host,"updated_at_ms":darkapple::now_ms(),"store":s.status()?,"coverage":coverage,"delivery":"Acknowledged means handled locally, not delivered upstream"}),
    )?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    std::fs::rename(tmp, c.state_dir.join("status.json"))?;
    std::fs::File::open(Path::new(&c.state_dir))?.sync_all()?;
    Ok(())
}
