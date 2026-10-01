//! Own child pipe, bounded messages and queue. Never accept a public event socket.
use crate::{
    Result,
    model::{Coverage, Observation},
};
use serde::Deserialize;
use std::{
    io::{BufRead, BufReader, Read},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver},
    },
    time::{Duration, Instant},
};
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Message {
    Event { observation: Observation },
    Health { status: String, detail: String },
}
pub struct Native {
    child: Child,
    rx: Receiver<Message>,
    lost: Arc<AtomicU64>,
    last: Instant,
    coverage: Coverage,
}
impl Native {
    pub fn start(path: &Path) -> Result<Self> {
        crate::fs::executable(path)?;
        let mut child = Command::new(path)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = child.stdout.take().ok_or("helper stdout")?;
        let (tx, rx) = mpsc::sync_channel(1024);
        let lost = Arc::new(AtomicU64::new(0));
        let loss = lost.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                match reader.by_ref().take(65537).read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    _ => {}
                }
                if line.len() > 65536 || !line.ends_with(b"\n") {
                    loss.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                match serde_json::from_slice::<Message>(&line) {
                    Ok(m) => {
                        if tx.try_send(m).is_err() {
                            loss.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        loss.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        Ok(Self {
            child,
            rx,
            lost,
            last: Instant::now(),
            coverage: Coverage::new("endpoint_security", "unavailable", "Starting helper"),
        })
    }
    pub fn drain(&mut self) -> (Vec<Observation>, Coverage) {
        let mut out = Vec::new();
        for m in self.rx.try_iter().take(1024) {
            self.last = Instant::now();
            match m {
                Message::Event { observation } if observation.validate().is_ok() => {
                    out.push(observation)
                }
                Message::Event { .. } => {
                    self.lost.fetch_add(1, Ordering::Relaxed);
                }
                Message::Health { status, detail } => {
                    self.coverage = Coverage::new(
                        "endpoint_security",
                        if status == "available" {
                            "available"
                        } else {
                            "unavailable"
                        },
                        &detail.chars().take(256).collect::<String>(),
                    )
                }
            }
        }
        if self.child.try_wait().ok().flatten().is_some()
            || self.last.elapsed() > Duration::from_secs(45)
        {
            self.coverage = Coverage::new(
                "endpoint_security",
                "unavailable",
                "Helper exited or heartbeat expired; verify entitlement, root and Full Disk Access",
            );
        }
        let lost = self.lost.swap(0, Ordering::Relaxed);
        if lost > 0 {
            let mut o =
                crate::sources::observation("endpoint_security", "sensor.loss", lost.to_string());
            o.start_us = Some(crate::now_ms() as u64);
            out.push(o);
        }
        (out, self.coverage.clone())
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
