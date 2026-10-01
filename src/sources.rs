use crate::{
    Result, fs,
    model::{Coverage, Observation},
};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
pub fn observation(source: &str, kind: &str, value: String) -> Observation {
    Observation {
        source: source.into(),
        kind: kind.into(),
        observed_at_ms: crate::now_ms(),
        pid: None,
        start_us: None,
        exe: None,
        path: None,
        value,
    }
}
/// Bounded output and execution time; stdout/stderr drain concurrently to avoid
/// pipe deadlock. Fixed executables and arguments only, no shell.
pub fn command(path: &str, args: &[&str]) -> Result<String> {
    let mut child = Command::new(path)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("stdout unavailable")?;
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        stdout.take(65537).read_to_end(&mut b).map(|_| b)
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if start.elapsed() > Duration::from_secs(3) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err("command timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let bytes = reader.join().map_err(|_| "reader failed")??;
    if (!status.success() && !(path == "/usr/sbin/spctl" && status.code() == Some(3)))
        || bytes.len() > 65536
    {
        return Err("command failed or output exceeded limit".into());
    }
    Ok(String::from_utf8(bytes)?)
}
pub fn launchd(dirs: &[PathBuf]) -> (Vec<Observation>, Coverage) {
    let mut out = Vec::new();
    let mut partial = false;
    for dir in dirs {
        if !std::fs::symlink_metadata(dir).is_ok_and(|md| md.is_dir()) {
            partial = true;
            continue;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => {
                partial = true;
                continue;
            }
        };
        let mut complete = true;
        for (index, entry) in entries.take(4097).enumerate() {
            if index >= 4096 || out.len() >= 4096 {
                complete = false;
                break;
            }
            let Ok(entry) = entry else {
                complete = false;
                continue;
            };
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "plist") {
                continue;
            }
            let bytes = match fs::read(&path, 1024 * 1024, false) {
                Ok(b) => b,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            let mut o = observation(
                "launchd",
                "launchd.file",
                hex::encode(Sha256::digest(bytes)),
            );
            o.path = Some(path.to_string_lossy().into());
            if o.validate().is_ok() {
                out.push(o);
            } else {
                complete = false;
            }
        }
        if complete && out.len() < 4096 {
            let mut marker = observation("launchd", "launchd.baseline", "ready".into());
            marker.path = Some(dir.to_string_lossy().into());
            if marker.validate().is_ok() {
                out.push(marker);
            } else {
                complete = false;
            }
        } else {
            complete = false;
        }
        partial |= !complete;
    }
    (
        out,
        Coverage::new(
            "launchd",
            if partial { "partial" } else { "available" },
            "Configured directories only; polling content hashes, no deletion inference",
        ),
    )
}
pub fn posture() -> (Vec<Observation>, Coverage) {
    let mut out = Vec::new();
    let mut partial = false;
    for (path, args, kind, on, off) in [
        (
            "/usr/bin/csrutil",
            vec!["status"],
            "posture.sip",
            "System Integrity Protection status: enabled.",
            "System Integrity Protection status: disabled.",
        ),
        (
            "/usr/sbin/spctl",
            vec!["--status"],
            "posture.gatekeeper",
            "assessments enabled",
            "assessments disabled",
        ),
    ] {
        match command(path, &args) {
            Ok(s) if s.trim() == on => out.push(observation("posture", kind, "enabled".into())),
            Ok(s) if s.trim() == off => out.push(observation("posture", kind, "disabled".into())),
            _ => partial = true,
        }
    }
    (
        out,
        Coverage::new(
            "posture",
            if partial { "partial" } else { "available" },
            "SIP and Gatekeeper only; unknown/custom output is not interpreted as enabled",
        ),
    )
}
#[cfg(target_os = "macos")]
pub fn processes() -> (Vec<Observation>, Coverage) {
    // SAFETY: fixed writable buffers, validated sizes and initialized structures.
    unsafe {
        let mut pids = vec![0_i32; 8192];
        let size = std::mem::size_of_val(pids.as_slice()) as i32;
        let n = libc::proc_listpids(
            1, /* PROC_ALL_PIDS, libproc.h */
            0,
            pids.as_mut_ptr().cast(),
            size,
        );
        if n <= 0 {
            return (
                vec![],
                Coverage::new("process", "unavailable", "proc_listpids failed"),
            );
        }
        let mut partial = n >= size;
        let mut out = Vec::new();
        for pid in pids
            .into_iter()
            .take((n as usize / 4).min(8192))
            .filter(|p| *p > 0)
        {
            let mut a: libc::proc_bsdinfo = std::mem::zeroed();
            let len = std::mem::size_of_val(&a) as i32;
            if libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut a as *mut libc::proc_bsdinfo).cast(),
                len,
            ) != len
            {
                partial = true;
                continue;
            }
            let mut path = [0u8; 4096];
            let got = libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32);
            if got <= 0 {
                partial = true;
                continue;
            }
            let mut b: libc::proc_bsdinfo = std::mem::zeroed();
            if libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut b as *mut libc::proc_bsdinfo).cast(),
                len,
            ) != len
                || (a.pbi_start_tvsec, a.pbi_start_tvusec)
                    != (b.pbi_start_tvsec, b.pbi_start_tvusec)
            {
                partial = true;
                continue;
            }
            let end = path.iter().position(|x| *x == 0).unwrap_or(path.len());
            let Ok(exe) = std::str::from_utf8(&path[..end]) else {
                partial = true;
                continue;
            };
            let mut o = observation("process", "process.observed", "present".into());
            o.pid = Some(pid as u32);
            o.start_us = Some(
                a.pbi_start_tvsec
                    .saturating_mul(1_000_000)
                    .saturating_add(a.pbi_start_tvusec),
            );
            o.exe = Some(exe.into());
            if o.validate().is_ok() {
                out.push(o);
            } else {
                partial = true;
            }
        }
        (
            out,
            Coverage::new(
                "process",
                if partial { "partial" } else { "available" },
                "Snapshots can miss short-lived processes; inaccessible/exited processes are partial coverage",
            ),
        )
    }
}
#[cfg(not(target_os = "macos"))]
pub fn processes() -> (Vec<Observation>, Coverage) {
    (
        vec![],
        Coverage::new("process", "unavailable", "macOS required"),
    )
}
