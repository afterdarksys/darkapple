use crate::{Result, config::Config, fs};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::Path,
    time::Duration,
};
pub const MAX_FRAME: usize = 65_536;
pub fn frame(host: &str, body: &Value) -> Result<Vec<u8>> {
    let b = serde_json::to_vec(
        &json!({"v":1,"tool":"darkapple","host":host,"sent_at_ms":crate::now_ms(),"body":body}),
    )?;
    if b.len() > MAX_FRAME {
        return Err("frame too large".into());
    }
    let mut out = (b.len() as u32).to_le_bytes().to_vec();
    out.extend(b);
    Ok(out)
}
fn check_socket(p: &Path) -> Result<()> {
    fs::trusted_ancestors(p)?;
    let parent = p.parent().ok_or("socket parent")?;
    let d = std::fs::symlink_metadata(parent)?;
    let m = std::fs::symlink_metadata(p)?;
    if !d.is_dir()
        || d.mode() & 0o022 != 0
        || !m.file_type().is_socket()
        || (m.uid() != 0 && m.uid() != fs::uid())
        || m.mode() & 0o002 != 0
    {
        return Err("untrusted darksignal socket".into());
    }
    Ok(())
}
/// True = ACK 1 (handled, not proof of remote delivery); false = retained refusal.
pub fn send(c: &Config, body: &Value) -> Result<bool> {
    check_socket(&c.darksignal_socket)?;
    let bytes = frame(&c.host, body)?;
    let mut s = UnixStream::connect(&c.darksignal_socket)?;
    s.set_write_timeout(Some(Duration::from_secs(2)))?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    s.write_all(&bytes)?;
    s.shutdown(std::net::Shutdown::Write)?;
    let mut ack = [0];
    s.read_exact(&mut ack)?;
    match ack[0] {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err("invalid acknowledgement".into()),
    }
}
