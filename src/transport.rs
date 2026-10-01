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
pub const ACK_REFUSED: u8 = 0x00;
pub const ACK_ACCEPTED: u8 = 0x01;
pub const ACK_RETRY: u8 = 0x02;
/// Darksignal's one-byte answer to a frame (darksignal DESIGN.md, Socket).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ack {
    /// `0x01`: stored, a duplicate, stored after eviction, or classified as
    /// not a signal. Handled locally by Darksignal; not proof of upstream delivery.
    Accepted,
    /// `0x00`: permanent refusal, the producer's fault. Resending the same
    /// bytes can never succeed, so the record leaves the outbox.
    Refused,
    /// Transient: keep the record and resend after backoff.
    Retry(Retry),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retry {
    /// Explicit `0x02` from Darksignal (peer identity unreadable, queue full,
    /// store error, socket setup failure).
    Ack,
    /// No byte, an unknown byte, I/O error, timeout or an untrusted/missing
    /// socket. Treated exactly like `0x02`.
    Transport(String),
}
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
pub fn decode(byte: u8) -> Ack {
    match byte {
        ACK_ACCEPTED => Ack::Accepted,
        ACK_REFUSED => Ack::Refused,
        ACK_RETRY => Ack::Retry(Retry::Ack),
        other => Ack::Retry(Retry::Transport(format!("unknown ack byte {other:#04x}"))),
    }
}
fn exchange(c: &Config, bytes: &[u8]) -> Result<u8> {
    check_socket(&c.darksignal_socket)?;
    let mut s = UnixStream::connect(&c.darksignal_socket)?;
    s.set_write_timeout(Some(Duration::from_secs(2)))?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok(write_and_read_ack(&mut s, bytes)?)
}
/// Darksignal frames are length-prefixed, so it can read the frame, ack and
/// shut the connection down before our `shutdown(Write)`. BSD then answers
/// that shutdown with `ENOTCONN` while the ack byte is still readable, so that
/// error must not discard the ack: an accepted frame would be resent and a
/// permanent refusal retried.
fn write_and_read_ack(s: &mut UnixStream, bytes: &[u8]) -> std::io::Result<u8> {
    s.write_all(bytes)?;
    match s.shutdown(std::net::Shutdown::Write) {
        Err(e) if e.kind() != std::io::ErrorKind::NotConnected => return Err(e),
        _ => {}
    }
    let mut ack = [0];
    s.read_exact(&mut ack)?;
    Ok(ack[0])
}
/// Sends one body. Never returns an error: every failure maps to an [`Ack`].
/// A body whose frame exceeds 64 KiB can never be accepted, so it is
/// [`Ack::Refused`] without connecting (Darksignal would answer `0x00`).
pub fn send(c: &Config, body: &Value) -> Ack {
    let bytes = match frame(&c.host, body) {
        Ok(b) => b,
        Err(_) => return Ack::Refused,
    };
    match exchange(c, &bytes) {
        Ok(b) => decode(b),
        Err(e) => Ack::Retry(Retry::Transport(e.to_string())),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ack_survives_peer_closing_before_our_shutdown() {
        for want in [ACK_ACCEPTED, ACK_REFUSED, ACK_RETRY] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            // The whole frame is already written; the peer reads it, acks and
            // shuts down before write_and_read_ack reaches shutdown(Write).
            client.write_all(&[7u8; 16]).unwrap();
            let peer = std::thread::spawn(move || {
                let mut got = [0u8; 16];
                server.read_exact(&mut got).unwrap();
                server.write_all(&[want]).unwrap();
                server.shutdown(std::net::Shutdown::Both).unwrap();
            });
            peer.join().unwrap();
            assert_eq!(write_and_read_ack(&mut client, &[]).unwrap(), want);
        }
    }
}
