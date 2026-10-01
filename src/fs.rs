//! State lives in an owner-only directory. Reject symlinks and writable ancestors.
use crate::Result;
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path},
};
pub fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
pub fn clean(p: &Path) -> bool {
    p.is_absolute() && !p.components().any(|c| matches!(c, Component::ParentDir))
}
pub fn trusted_ancestors(p: &Path) -> Result<()> {
    if !clean(p) {
        return Err("absolute path without .. required".into());
    }
    for a in p.ancestors().skip(1) {
        let md = std::fs::symlink_metadata(a)?;
        // /tmp is commonly a symlink on macOS; use canonical /private/tmp in configs.
        if !md.is_dir()
            || (md.uid() != 0 && md.uid() != uid())
            || (md.mode() & 0o022 != 0 && md.mode() & 0o1000 == 0)
        {
            return Err(format!("untrusted ancestor: {}", a.display()).into());
        }
    }
    Ok(())
}
pub fn read(p: &Path, max: usize, owned: bool) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(p)?;
    let md = f.metadata()?;
    if !md.is_file() || (owned && (md.uid() != uid() || md.mode() & 0o022 != 0)) {
        return Err("unsafe file".into());
    }
    let mut b = Vec::new();
    f.take((max + 1) as u64).read_to_end(&mut b)?;
    if b.len() > max {
        return Err("file size limit".into());
    }
    Ok(b)
}
pub fn private_dir(p: &Path) -> Result<()> {
    trusted_ancestors(p)?;
    match std::fs::symlink_metadata(p) {
        Ok(md) if md.is_dir() && md.uid() == uid() && md.mode() & 0o777 == 0o700 => Ok(()),
        Ok(_) => Err("state directory must be owned by service uid, mode 0700, no symlink".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(p)?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}
pub fn private_file(p: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != uid() || m.mode() & 0o777 != 0o600 || m.nlink() != 1 {
        return Err("unsafe state file".into());
    }
    Ok(f)
}
pub fn lock(p: &Path) -> Result<File> {
    let f = private_file(p)?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another darkapple writer is running".into());
    }
    Ok(f)
}
pub fn executable(p: &Path) -> Result<()> {
    trusted_ancestors(p)?;
    let m = std::fs::symlink_metadata(p)?;
    if !m.is_file()
        || (m.uid() != 0 && m.uid() != uid())
        || m.permissions().mode() & 0o022 != 0
        || m.mode() & 0o111 == 0
    {
        return Err("untrusted helper executable".into());
    }
    Ok(())
}
