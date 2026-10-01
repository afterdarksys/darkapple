use crate::{Result, fs};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub host: String,
    pub state_dir: PathBuf,
    pub darksignal_socket: PathBuf,
    #[serde(default = "interval")]
    pub interval_seconds: u64,
    #[serde(default = "capacity")]
    pub capacity: usize,
    #[serde(default = "retention")]
    pub retention_days: u32,
    #[serde(default)]
    pub endpoint_helper: Option<PathBuf>,
    #[serde(default = "launch_dirs")]
    pub launch_dirs: Vec<PathBuf>,
}
fn interval() -> u64 {
    30
}
fn capacity() -> usize {
    10_000
}
fn retention() -> u32 {
    7
}
fn launch_dirs() -> Vec<PathBuf> {
    ["/Library/LaunchAgents", "/Library/LaunchDaemons"]
        .map(PathBuf::from)
        .into()
}
pub fn valid_host(h: &str) -> bool {
    (1..=253).contains(&h.len())
        && h.split('.').all(|p| {
            (1..=63).contains(&p.len())
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        })
}
impl Config {
    pub fn load(p: &Path) -> Result<Self> {
        fs::trusted_ancestors(p)?;
        let c: Self = serde_json::from_slice(&fs::read(p, 65536, true)?)?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        if !valid_host(&self.host)
            || !(1..=30).contains(&self.interval_seconds)
            || !(100..=100_000).contains(&self.capacity)
            || !(1..=90).contains(&self.retention_days)
            || self.launch_dirs.len() > 64
        {
            return Err("invalid host or resource limits".into());
        }
        for p in [&self.state_dir, &self.darksignal_socket]
            .into_iter()
            .chain(self.endpoint_helper.iter())
            .chain(self.launch_dirs.iter())
        {
            if !fs::clean(p) {
                return Err("paths must be absolute without ..".into());
            }
        }
        if let Some(p) = &self.endpoint_helper {
            fs::executable(p)?;
        }
        Ok(())
    }
}
