use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub source: String,
    pub kind: String,
    pub observed_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Fixed status or content digest, never file contents or command arguments.
    pub value: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coverage {
    pub source: String,
    pub status: String,
    pub detail: String,
}
impl Coverage {
    pub fn new(s: &str, status: &str, d: &str) -> Self {
        Self {
            source: s.into(),
            status: status.into(),
            detail: d.into(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema: String,
    pub event_id: String,
    pub observed_at_ms: i64,
    pub source: String,
    pub kind: String,
    pub rule_id: String,
    pub severity: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}
impl Observation {
    pub fn validate(&self) -> Result<()> {
        if !(0..=4_102_444_800_000).contains(&self.observed_at_ms)
            || self.source.len() > 64
            || self.kind.len() > 64
            || self.value.len() > 256
            || self
                .exe
                .iter()
                .chain(self.path.iter())
                .any(|s| s.len() > 4096 || s.chars().any(char::is_control))
        {
            return Err("invalid observation".into());
        }
        Ok(())
    }
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.source,
            self.kind,
            self.pid.unwrap_or(0),
            self.start_us.unwrap_or(0),
            self.path.as_deref().unwrap_or("")
        )
    }
    pub fn fingerprint(&self) -> String {
        let mut copy = self.clone();
        copy.observed_at_ms = 0;
        hex::encode(Sha256::digest(
            serde_json::to_vec(&copy).unwrap_or_default(),
        ))
    }
}
pub fn detection(o: &Observation, changed: bool) -> Option<Event> {
    let (rule, severity, summary) = match o.kind.as_str() {
        "process.observed" | "process.exec"
            if o.exe.as_deref().is_some_and(|s| {
                s.starts_with("/tmp/")
                    || s.starts_with("/private/tmp/")
                    || s.starts_with("/var/tmp/")
                    || s.starts_with("/private/var/tmp/")
            }) =>
        {
            (
                "macos.process.temporary_executable",
                "medium",
                "Process executable in temporary directory",
            )
        }
        "process.observed" | "process.exec"
            if o.exe
                .as_deref()
                .is_some_and(|s| s.split('/').any(|p| p.starts_with('.') && p.len() > 1)) =>
        {
            (
                "macos.process.hidden_executable",
                "medium",
                "Process executable in hidden directory",
            )
        }
        "launchd.file" if changed => (
            "macos.persistence.launchd_changed",
            "low",
            "Launchd configuration changed since baseline",
        ),
        "posture.sip" if o.value == "disabled" => (
            "macos.posture.sip_disabled",
            "high",
            "System Integrity Protection disabled",
        ),
        "posture.gatekeeper" if o.value == "disabled" => (
            "macos.posture.gatekeeper_disabled",
            "medium",
            "Gatekeeper assessments disabled",
        ),
        "sensor.loss" => (
            "macos.sensor.events_dropped",
            "high",
            "Sensor event collection lost records",
        ),
        "sensor.coverage" if o.value != "available" => (
            "macos.sensor.coverage_degraded",
            "medium",
            "Sensor coverage is degraded; inspect local status",
        ),
        _ => return None,
    };
    Some(Event {
        schema: "darkapple.event.v1".into(),
        event_id: uuid::Uuid::new_v4().to_string(),
        observed_at_ms: o.observed_at_ms,
        source: o.source.clone(),
        kind: o.kind.clone(),
        rule_id: rule.into(),
        severity: severity.into(),
        summary: summary.into(),
        pid: o.pid,
        exe: o.exe.clone(),
        path: o.path.clone(),
    })
}
