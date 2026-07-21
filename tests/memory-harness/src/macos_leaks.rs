use serde::{Deserialize, Serialize};

use crate::HarnessError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaksSummary {
    pub leak_count: u64,
    pub leaked_bytes: u64,
}

pub fn parse_leaks_summary(raw: &str) -> Result<LeaksSummary, HarnessError> {
    if raw.is_empty()
        || raw.contains("[fatal]")
        || raw.contains("task port")
        || raw.contains("appropriate privileges")
    {
        return Err(HarnessError::new(
            "macOS leaks output reports a tool failure",
        ));
    }
    let mut parsed = None;
    for line in raw.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 9
            || fields[0] != "Process"
            || !fields[1].ends_with(':')
            || !matches!(fields[3], "leak" | "leaks")
            || fields[4] != "for"
            || fields[6] != "total"
            || fields[7] != "leaked"
            || fields[8] != "bytes."
        {
            continue;
        }
        let pid = fields[1]
            .trim_end_matches(':')
            .parse::<u64>()
            .map_err(|_| HarnessError::new("macOS leaks process summary is invalid"))?;
        if pid == 0 || parsed.is_some() {
            return Err(HarnessError::new(
                "macOS leaks output must contain one process summary",
            ));
        }
        let leak_count = fields[2]
            .parse::<u64>()
            .map_err(|_| HarnessError::new("macOS leaks count is invalid"))?;
        let leaked_bytes = fields[5]
            .parse::<u64>()
            .map_err(|_| HarnessError::new("macOS leaked bytes are invalid"))?;
        if (leak_count == 0) != (leaked_bytes == 0) || (leak_count == 1) != (fields[3] == "leak") {
            return Err(HarnessError::new(
                "macOS leaks count and bytes are inconsistent",
            ));
        }
        parsed = Some(LeaksSummary {
            leak_count,
            leaked_bytes,
        });
    }
    parsed.ok_or_else(|| HarnessError::new("macOS leaks process summary is missing"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLeaksState {
    Created,
    InputsVerified,
    Parsed,
    Validated,
    Published,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLeaksEvent {
    InputsVerified,
    Parsed,
    Validated,
    Published,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacosLeaksLifecycle {
    state: MacosLeaksState,
}

impl MacosLeaksLifecycle {
    pub fn new() -> Self {
        Self {
            state: MacosLeaksState::Created,
        }
    }

    pub fn state(&self) -> MacosLeaksState {
        self.state
    }

    pub fn transition(&mut self, event: MacosLeaksEvent) -> Result<(), HarnessError> {
        let next = match (self.state, event) {
            (MacosLeaksState::Created, MacosLeaksEvent::InputsVerified) => {
                MacosLeaksState::InputsVerified
            }
            (MacosLeaksState::InputsVerified, MacosLeaksEvent::Parsed) => MacosLeaksState::Parsed,
            (MacosLeaksState::Parsed, MacosLeaksEvent::Validated) => MacosLeaksState::Validated,
            (MacosLeaksState::Validated, MacosLeaksEvent::Published) => MacosLeaksState::Published,
            (MacosLeaksState::Published | MacosLeaksState::Failed, _) => {
                return Err(HarnessError::new(
                    "macOS leaks terminal state rejects transitions",
                ));
            }
            (_, MacosLeaksEvent::Fail) => MacosLeaksState::Failed,
            _ => {
                self.state = MacosLeaksState::Failed;
                return Err(HarnessError::new("macOS leaks transition is out of order"));
            }
        };
        self.state = next;
        Ok(())
    }
}

impl Default for MacosLeaksLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosLeaksInput {
    pub build_identity: String,
    pub architecture: String,
    pub original_binary_sha256: String,
    pub signed_binary_sha256: String,
    pub config_sha256: String,
    pub process_identity_sha256: String,
    pub raw_sha256: String,
    pub tool_exit_code: i32,
    pub workload_expected: u64,
    pub workload_succeeded: u64,
    pub workload_failed: u64,
    pub cleanup_connections: u64,
    pub cleanup_payload_bytes: u64,
    pub cleanup_pressure: String,
    pub recovery_status: u16,
    pub summary: LeaksSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosLeaksReport {
    pub schema_version: u32,
    pub profile_id: String,
    pub build_identity: String,
    pub platform: String,
    pub architecture: String,
    pub original_binary_sha256: String,
    pub signed_binary_sha256: String,
    pub config_sha256: String,
    pub process_identity_sha256: String,
    pub raw_sha256: String,
    pub tool_exit_code: i32,
    pub workload_expected: u64,
    pub workload_succeeded: u64,
    pub workload_failed: u64,
    pub cleanup_connections: u64,
    pub cleanup_payload_bytes: u64,
    pub cleanup_pressure: String,
    pub recovery_status: u16,
    pub leak_count: u64,
    pub leaked_bytes: u64,
}

impl MacosLeaksReport {
    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.schema_version != 1
            || self.profile_id != "phase011-macos-leaks-v1"
            || !valid_build_identity(&self.build_identity)
            || self.platform != "macos"
            || self.architecture.is_empty()
            || !valid_digest(&self.original_binary_sha256)
            || !valid_digest(&self.signed_binary_sha256)
            || !valid_digest(&self.config_sha256)
            || !valid_digest(&self.process_identity_sha256)
            || !valid_digest(&self.raw_sha256)
            || self.tool_exit_code != 0
            || self.workload_expected == 0
            || self.workload_succeeded != self.workload_expected
            || self.workload_failed != 0
            || self.cleanup_connections != 0
            || self.cleanup_payload_bytes != 0
            || self.cleanup_pressure != "normal"
            || self.recovery_status != 200
            || self.leak_count != 0
            || self.leaked_bytes != 0
        {
            return Err(HarnessError::new("macOS leaks report is invalid"));
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, HarnessError> {
        self.validate()?;
        let mut encoded = serde_json::to_string_pretty(self)
            .map_err(|_| HarnessError::new("macOS leaks report encoding failed"))?;
        encoded.push('\n');
        Ok(encoded)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        let report: Self = serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("macOS leaks report decoding failed"))?;
        report.validate()?;
        if report.to_canonical_json()?.as_bytes() != bytes {
            return Err(HarnessError::new("macOS leaks report is not canonical"));
        }
        Ok(report)
    }
}

pub fn evaluate_macos_leaks(input: MacosLeaksInput) -> Result<MacosLeaksReport, HarnessError> {
    if input.summary.leak_count != 0 || input.summary.leaked_bytes != 0 {
        return Err(HarnessError::new(
            "macOS leaks diagnostic reports a definite leak",
        ));
    }
    let report = MacosLeaksReport {
        schema_version: 1,
        profile_id: "phase011-macos-leaks-v1".to_string(),
        build_identity: input.build_identity,
        platform: "macos".to_string(),
        architecture: input.architecture,
        original_binary_sha256: input.original_binary_sha256,
        signed_binary_sha256: input.signed_binary_sha256,
        config_sha256: input.config_sha256,
        process_identity_sha256: input.process_identity_sha256,
        raw_sha256: input.raw_sha256,
        tool_exit_code: input.tool_exit_code,
        workload_expected: input.workload_expected,
        workload_succeeded: input.workload_succeeded,
        workload_failed: input.workload_failed,
        cleanup_connections: input.cleanup_connections,
        cleanup_payload_bytes: input.cleanup_payload_bytes,
        cleanup_pressure: input.cleanup_pressure,
        recovery_status: input.recovery_status,
        leak_count: input.summary.leak_count,
        leaked_bytes: input.summary.leaked_bytes,
    };
    report.validate()?;
    Ok(report)
}

fn valid_build_identity(value: &str) -> bool {
    value
        .strip_prefix("source-tree-sha256:")
        .is_some_and(valid_digest)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
