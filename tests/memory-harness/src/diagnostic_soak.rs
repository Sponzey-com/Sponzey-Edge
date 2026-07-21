use serde::{Deserialize, Serialize};

use crate::report_io::sha256_hex;
use crate::HarnessError;

pub const SOAK_DURATION_SECONDS: u64 = 7_200;
pub const SOAK_INTERVAL_SECONDS: u64 = 60;
pub const SOAK_OBSERVATION_COUNT: u32 = 121;
pub const SOAK_RSS_CEILING_BYTES: u64 = 384 * 1024 * 1024;
pub const SOAK_PLATEAU_FLOOR_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoakWorkload {
    Baseline,
    Churn,
    Websocket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSoakState {
    Created,
    Baseline,
    Running { completed_windows: u32 },
    Cooling,
    Published,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSoakEvent {
    CaptureBaseline,
    CaptureWindow { index: u32 },
    CompleteWindows,
    Publish,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticSoakLifecycle {
    state: DiagnosticSoakState,
}

impl DiagnosticSoakLifecycle {
    pub fn new() -> Self {
        Self {
            state: DiagnosticSoakState::Created,
        }
    }

    pub fn state(&self) -> DiagnosticSoakState {
        self.state
    }

    pub fn transition(&mut self, event: DiagnosticSoakEvent) -> Result<(), HarnessError> {
        let next = match (self.state, event) {
            (DiagnosticSoakState::Created, DiagnosticSoakEvent::CaptureBaseline) => {
                DiagnosticSoakState::Baseline
            }
            (DiagnosticSoakState::Baseline, DiagnosticSoakEvent::CaptureWindow { index: 1 }) => {
                DiagnosticSoakState::Running {
                    completed_windows: 1,
                }
            }
            (
                DiagnosticSoakState::Running { completed_windows },
                DiagnosticSoakEvent::CaptureWindow { index },
            ) if completed_windows < 120 && index == completed_windows + 1 => {
                DiagnosticSoakState::Running {
                    completed_windows: index,
                }
            }
            (
                DiagnosticSoakState::Running {
                    completed_windows: 120,
                },
                DiagnosticSoakEvent::CompleteWindows,
            ) => DiagnosticSoakState::Cooling,
            (DiagnosticSoakState::Cooling, DiagnosticSoakEvent::Publish) => {
                DiagnosticSoakState::Published
            }
            (DiagnosticSoakState::Published | DiagnosticSoakState::Failed, _) => {
                return Err(HarnessError::new(
                    "diagnostic soak terminal state rejects transitions",
                ));
            }
            (_, DiagnosticSoakEvent::Fail) => DiagnosticSoakState::Failed,
            _ => {
                self.state = DiagnosticSoakState::Failed;
                return Err(HarnessError::new(
                    "diagnostic soak transition is out of order",
                ));
            }
        };
        self.state = next;
        Ok(())
    }
}

impl Default for DiagnosticSoakLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticSoakObservation {
    pub index: u32,
    pub elapsed_seconds: u64,
    pub workload: SoakWorkload,
    pub build_identity: String,
    pub config_sha256: String,
    pub process_start_identity: String,
    pub expected: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub process_alive: bool,
    pub rss_bytes: u64,
    pub cleanup_connections: u64,
    pub cleanup_payload_bytes: u64,
    pub cleanup_pressure: String,
    pub recovery_status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticSoakInput {
    pub observations: Vec<DiagnosticSoakObservation>,
}

impl DiagnosticSoakInput {
    pub fn from_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("diagnostic soak input is invalid"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticSoakWindow {
    pub index: u32,
    pub elapsed_seconds: u64,
    pub workload: SoakWorkload,
    pub rss_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticSoakReport {
    pub schema_version: u32,
    pub profile_id: String,
    pub scenario_version: String,
    pub build_identity: String,
    pub config_sha256: String,
    pub process_identity_sha256: String,
    pub duration_seconds: u64,
    pub interval_seconds: u64,
    pub observation_count: u32,
    pub churn_windows: u32,
    pub websocket_windows: u32,
    pub churn_requests: u64,
    pub websocket_lifecycles: u64,
    pub peak_rss_bytes: u64,
    pub first_window_median_rss_bytes: u64,
    pub last_window_median_rss_bytes: u64,
    pub plateau_tolerance_bytes: u64,
    pub plateau_passed: bool,
    pub correctness_failures: u32,
    pub cleanup_failures: u32,
    pub rss_ceiling_bytes: u64,
    pub windows: Vec<DiagnosticSoakWindow>,
}

impl DiagnosticSoakReport {
    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.schema_version != 1
            || self.profile_id != "phase011-diagnostic-soak-2h-v1"
            || self.scenario_version != "phase011-v1"
            || !valid_build_identity(&self.build_identity)
            || !valid_digest(&self.config_sha256)
            || !valid_digest(&self.process_identity_sha256)
            || self.duration_seconds != SOAK_DURATION_SECONDS
            || self.interval_seconds != SOAK_INTERVAL_SECONDS
            || self.observation_count != SOAK_OBSERVATION_COUNT
            || self.windows.len() != SOAK_OBSERVATION_COUNT as usize
            || self.churn_windows != 60
            || self.websocket_windows != 60
            || self.churn_requests != 60_000
            || self.websocket_lifecycles != 7_680
            || self.peak_rss_bytes == 0
            || self.peak_rss_bytes > SOAK_RSS_CEILING_BYTES
            || !self.plateau_passed
            || self.correctness_failures != 0
            || self.cleanup_failures != 0
            || self.rss_ceiling_bytes != SOAK_RSS_CEILING_BYTES
        {
            return Err(HarnessError::new(
                "diagnostic soak report header is invalid",
            ));
        }
        validate_windows(&self.windows)?;
        let first = median_five(&self.windows[..5])?;
        let last = median_five(&self.windows[self.windows.len() - 5..])?;
        let tolerance = plateau_tolerance(first)?;
        if self.first_window_median_rss_bytes != first
            || self.last_window_median_rss_bytes != last
            || self.plateau_tolerance_bytes != tolerance
            || last
                > first
                    .checked_add(tolerance)
                    .ok_or_else(|| HarnessError::new("diagnostic soak plateau overflows"))?
        {
            return Err(HarnessError::new("diagnostic soak plateau is invalid"));
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, HarnessError> {
        self.validate()?;
        let mut encoded = serde_json::to_string_pretty(self)
            .map_err(|_| HarnessError::new("diagnostic soak encoding failed"))?;
        encoded.push('\n');
        Ok(encoded)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        let report: Self = serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("diagnostic soak decoding failed"))?;
        report.validate()?;
        if report.to_canonical_json()?.as_bytes() != bytes {
            return Err(HarnessError::new("diagnostic soak report is not canonical"));
        }
        Ok(report)
    }
}

pub fn evaluate_diagnostic_soak(
    observations: Vec<DiagnosticSoakObservation>,
) -> Result<DiagnosticSoakReport, HarnessError> {
    if observations.len() != SOAK_OBSERVATION_COUNT as usize {
        return Err(HarnessError::new(
            "diagnostic soak requires exactly 121 observations",
        ));
    }
    let first = &observations[0];
    let mut windows = Vec::with_capacity(observations.len());
    let mut churn_windows = 0u32;
    let mut websocket_windows = 0u32;
    for (position, observation) in observations.iter().enumerate() {
        let expected_workload = expected_workload(position as u32);
        let expected_count = match expected_workload {
            SoakWorkload::Baseline => 0,
            SoakWorkload::Churn => 1_000,
            SoakWorkload::Websocket => 128,
        };
        if observation.index != position as u32
            || observation.elapsed_seconds != position as u64 * SOAK_INTERVAL_SECONDS
            || observation.workload != expected_workload
            || observation.build_identity != first.build_identity
            || observation.config_sha256 != first.config_sha256
            || observation.process_start_identity != first.process_start_identity
            || observation.expected != expected_count
            || observation.succeeded != expected_count
            || observation.failed != 0
            || !observation.process_alive
            || observation.rss_bytes == 0
            || observation.rss_bytes > SOAK_RSS_CEILING_BYTES
            || observation.cleanup_connections != 0
            || observation.cleanup_payload_bytes != 0
            || observation.cleanup_pressure != "normal"
            || observation.recovery_status != 200
        {
            return Err(HarnessError::new("diagnostic soak observation is invalid"));
        }
        match expected_workload {
            SoakWorkload::Baseline => {}
            SoakWorkload::Churn => churn_windows += 1,
            SoakWorkload::Websocket => websocket_windows += 1,
        }
        windows.push(DiagnosticSoakWindow {
            index: observation.index,
            elapsed_seconds: observation.elapsed_seconds,
            workload: observation.workload,
            rss_bytes: observation.rss_bytes,
        });
    }
    validate_windows(&windows)?;
    let first_median = median_five(&windows[..5])?;
    let last_median = median_five(&windows[windows.len() - 5..])?;
    let tolerance = plateau_tolerance(first_median)?;
    if last_median
        > first_median
            .checked_add(tolerance)
            .ok_or_else(|| HarnessError::new("diagnostic soak plateau overflows"))?
    {
        return Err(HarnessError::new(
            "diagnostic soak plateau threshold exceeded",
        ));
    }
    let report = DiagnosticSoakReport {
        schema_version: 1,
        profile_id: "phase011-diagnostic-soak-2h-v1".to_string(),
        scenario_version: "phase011-v1".to_string(),
        build_identity: first.build_identity.clone(),
        config_sha256: first.config_sha256.clone(),
        process_identity_sha256: sha256_hex(first.process_start_identity.as_bytes()),
        duration_seconds: SOAK_DURATION_SECONDS,
        interval_seconds: SOAK_INTERVAL_SECONDS,
        observation_count: SOAK_OBSERVATION_COUNT,
        churn_windows,
        websocket_windows,
        churn_requests: u64::from(churn_windows) * 1_000,
        websocket_lifecycles: u64::from(websocket_windows) * 128,
        peak_rss_bytes: windows
            .iter()
            .map(|window| window.rss_bytes)
            .max()
            .ok_or_else(|| HarnessError::new("diagnostic soak peak is missing"))?,
        first_window_median_rss_bytes: first_median,
        last_window_median_rss_bytes: last_median,
        plateau_tolerance_bytes: tolerance,
        plateau_passed: true,
        correctness_failures: 0,
        cleanup_failures: 0,
        rss_ceiling_bytes: SOAK_RSS_CEILING_BYTES,
        windows,
    };
    report.validate()?;
    Ok(report)
}

fn expected_workload(index: u32) -> SoakWorkload {
    if index == 0 {
        SoakWorkload::Baseline
    } else if index % 2 == 1 {
        SoakWorkload::Churn
    } else {
        SoakWorkload::Websocket
    }
}

fn validate_windows(windows: &[DiagnosticSoakWindow]) -> Result<(), HarnessError> {
    for (position, window) in windows.iter().enumerate() {
        if window.index != position as u32
            || window.elapsed_seconds != position as u64 * SOAK_INTERVAL_SECONDS
            || window.workload != expected_workload(position as u32)
            || window.rss_bytes == 0
            || window.rss_bytes > SOAK_RSS_CEILING_BYTES
        {
            return Err(HarnessError::new("diagnostic soak window is invalid"));
        }
    }
    Ok(())
}

fn median_five(windows: &[DiagnosticSoakWindow]) -> Result<u64, HarnessError> {
    if windows.len() != 5 {
        return Err(HarnessError::new(
            "diagnostic soak median window is invalid",
        ));
    }
    let mut values = windows
        .iter()
        .map(|window| window.rss_bytes)
        .collect::<Vec<_>>();
    values.sort_unstable();
    Ok(values[2])
}

fn plateau_tolerance(first: u64) -> Result<u64, HarnessError> {
    if first == 0 {
        return Err(HarnessError::new(
            "diagnostic soak plateau baseline is invalid",
        ));
    }
    Ok(SOAK_PLATEAU_FLOOR_BYTES.max(first / 10))
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
