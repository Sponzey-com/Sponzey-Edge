//! Test/release-only memory evidence model.

use std::error::Error;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

mod bounded_net;

pub mod admission_probe;
pub mod canonical_slow_profile;
pub mod connection_churn;
pub mod connection_churn_cli;
pub mod connection_churn_evidence;
pub mod connection_holder;
pub mod control_max;
pub mod diagnostic_soak;
pub mod diagnostic_soak_runner;
pub mod diagnostic_soak_runner_cli;
pub mod evaluator;
pub mod evidence_cli;
pub mod full_profile_readiness;
pub mod full_profile_runner;
pub mod http_driver;
pub mod http_evidence;
pub mod http_evidence_cli;
pub mod http_steady;
pub mod https_steady;
pub mod macos_leaks;
pub mod macos_leaks_cli;
pub mod memory_aggregate;
pub mod memory_manifest;
pub mod mtls_connection_holder;
pub mod mtls_steady;
pub mod orchestrator;
pub mod payload_pressure;
pub mod phase011_memory_release;
pub mod phase011_memory_release_cli;
pub mod ports;
pub mod private_https;
pub mod release_http_cli;
pub mod release_http_scenario;
pub mod report;
pub mod report_io;
pub mod scenario;
pub mod slow_body;
pub mod slow_body_cycles;
pub mod slow_header;
pub mod slow_header_cycles;
pub mod slow_response;
pub mod slow_response_cycles;
pub mod soak_window;
pub mod soak_window_adapters;
pub mod system_adapters;
pub mod tls_connection_holder;
pub mod websocket_cycles;
pub mod websocket_driver;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessError {
    message: String,
}

impl HarnessError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for HarnessError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for HarnessError {}

pub fn parse_macos_ps_rss_bytes(output: &str) -> Result<u64, HarnessError> {
    let mut fields = output.split_whitespace();
    let kib = fields
        .next()
        .ok_or_else(|| HarnessError::new("macOS ps RSS output is empty"))?;
    if fields.next().is_some() {
        return Err(HarnessError::new(
            "macOS ps RSS output must contain exactly one value",
        ));
    }
    let kib = kib
        .parse::<u64>()
        .map_err(|_| HarnessError::new("macOS ps RSS value is invalid"))?;
    if kib == 0 {
        return Err(HarnessError::new("macOS ps RSS value must be positive"));
    }
    kib.checked_mul(1024)
        .ok_or_else(|| HarnessError::new("macOS ps RSS value overflows bytes"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineState {
    Created,
    Preflight,
    Started,
    Sampled,
    Reported,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineEvent {
    PreflightPassed,
    ChildReady,
    SampleCollected,
    ReportWritten,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineLifecycle {
    state: BaselineState,
}

impl BaselineLifecycle {
    pub fn new() -> Self {
        Self {
            state: BaselineState::Created,
        }
    }

    pub fn state(&self) -> BaselineState {
        self.state
    }

    pub fn transition(&mut self, event: BaselineEvent) -> Result<(), HarnessError> {
        let next = match (self.state, event) {
            (BaselineState::Created, BaselineEvent::PreflightPassed) => BaselineState::Preflight,
            (BaselineState::Preflight, BaselineEvent::ChildReady) => BaselineState::Started,
            (BaselineState::Started | BaselineState::Sampled, BaselineEvent::SampleCollected) => {
                BaselineState::Sampled
            }
            (BaselineState::Sampled, BaselineEvent::ReportWritten) => BaselineState::Reported,
            (
                BaselineState::Created
                | BaselineState::Preflight
                | BaselineState::Started
                | BaselineState::Sampled,
                BaselineEvent::Failed,
            ) => BaselineState::Failed,
            _ => {
                return Err(HarnessError::new(
                    "mini baseline lifecycle transition is invalid",
                ));
            }
        };
        self.state = next;
        Ok(())
    }
}

impl Default for BaselineLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySample {
    pub elapsed_ms: u64,
    pub rss_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub scenario: String,
    pub platform: String,
    pub architecture: String,
    pub build_identity: String,
    pub process_start_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineReport {
    pub schema_version: u32,
    pub profile: BaselineProfile,
    pub connection_count: usize,
    pub baseline_rss_bytes: u64,
    pub peak_rss_bytes: u64,
    pub samples: Vec<MemorySample>,
}

impl BaselineReport {
    pub fn new(
        profile: BaselineProfile,
        connection_count: usize,
        samples: Vec<MemorySample>,
    ) -> Result<Self, HarnessError> {
        validate_profile(&profile)?;
        let baseline_rss_bytes = samples
            .first()
            .map(|sample| sample.rss_bytes)
            .ok_or_else(|| HarnessError::new("memory baseline report requires samples"))?;
        if samples.iter().any(|sample| sample.rss_bytes == 0) {
            return Err(HarnessError::new("memory baseline RSS must be positive"));
        }
        if samples
            .windows(2)
            .any(|window| window[0].elapsed_ms >= window[1].elapsed_ms)
        {
            return Err(HarnessError::new(
                "memory baseline samples must be strictly ordered",
            ));
        }
        let peak_rss_bytes = samples
            .iter()
            .map(|sample| sample.rss_bytes)
            .max()
            .expect("non-empty samples have a maximum");
        Ok(Self {
            schema_version: 1,
            profile,
            connection_count,
            baseline_rss_bytes,
            peak_rss_bytes,
            samples,
        })
    }

    pub fn to_canonical_json(&self) -> Result<String, HarnessError> {
        let mut encoded = serde_json::to_string_pretty(self)
            .map_err(|_| HarnessError::new("memory baseline report encoding failed"))?;
        encoded.push('\n');
        Ok(encoded)
    }
}

fn validate_profile(profile: &BaselineProfile) -> Result<(), HarnessError> {
    if [
        profile.scenario.as_str(),
        profile.platform.as_str(),
        profile.architecture.as_str(),
        profile.build_identity.as_str(),
        profile.process_start_identity.as_str(),
    ]
    .into_iter()
    .any(str::is_empty)
    {
        return Err(HarnessError::new(
            "memory baseline profile fields must be non-empty",
        ));
    }
    Ok(())
}
