use serde::{Deserialize, Serialize};

use crate::diagnostic_soak::{DiagnosticSoakReport, SOAK_DURATION_SECONDS, SOAK_OBSERVATION_COUNT};
use crate::full_profile_readiness::{
    evaluate_full_profile, FullProfileInput, FullProfileReadinessReport, FULL_PROFILE_SCENARIOS,
};
use crate::HarnessError;

pub const PHASE011_MEMORY_RELEASE_MARKER: &str =
    "phase 011 quantitative memory and resource safety passed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryReleaseState {
    Created,
    InputsVerified,
    ReportsValidated,
    Bound,
    Published,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryReleaseEvent {
    InputsVerified,
    ReportsValidated,
    Bound,
    Published,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryReleaseLifecycle {
    state: MemoryReleaseState,
}

impl MemoryReleaseLifecycle {
    pub fn new() -> Self {
        Self {
            state: MemoryReleaseState::Created,
        }
    }

    pub fn state(&self) -> MemoryReleaseState {
        self.state
    }

    pub fn transition(&mut self, event: MemoryReleaseEvent) -> Result<(), HarnessError> {
        let next = match (self.state, event) {
            (MemoryReleaseState::Created, MemoryReleaseEvent::InputsVerified) => {
                MemoryReleaseState::InputsVerified
            }
            (MemoryReleaseState::InputsVerified, MemoryReleaseEvent::ReportsValidated) => {
                MemoryReleaseState::ReportsValidated
            }
            (MemoryReleaseState::ReportsValidated, MemoryReleaseEvent::Bound) => {
                MemoryReleaseState::Bound
            }
            (MemoryReleaseState::Bound, MemoryReleaseEvent::Published) => {
                MemoryReleaseState::Published
            }
            (MemoryReleaseState::Published | MemoryReleaseState::Failed, _) => {
                return Err(HarnessError::new(
                    "memory release terminal state rejects transitions",
                ));
            }
            (_, MemoryReleaseEvent::Fail) => MemoryReleaseState::Failed,
            _ => {
                self.state = MemoryReleaseState::Failed;
                return Err(HarnessError::new(
                    "memory release transition is out of order",
                ));
            }
        };
        self.state = next;
        Ok(())
    }
}

impl Default for MemoryReleaseLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryReleaseInput {
    pub expected_build_identity: String,
    pub expected_platform: String,
    pub expected_architecture: String,
    pub inventory: FullProfileInput,
    pub inventory_sha256: String,
    pub readiness: FullProfileReadinessReport,
    pub readiness_sha256: String,
    pub soak: DiagnosticSoakReport,
    pub soak_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase011MemoryReleaseReport {
    pub schema_version: u32,
    pub profile_id: String,
    pub build_identity: String,
    pub platform: String,
    pub architecture: String,
    pub full_profile_scenarios: u32,
    pub full_profile_ready: bool,
    pub full_profile_blockers: u32,
    pub inventory_sha256: String,
    pub readiness_sha256: String,
    pub soak_sha256: String,
    pub soak_duration_seconds: u64,
    pub soak_observations: u32,
    pub soak_plateau_passed: bool,
    pub marker: String,
}

impl Phase011MemoryReleaseReport {
    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.schema_version != 1
            || self.profile_id != "phase011-memory-release-v1"
            || !valid_build_identity(&self.build_identity)
            || self.platform.is_empty()
            || self.architecture.is_empty()
            || self.full_profile_scenarios != FULL_PROFILE_SCENARIOS.len() as u32
            || !self.full_profile_ready
            || self.full_profile_blockers != 0
            || !valid_digest(&self.inventory_sha256)
            || !valid_digest(&self.readiness_sha256)
            || !valid_digest(&self.soak_sha256)
            || self.soak_duration_seconds != SOAK_DURATION_SECONDS
            || self.soak_observations != SOAK_OBSERVATION_COUNT
            || !self.soak_plateau_passed
            || self.marker != PHASE011_MEMORY_RELEASE_MARKER
        {
            return Err(HarnessError::new(
                "Phase 011 memory release report is invalid",
            ));
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, HarnessError> {
        self.validate()?;
        let mut encoded = serde_json::to_string_pretty(self)
            .map_err(|_| HarnessError::new("Phase 011 memory release encoding failed"))?;
        encoded.push('\n');
        Ok(encoded)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        let report: Self = serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("Phase 011 memory release decoding failed"))?;
        report.validate()?;
        if report.to_canonical_json()?.as_bytes() != bytes {
            return Err(HarnessError::new(
                "Phase 011 memory release report is not canonical",
            ));
        }
        Ok(report)
    }
}

pub fn evaluate_phase011_memory_release(
    input: MemoryReleaseInput,
) -> Result<Phase011MemoryReleaseReport, HarnessError> {
    if !valid_build_identity(&input.expected_build_identity)
        || input.expected_platform.is_empty()
        || input.expected_architecture.is_empty()
        || !valid_digest(&input.inventory_sha256)
        || !valid_digest(&input.readiness_sha256)
        || !valid_digest(&input.soak_sha256)
    {
        return Err(HarnessError::new(
            "memory release input identity is invalid",
        ));
    }
    if input.inventory.current_build_identity != input.expected_build_identity
        || input.inventory.platform != input.expected_platform
        || input.inventory.architecture != input.expected_architecture
    {
        return Err(HarnessError::new(
            "memory release full profile identity is invalid",
        ));
    }
    let expected_readiness = evaluate_full_profile(input.inventory.clone())?;
    input.readiness.validate()?;
    if input.readiness != expected_readiness
        || !input.readiness.ready
        || !input.readiness.blockers.is_empty()
        || input.readiness.build_identity != input.expected_build_identity
        || input.readiness.platform != input.expected_platform
        || input.readiness.architecture != input.expected_architecture
    {
        return Err(HarnessError::new(
            "memory release full profile readiness is invalid",
        ));
    }
    input.soak.validate()?;
    if input.soak.build_identity != input.expected_build_identity {
        return Err(HarnessError::new(
            "memory release soak source identity is invalid",
        ));
    }
    let report = Phase011MemoryReleaseReport {
        schema_version: 1,
        profile_id: "phase011-memory-release-v1".to_string(),
        build_identity: input.expected_build_identity,
        platform: input.expected_platform,
        architecture: input.expected_architecture,
        full_profile_scenarios: FULL_PROFILE_SCENARIOS.len() as u32,
        full_profile_ready: true,
        full_profile_blockers: 0,
        inventory_sha256: input.inventory_sha256,
        readiness_sha256: input.readiness_sha256,
        soak_sha256: input.soak_sha256,
        soak_duration_seconds: input.soak.duration_seconds,
        soak_observations: input.soak.observation_count,
        soak_plateau_passed: input.soak.plateau_passed,
        marker: PHASE011_MEMORY_RELEASE_MARKER.to_string(),
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
