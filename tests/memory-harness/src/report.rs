use serde::{Deserialize, Serialize};

use crate::orchestrator::{ScenarioOutcome, ScenarioRunRecord};
use crate::scenario::ScenarioState;
use crate::MemorySample;

pub const MEMORY_EVIDENCE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIdentity {
    pub scenario_id: String,
    pub scenario_version: String,
    pub platform: String,
    pub architecture: String,
    pub build_identity: String,
    pub config_sha256: String,
    pub process_start_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryEvidenceReport {
    pub schema_version: u32,
    pub identity: EvidenceIdentity,
    pub expected_samples: usize,
    pub missing_samples: usize,
    pub state: ScenarioState,
    pub outcome: ScenarioOutcome,
    pub baseline_rss_bytes: u64,
    pub peak_rss_bytes: u64,
    pub cooldown_rss_bytes: u64,
    pub samples: Vec<MemorySample>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportValidationError {
    InvalidSchema,
    InvalidIdentity,
    InvalidSamples,
    InvalidOutcome,
    DigestMismatch,
    IdentityMismatch,
}

impl MemoryEvidenceReport {
    pub fn new(
        identity: EvidenceIdentity,
        expected_samples: usize,
        run: ScenarioRunRecord,
    ) -> Result<Self, ReportValidationError> {
        let baseline_rss_bytes = run
            .samples
            .first()
            .map(|sample| sample.rss_bytes)
            .ok_or(ReportValidationError::InvalidSamples)?;
        let peak_rss_bytes = run
            .samples
            .iter()
            .map(|sample| sample.rss_bytes)
            .max()
            .ok_or(ReportValidationError::InvalidSamples)?;
        let cooldown_rss_bytes = run
            .samples
            .last()
            .map(|sample| sample.rss_bytes)
            .ok_or(ReportValidationError::InvalidSamples)?;
        let report = Self {
            schema_version: MEMORY_EVIDENCE_SCHEMA_VERSION,
            identity,
            expected_samples,
            missing_samples: run.missing_samples,
            state: run.state,
            outcome: run.outcome,
            baseline_rss_bytes,
            peak_rss_bytes,
            cooldown_rss_bytes,
            samples: run.samples,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), ReportValidationError> {
        if self.schema_version != MEMORY_EVIDENCE_SCHEMA_VERSION {
            return Err(ReportValidationError::InvalidSchema);
        }
        if [
            self.identity.scenario_id.as_str(),
            self.identity.scenario_version.as_str(),
            self.identity.platform.as_str(),
            self.identity.architecture.as_str(),
            self.identity.build_identity.as_str(),
            self.identity.config_sha256.as_str(),
            self.identity.process_start_identity.as_str(),
        ]
        .into_iter()
        .any(str::is_empty)
            || self.identity.config_sha256.len() != 64
            || !self
                .identity
                .config_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ReportValidationError::InvalidIdentity);
        }
        if self.expected_samples == 0
            || self.missing_samples > self.expected_samples / 100
            || self.samples.len().checked_add(self.missing_samples) != Some(self.expected_samples)
            || self.samples.iter().any(|sample| sample.rss_bytes == 0)
            || self
                .samples
                .windows(2)
                .any(|window| window[0].elapsed_ms >= window[1].elapsed_ms)
        {
            return Err(ReportValidationError::InvalidSamples);
        }
        let first = self
            .samples
            .first()
            .ok_or(ReportValidationError::InvalidSamples)?;
        let last = self
            .samples
            .last()
            .ok_or(ReportValidationError::InvalidSamples)?;
        let peak = self
            .samples
            .iter()
            .map(|sample| sample.rss_bytes)
            .max()
            .ok_or(ReportValidationError::InvalidSamples)?;
        if self.baseline_rss_bytes != first.rss_bytes
            || self.peak_rss_bytes != peak
            || self.cooldown_rss_bytes != last.rss_bytes
        {
            return Err(ReportValidationError::InvalidSamples);
        }
        let outcome_matches = matches!(
            (&self.state, &self.outcome),
            (ScenarioState::Passed, ScenarioOutcome::Passed)
                | (ScenarioState::Failed, ScenarioOutcome::Failed(_))
                | (
                    ScenarioState::InvalidEvidence,
                    ScenarioOutcome::InvalidEvidence(_)
                )
        );
        if !outcome_matches {
            return Err(ReportValidationError::InvalidOutcome);
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, ReportValidationError> {
        self.validate()?;
        let mut encoded =
            serde_json::to_string_pretty(self).map_err(|_| ReportValidationError::InvalidSchema)?;
        encoded.push('\n');
        Ok(encoded)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, ReportValidationError> {
        let report: Self =
            serde_json::from_slice(bytes).map_err(|_| ReportValidationError::InvalidSchema)?;
        report.validate()?;
        if report.to_canonical_json()?.as_bytes() != bytes {
            return Err(ReportValidationError::InvalidSchema);
        }
        Ok(report)
    }
}
