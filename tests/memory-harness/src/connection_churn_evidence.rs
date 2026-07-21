use serde::{Deserialize, Serialize};

use crate::connection_churn::{ChurnScenarioOutcome, ChurnScenarioRecord, ChurnScenarioState};
use crate::evaluator::AcceptanceResult;
use crate::http_driver::RuntimePressure;
use crate::report::EvidenceIdentity;
use crate::report_io::sha256_hex;

pub const CHURN_EVIDENCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChurnEvidencePolicy {
    pub absolute_ceiling_bytes: u64,
    pub cycles: usize,
    pub requests_per_cycle: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChurnRequestEvidence {
    pub expected: u64,
    pub succeeded: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChurnRuntimeEvidence {
    pub revision_id: String,
    pub generation: u64,
    pub active_connections: u64,
    pub used_payload_bytes: u64,
    pub payload_limit_bytes: u64,
    pub pressure: RuntimePressure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChurnCycleEvidence {
    pub cycle: usize,
    pub requests: ChurnRequestEvidence,
    pub runtime: ChurnRuntimeEvidence,
    pub cooldown_rss_bytes: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChurnRssEvidence {
    pub baseline_bytes: u64,
    pub observed_peak_bytes: u64,
    pub first_cooldown_median_bytes: u64,
    pub last_cooldown_median_bytes: u64,
    pub plateau_tolerance_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChurnEvidenceOutcome {
    Passed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChurnMemoryEvidenceReport {
    pub schema_version: u32,
    pub identity: EvidenceIdentity,
    pub policy: ChurnEvidencePolicy,
    pub requests: ChurnRequestEvidence,
    pub cycles: Vec<ChurnCycleEvidence>,
    pub rss: ChurnRssEvidence,
    pub outcome: ChurnEvidenceOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChurnEvidenceError {
    InvalidSchema,
    InvalidIdentity,
    InvalidRecord,
    DigestMismatch,
    IdentityMismatch,
}

impl ChurnMemoryEvidenceReport {
    pub fn new(
        identity: EvidenceIdentity,
        absolute_ceiling_bytes: u64,
        expected_cycles: usize,
        requests_per_cycle: u64,
        record: ChurnScenarioRecord,
    ) -> Result<Self, ChurnEvidenceError> {
        if record.state != ChurnScenarioState::Passed
            || record.outcome != ChurnScenarioOutcome::Passed
            || record.cycles.len() != expected_cycles
            || expected_cycles < 5
        {
            return Err(ChurnEvidenceError::InvalidRecord);
        }
        let evaluation = record.evaluation.ok_or(ChurnEvidenceError::InvalidRecord)?;
        if !matches!(evaluation.result, AcceptanceResult::Passed) {
            return Err(ChurnEvidenceError::InvalidRecord);
        }
        let report = Self {
            schema_version: CHURN_EVIDENCE_SCHEMA_VERSION,
            identity,
            policy: ChurnEvidencePolicy {
                absolute_ceiling_bytes,
                cycles: expected_cycles,
                requests_per_cycle,
            },
            requests: ChurnRequestEvidence {
                expected: record.expected_requests,
                succeeded: record.succeeded_requests,
                failed: record.failed_requests,
            },
            cycles: record
                .cycles
                .into_iter()
                .map(|cycle| ChurnCycleEvidence {
                    cycle: cycle.cycle,
                    requests: ChurnRequestEvidence {
                        expected: cycle.counters.expected,
                        succeeded: cycle.counters.succeeded,
                        failed: cycle.counters.failed,
                    },
                    runtime: ChurnRuntimeEvidence {
                        revision_id: cycle.runtime.revision_id,
                        generation: cycle.runtime.generation,
                        active_connections: cycle.runtime.active_connections,
                        used_payload_bytes: cycle.runtime.used_payload_bytes,
                        payload_limit_bytes: cycle.runtime.payload_limit_bytes,
                        pressure: cycle.runtime.pressure,
                    },
                    cooldown_rss_bytes: cycle.cooldown_rss_bytes,
                    elapsed_ms: cycle.elapsed_ms,
                })
                .collect(),
            rss: ChurnRssEvidence {
                baseline_bytes: record.baseline_rss_bytes,
                observed_peak_bytes: record.peak_rss_bytes,
                first_cooldown_median_bytes: evaluation.first_cooldown_median_bytes,
                last_cooldown_median_bytes: evaluation.last_cooldown_median_bytes,
                plateau_tolerance_bytes: evaluation.plateau_tolerance_bytes,
            },
            outcome: ChurnEvidenceOutcome::Passed,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), ChurnEvidenceError> {
        if self.schema_version != CHURN_EVIDENCE_SCHEMA_VERSION {
            return Err(ChurnEvidenceError::InvalidSchema);
        }
        validate_identity(&self.identity)?;
        let expected_total = self
            .policy
            .requests_per_cycle
            .checked_mul(self.policy.cycles as u64)
            .ok_or(ChurnEvidenceError::InvalidRecord)?;
        if self.policy.cycles < 5
            || self.policy.absolute_ceiling_bytes == 0
            || self.policy.requests_per_cycle == 0
            || self.cycles.len() != self.policy.cycles
            || self.requests.expected != expected_total
            || self.requests.succeeded != expected_total
            || self.requests.failed != 0
            || self.rss.baseline_bytes == 0
        {
            return Err(ChurnEvidenceError::InvalidRecord);
        }
        for (index, cycle) in self.cycles.iter().enumerate() {
            if cycle.cycle != index + 1
                || cycle.requests.expected != self.policy.requests_per_cycle
                || cycle.requests.succeeded != self.policy.requests_per_cycle
                || cycle.requests.failed != 0
                || cycle.runtime.revision_id.is_empty()
                || cycle.runtime.payload_limit_bytes == 0
                || cycle.runtime.active_connections != 0
                || cycle.runtime.used_payload_bytes != 0
                || cycle.runtime.pressure != RuntimePressure::Normal
                || cycle.cooldown_rss_bytes == 0
                || (index > 0 && self.cycles[index - 1].elapsed_ms >= cycle.elapsed_ms)
            {
                return Err(ChurnEvidenceError::InvalidRecord);
            }
        }
        let observed_peak = self
            .cycles
            .iter()
            .map(|cycle| cycle.cooldown_rss_bytes)
            .chain(std::iter::once(self.rss.baseline_bytes))
            .max()
            .ok_or(ChurnEvidenceError::InvalidRecord)?;
        let first = pair_median(
            self.cycles[0].cooldown_rss_bytes,
            self.cycles[1].cooldown_rss_bytes,
        )?;
        let last = pair_median(
            self.cycles[self.cycles.len() - 2].cooldown_rss_bytes,
            self.cycles[self.cycles.len() - 1].cooldown_rss_bytes,
        )?;
        let tolerance = (16 * 1024 * 1024).max(first / 10);
        if self.rss.observed_peak_bytes != observed_peak
            || observed_peak > self.policy.absolute_ceiling_bytes
            || self.rss.first_cooldown_median_bytes != first
            || self.rss.last_cooldown_median_bytes != last
            || self.rss.plateau_tolerance_bytes != tolerance
            || last
                > first
                    .checked_add(tolerance)
                    .ok_or(ChurnEvidenceError::InvalidRecord)?
        {
            return Err(ChurnEvidenceError::InvalidRecord);
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, ChurnEvidenceError> {
        self.validate()?;
        let mut encoded =
            serde_json::to_string_pretty(self).map_err(|_| ChurnEvidenceError::InvalidSchema)?;
        encoded.push('\n');
        Ok(encoded)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, ChurnEvidenceError> {
        let report: Self =
            serde_json::from_slice(bytes).map_err(|_| ChurnEvidenceError::InvalidSchema)?;
        report.validate()?;
        if report.to_canonical_json()?.as_bytes() != bytes {
            return Err(ChurnEvidenceError::InvalidSchema);
        }
        Ok(report)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChurnEvidenceExpectations {
    pub scenario_id: String,
    pub scenario_version: String,
    pub build_identity: String,
    pub config_sha256: String,
}

pub struct ChurnEvidenceValidator {
    expected: ChurnEvidenceExpectations,
}

impl ChurnEvidenceValidator {
    pub fn new(expected: ChurnEvidenceExpectations) -> Self {
        Self { expected }
    }

    pub fn validate(
        &self,
        bytes: &[u8],
        expected_sha256: &str,
    ) -> Result<ChurnMemoryEvidenceReport, ChurnEvidenceError> {
        if expected_sha256.len() != 64 || sha256_hex(bytes) != expected_sha256 {
            return Err(ChurnEvidenceError::DigestMismatch);
        }
        let report = ChurnMemoryEvidenceReport::from_canonical_json(bytes)?;
        if report.identity.scenario_id != self.expected.scenario_id
            || report.identity.scenario_version != self.expected.scenario_version
            || report.identity.build_identity != self.expected.build_identity
            || report.identity.config_sha256 != self.expected.config_sha256
        {
            return Err(ChurnEvidenceError::IdentityMismatch);
        }
        Ok(report)
    }
}

fn pair_median(left: u64, right: u64) -> Result<u64, ChurnEvidenceError> {
    left.checked_add(right)
        .map(|sum| sum / 2)
        .ok_or(ChurnEvidenceError::InvalidRecord)
}

fn validate_identity(identity: &EvidenceIdentity) -> Result<(), ChurnEvidenceError> {
    if [
        identity.scenario_id.as_str(),
        identity.scenario_version.as_str(),
        identity.platform.as_str(),
        identity.architecture.as_str(),
        identity.build_identity.as_str(),
        identity.config_sha256.as_str(),
        identity.process_start_identity.as_str(),
    ]
    .into_iter()
    .any(str::is_empty)
        || identity.config_sha256.len() != 64
        || !identity
            .config_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ChurnEvidenceError::InvalidIdentity);
    }
    Ok(())
}
