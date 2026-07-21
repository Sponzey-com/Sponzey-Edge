use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::evaluator::AcceptanceResult;
use crate::http_driver::RuntimePressure;
use crate::release_http_scenario::{
    ReleaseHttpScenarioRecord, ReleaseScenarioOutcome, ReleaseScenarioState,
};
use crate::report::EvidenceIdentity;
use crate::report_io::{publish_canonical_bytes, sha256_hex, PublishedReport};
use crate::MemorySample;

pub const HTTP_MEMORY_EVIDENCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpEvidencePolicy {
    pub absolute_ceiling_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestEvidence {
    pub expected: u64,
    pub succeeded: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRssEvidence {
    pub baseline_bytes: u64,
    pub load_bytes: u64,
    pub peak_bytes: u64,
    pub cooldown_bytes: Vec<u64>,
    pub first_cooldown_median_bytes: u64,
    pub last_cooldown_median_bytes: u64,
    pub plateau_tolerance_bytes: u64,
    pub samples: Vec<MemorySample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRuntimeEvidence {
    pub revision_id: String,
    pub generation: u64,
    pub used_payload_bytes: u64,
    pub payload_limit_bytes: u64,
    pub active_connections: u64,
    pub pressure: RuntimePressure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpEvidenceOutcome {
    Passed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpMemoryEvidenceReport {
    pub schema_version: u32,
    pub identity: EvidenceIdentity,
    pub policy: HttpEvidencePolicy,
    pub requests: HttpRequestEvidence,
    pub rss: HttpRssEvidence,
    pub runtime: HttpRuntimeEvidence,
    pub outcome: HttpEvidenceOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpEvidenceError {
    InvalidSchema,
    InvalidIdentity,
    InvalidRecord,
    DigestMismatch,
    IdentityMismatch,
}

impl HttpMemoryEvidenceReport {
    pub fn new(
        identity: EvidenceIdentity,
        absolute_ceiling_bytes: u64,
        record: ReleaseHttpScenarioRecord,
    ) -> Result<Self, HttpEvidenceError> {
        if record.state != ReleaseScenarioState::Passed
            || record.outcome != ReleaseScenarioOutcome::Passed
        {
            return Err(HttpEvidenceError::InvalidRecord);
        }
        let counters = record.counters.ok_or(HttpEvidenceError::InvalidRecord)?;
        let runtime = record
            .runtime_status
            .ok_or(HttpEvidenceError::InvalidRecord)?;
        let observation = record.observation.ok_or(HttpEvidenceError::InvalidRecord)?;
        let evaluation = record.evaluation.ok_or(HttpEvidenceError::InvalidRecord)?;
        if !matches!(evaluation.result, AcceptanceResult::Passed) || record.samples.len() < 7 {
            return Err(HttpEvidenceError::InvalidRecord);
        }
        let cooldown_bytes = record.samples[2..]
            .iter()
            .map(|sample| sample.rss_bytes)
            .collect::<Vec<_>>();
        let report = Self {
            schema_version: HTTP_MEMORY_EVIDENCE_SCHEMA_VERSION,
            identity,
            policy: HttpEvidencePolicy {
                absolute_ceiling_bytes,
            },
            requests: HttpRequestEvidence {
                expected: counters.expected,
                succeeded: counters.succeeded,
                failed: counters.failed,
            },
            rss: HttpRssEvidence {
                baseline_bytes: record.samples[0].rss_bytes,
                load_bytes: record.samples[1].rss_bytes,
                peak_bytes: observation.peak_rss_bytes,
                cooldown_bytes,
                first_cooldown_median_bytes: evaluation.first_cooldown_median_bytes,
                last_cooldown_median_bytes: evaluation.last_cooldown_median_bytes,
                plateau_tolerance_bytes: evaluation.plateau_tolerance_bytes,
                samples: record.samples,
            },
            runtime: HttpRuntimeEvidence {
                revision_id: runtime.revision_id,
                generation: runtime.generation,
                used_payload_bytes: runtime.used_payload_bytes,
                payload_limit_bytes: runtime.payload_limit_bytes,
                active_connections: runtime.active_connections,
                pressure: runtime.pressure,
            },
            outcome: HttpEvidenceOutcome::Passed,
        };
        report.validate()?;
        if observation.successful_requests != report.requests.succeeded
            || observation.failed_requests != report.requests.failed
            || observation.active_connections_after_cooldown != report.runtime.active_connections
            || observation.charged_payload_bytes_after_cooldown != report.runtime.used_payload_bytes
            || observation.cooldown_cycle_medians != report.rss.cooldown_bytes
        {
            return Err(HttpEvidenceError::InvalidRecord);
        }
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), HttpEvidenceError> {
        if self.schema_version != HTTP_MEMORY_EVIDENCE_SCHEMA_VERSION {
            return Err(HttpEvidenceError::InvalidSchema);
        }
        validate_identity(&self.identity)?;
        if self.policy.absolute_ceiling_bytes == 0
            || self.requests.expected == 0
            || self.requests.succeeded.checked_add(self.requests.failed)
                != Some(self.requests.expected)
            || self.requests.failed != 0
            || self.requests.succeeded != self.requests.expected
            || self.runtime.revision_id.is_empty()
            || self.runtime.payload_limit_bytes == 0
            || self.runtime.active_connections != 0
            || self.runtime.used_payload_bytes != 0
            || self.runtime.pressure != RuntimePressure::Normal
            || self.rss.samples.len() < 7
            || self.rss.cooldown_bytes.len() != self.rss.samples.len() - 2
            || self.rss.cooldown_bytes.len() < 5
            || self.rss.samples.iter().any(|sample| sample.rss_bytes == 0)
            || self
                .rss
                .samples
                .windows(2)
                .any(|window| window[0].elapsed_ms >= window[1].elapsed_ms)
        {
            return Err(HttpEvidenceError::InvalidRecord);
        }
        let peak = self
            .rss
            .samples
            .iter()
            .map(|sample| sample.rss_bytes)
            .max()
            .ok_or(HttpEvidenceError::InvalidRecord)?;
        let cooldown = self.rss.samples[2..]
            .iter()
            .map(|sample| sample.rss_bytes)
            .collect::<Vec<_>>();
        let first = pair_median(cooldown[0], cooldown[1])?;
        let last = pair_median(cooldown[cooldown.len() - 2], cooldown[cooldown.len() - 1])?;
        let tolerance = (16 * 1024 * 1024).max(first / 10);
        let plateau_maximum = first
            .checked_add(tolerance)
            .ok_or(HttpEvidenceError::InvalidRecord)?;
        if self.rss.baseline_bytes != self.rss.samples[0].rss_bytes
            || self.rss.load_bytes != self.rss.samples[1].rss_bytes
            || self.rss.peak_bytes != peak
            || self.rss.peak_bytes > self.policy.absolute_ceiling_bytes
            || self.rss.cooldown_bytes != cooldown
            || self.rss.first_cooldown_median_bytes != first
            || self.rss.last_cooldown_median_bytes != last
            || self.rss.plateau_tolerance_bytes != tolerance
            || last > plateau_maximum
        {
            return Err(HttpEvidenceError::InvalidRecord);
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, HttpEvidenceError> {
        self.validate()?;
        let mut encoded =
            serde_json::to_string_pretty(self).map_err(|_| HttpEvidenceError::InvalidSchema)?;
        encoded.push('\n');
        Ok(encoded)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, HttpEvidenceError> {
        let report: Self =
            serde_json::from_slice(bytes).map_err(|_| HttpEvidenceError::InvalidSchema)?;
        report.validate()?;
        if report.to_canonical_json()?.as_bytes() != bytes {
            return Err(HttpEvidenceError::InvalidSchema);
        }
        Ok(report)
    }
}

fn pair_median(left: u64, right: u64) -> Result<u64, HttpEvidenceError> {
    left.checked_add(right)
        .map(|sum| sum / 2)
        .ok_or(HttpEvidenceError::InvalidRecord)
}

fn validate_identity(identity: &EvidenceIdentity) -> Result<(), HttpEvidenceError> {
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
        return Err(HttpEvidenceError::InvalidIdentity);
    }
    Ok(())
}

pub struct HttpEvidenceWriter;

impl HttpEvidenceWriter {
    pub fn publish(
        path: &Path,
        report: &HttpMemoryEvidenceReport,
    ) -> Result<PublishedReport, crate::HarnessError> {
        let encoded = report
            .to_canonical_json()
            .map_err(|_| crate::HarnessError::new("HTTP evidence validation failed"))?;
        publish_canonical_bytes(path, encoded.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEvidenceExpectations {
    pub scenario_id: String,
    pub scenario_version: String,
    pub build_identity: String,
    pub config_sha256: String,
}

pub struct HttpEvidenceValidator {
    expected: HttpEvidenceExpectations,
}

impl HttpEvidenceValidator {
    pub fn new(expected: HttpEvidenceExpectations) -> Self {
        Self { expected }
    }

    pub fn validate(
        &self,
        bytes: &[u8],
        expected_sha256: &str,
    ) -> Result<HttpMemoryEvidenceReport, HttpEvidenceError> {
        if expected_sha256.len() != 64 || sha256_hex(bytes) != expected_sha256 {
            return Err(HttpEvidenceError::DigestMismatch);
        }
        let report = HttpMemoryEvidenceReport::from_canonical_json(bytes)?;
        if report.identity.scenario_id != self.expected.scenario_id
            || report.identity.scenario_version != self.expected.scenario_version
            || report.identity.build_identity != self.expected.build_identity
            || report.identity.config_sha256 != self.expected.config_sha256
        {
            return Err(HttpEvidenceError::IdentityMismatch);
        }
        Ok(report)
    }
}
