use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::HarnessError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    SingleRun,
    ThreeRun,
    FiveCycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FullProfileScenarioContract {
    pub scenario_id: &'static str,
    pub evidence_kind: EvidenceKind,
    pub rss_ceiling_bytes: u64,
}

pub const FULL_PROFILE_SCENARIOS: [FullProfileScenarioContract; 12] = [
    contract("idle", EvidenceKind::SingleRun, 128),
    contract("http-steady", EvidenceKind::ThreeRun, 384),
    contract("http-idle-1024", EvidenceKind::SingleRun, 256),
    contract("slow-header", EvidenceKind::FiveCycle, 384),
    contract("slow-body", EvidenceKind::FiveCycle, 512),
    contract("slow-response", EvidenceKind::FiveCycle, 512),
    contract("connection-churn", EvidenceKind::FiveCycle, 384),
    contract("https-steady", EvidenceKind::ThreeRun, 384),
    contract("https-idle-512", EvidenceKind::SingleRun, 384),
    contract("mtls-steady", EvidenceKind::ThreeRun, 384),
    contract("websocket-128", EvidenceKind::FiveCycle, 384),
    contract("control-max", EvidenceKind::SingleRun, 512),
];

const fn contract(
    scenario_id: &'static str,
    evidence_kind: EvidenceKind,
    ceiling_mib: u64,
) -> FullProfileScenarioContract {
    FullProfileScenarioContract {
        scenario_id,
        evidence_kind,
        rss_ceiling_bytes: ceiling_mib * 1024 * 1024,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullProfileEntry {
    pub scenario_id: String,
    pub evidence_kind: EvidenceKind,
    pub build_identity: String,
    pub report_sha256: String,
    pub validation_passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullProfileInput {
    pub current_build_identity: String,
    pub platform: String,
    pub architecture: String,
    pub entries: Vec<FullProfileEntry>,
}

impl FullProfileInput {
    pub fn from_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("full profile input is invalid"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioReadiness {
    Verified,
    Missing,
    Stale,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullProfileScenarioResult {
    pub scenario_id: String,
    pub expected_evidence_kind: EvidenceKind,
    pub observed_evidence_kind: Option<EvidenceKind>,
    pub rss_ceiling_bytes: u64,
    pub readiness: ScenarioReadiness,
    pub report_sha256: Option<String>,
    pub blocker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullProfileReadinessReport {
    pub schema_version: u32,
    pub profile_id: String,
    pub build_identity: String,
    pub platform: String,
    pub architecture: String,
    pub ready: bool,
    pub blockers: Vec<String>,
    pub scenarios: Vec<FullProfileScenarioResult>,
}

impl FullProfileReadinessReport {
    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.schema_version != 1
            || self.profile_id != "phase011-full-profile-readiness-v1"
            || !valid_build_identity(&self.build_identity)
            || self.platform.is_empty()
            || self.architecture.is_empty()
            || self.scenarios.len() != FULL_PROFILE_SCENARIOS.len()
        {
            return Err(HarnessError::new("full profile report header is invalid"));
        }
        let mut blockers = Vec::new();
        for (result, contract) in self.scenarios.iter().zip(FULL_PROFILE_SCENARIOS) {
            if result.scenario_id != contract.scenario_id
                || result.expected_evidence_kind != contract.evidence_kind
                || result.rss_ceiling_bytes != contract.rss_ceiling_bytes
                || result
                    .report_sha256
                    .as_deref()
                    .is_some_and(|digest| !valid_digest(digest))
            {
                return Err(HarnessError::new("full profile scenario result is invalid"));
            }
            match result.readiness {
                ScenarioReadiness::Verified => {
                    if result.observed_evidence_kind != Some(contract.evidence_kind)
                        || result.report_sha256.is_none()
                        || result.blocker.is_some()
                    {
                        return Err(HarnessError::new(
                            "verified full profile scenario is invalid",
                        ));
                    }
                }
                ScenarioReadiness::Missing => {
                    if result.observed_evidence_kind.is_some()
                        || result.report_sha256.is_some()
                        || result.blocker.as_deref()
                            != Some(&format!("{}:missing", contract.scenario_id))
                    {
                        return Err(HarnessError::new(
                            "missing full profile scenario is invalid",
                        ));
                    }
                }
                ScenarioReadiness::Stale | ScenarioReadiness::Failed => {
                    if result.observed_evidence_kind.is_none()
                        || result.report_sha256.is_none()
                        || result.blocker.is_none()
                    {
                        return Err(HarnessError::new(
                            "blocked full profile scenario is invalid",
                        ));
                    }
                }
            }
            if let Some(blocker) = &result.blocker {
                blockers.push(blocker.clone());
            }
        }
        if self.blockers != blockers || self.ready != blockers.is_empty() {
            return Err(HarnessError::new("full profile readiness is inconsistent"));
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, HarnessError> {
        self.validate()?;
        let mut encoded = serde_json::to_string_pretty(self)
            .map_err(|_| HarnessError::new("full profile report encoding failed"))?;
        encoded.push('\n');
        Ok(encoded)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        let report: Self = serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("full profile report decoding failed"))?;
        report.validate()?;
        if report.to_canonical_json()?.as_bytes() != bytes {
            return Err(HarnessError::new("full profile report is not canonical"));
        }
        Ok(report)
    }
}

pub fn evaluate_full_profile(
    input: FullProfileInput,
) -> Result<FullProfileReadinessReport, HarnessError> {
    if !valid_build_identity(&input.current_build_identity)
        || input.platform.is_empty()
        || input.architecture.is_empty()
    {
        return Err(HarnessError::new("full profile identity is invalid"));
    }
    let allowed = FULL_PROFILE_SCENARIOS
        .iter()
        .map(|contract| contract.scenario_id)
        .collect::<BTreeSet<_>>();
    let mut entries = BTreeMap::new();
    for entry in input.entries {
        if !allowed.contains(entry.scenario_id.as_str())
            || !valid_build_identity(&entry.build_identity)
            || !valid_digest(&entry.report_sha256)
            || entries.insert(entry.scenario_id.clone(), entry).is_some()
        {
            return Err(HarnessError::new("full profile entry is invalid"));
        }
    }

    let mut blockers = Vec::new();
    let mut scenarios = Vec::with_capacity(FULL_PROFILE_SCENARIOS.len());
    for contract in FULL_PROFILE_SCENARIOS {
        let result = match entries.remove(contract.scenario_id) {
            None => blocked_result(contract, ScenarioReadiness::Missing, None, "missing"),
            Some(entry) if entry.evidence_kind != contract.evidence_kind => blocked_result(
                contract,
                ScenarioReadiness::Failed,
                Some(entry),
                "wrong_evidence_kind",
            ),
            Some(entry) if entry.build_identity != input.current_build_identity => blocked_result(
                contract,
                ScenarioReadiness::Stale,
                Some(entry),
                "stale_source",
            ),
            Some(entry) if !entry.validation_passed => blocked_result(
                contract,
                ScenarioReadiness::Failed,
                Some(entry),
                "validation_failed",
            ),
            Some(entry) => FullProfileScenarioResult {
                scenario_id: contract.scenario_id.to_string(),
                expected_evidence_kind: contract.evidence_kind,
                observed_evidence_kind: Some(entry.evidence_kind),
                rss_ceiling_bytes: contract.rss_ceiling_bytes,
                readiness: ScenarioReadiness::Verified,
                report_sha256: Some(entry.report_sha256),
                blocker: None,
            },
        };
        if let Some(blocker) = &result.blocker {
            blockers.push(blocker.clone());
        }
        scenarios.push(result);
    }
    let report = FullProfileReadinessReport {
        schema_version: 1,
        profile_id: "phase011-full-profile-readiness-v1".to_string(),
        build_identity: input.current_build_identity,
        platform: input.platform,
        architecture: input.architecture,
        ready: blockers.is_empty(),
        blockers,
        scenarios,
    };
    report.validate()?;
    Ok(report)
}

fn blocked_result(
    contract: FullProfileScenarioContract,
    readiness: ScenarioReadiness,
    entry: Option<FullProfileEntry>,
    reason: &str,
) -> FullProfileScenarioResult {
    FullProfileScenarioResult {
        scenario_id: contract.scenario_id.to_string(),
        expected_evidence_kind: contract.evidence_kind,
        observed_evidence_kind: entry.as_ref().map(|entry| entry.evidence_kind),
        rss_ceiling_bytes: contract.rss_ceiling_bytes,
        readiness,
        report_sha256: entry.map(|entry| entry.report_sha256),
        blocker: Some(format!("{}:{reason}", contract.scenario_id)),
    }
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
