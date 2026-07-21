use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::orchestrator::ScenarioOutcome;
use crate::report::MemoryEvidenceReport;
use crate::report_io::sha256_hex;
use crate::scenario::ScenarioState;
use crate::HarnessError;

pub const MEMORY_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const STEADY_PROFILE_ID: &str = "phase011-steady-v1";
pub const STEADY_PROFILE_SCENARIOS: [&str; 3] = ["http-steady", "https-steady", "mtls-steady"];
pub const STEADY_RSS_CEILING_BYTES: u64 = 402_653_184;
pub const PAYLOAD_BUDGET_BYTES: u64 = 134_217_728;
pub const CONNECTION_LIMIT: u64 = 1_024;

const APPROVAL_BLOCKERS: [&str; 3] = [
    "linux-x86_64-profile",
    "three-independent-repetitions",
    "long-soak-and-deep-diagnostic",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryManifestStatus {
    Partial,
    Approved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestInputs {
    pub input_dir: PathBuf,
    pub build_identity: String,
    pub platform: String,
    pub architecture: String,
    pub repetitions: u32,
    pub status: MemoryManifestStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryManifestEntry {
    pub scenario_id: String,
    pub scenario_version: String,
    pub report_file: String,
    pub report_sha256: String,
    pub driver_summary_file: String,
    pub driver_summary_sha256: String,
    pub terminal_summary_file: String,
    pub terminal_summary_sha256: String,
    pub config_sha256: String,
    pub expected_requests: u64,
    pub succeeded_requests: u64,
    pub failed_requests: u64,
    pub workers: u64,
    pub rejected_negatives: u64,
    pub forwarded_requests: u64,
    pub observed_status_samples: u64,
    pub max_active_connections: u64,
    pub max_charged_payload_bytes: u64,
    pub cleanup_active_connections: u64,
    pub cleanup_charged_payload_bytes: u64,
    pub cleanup_pressure: String,
    pub recovery_status: u16,
    pub peak_rss_bytes: u64,
    pub rss_ceiling_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryEvidenceManifest {
    pub schema_version: u32,
    pub profile_id: String,
    pub collector_version: String,
    pub build_identity: String,
    pub platform: String,
    pub architecture: String,
    pub repetitions: u32,
    pub status: MemoryManifestStatus,
    pub approval_blockers: Vec<String>,
    pub entries: Vec<MemoryManifestEntry>,
}

impl MemoryEvidenceManifest {
    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.schema_version != MEMORY_MANIFEST_SCHEMA_VERSION
            || self.profile_id != STEADY_PROFILE_ID
            || self.collector_version != "edge-memory-manifest-v1"
            || !valid_build_identity(&self.build_identity)
            || self.platform.is_empty()
            || self.architecture.is_empty()
            || self.repetitions != 1
            || self.status != MemoryManifestStatus::Partial
            || self.approval_blockers
                != APPROVAL_BLOCKERS
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect::<Vec<_>>()
        {
            return Err(HarnessError::new("memory manifest header is invalid"));
        }
        if self.entries.len() != STEADY_PROFILE_SCENARIOS.len() {
            return Err(HarnessError::new(
                "memory manifest scenario count is invalid",
            ));
        }
        for (entry, expected_id) in self.entries.iter().zip(STEADY_PROFILE_SCENARIOS) {
            validate_entry(entry, expected_id)?;
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, HarnessError> {
        self.validate()?;
        let mut encoded = serde_json::to_string_pretty(self)
            .map_err(|_| HarnessError::new("memory manifest encoding failed"))?;
        encoded.push('\n');
        Ok(encoded)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("memory manifest decoding failed"))?;
        manifest.validate()?;
        if manifest.to_canonical_json()?.as_bytes() != bytes {
            return Err(HarnessError::new("memory manifest is not canonical"));
        }
        Ok(manifest)
    }
}

pub fn collect_manifest(inputs: &ManifestInputs) -> Result<MemoryEvidenceManifest, HarnessError> {
    validate_inputs(inputs)?;
    reject_unknown_or_non_regular_inputs(&inputs.input_dir)?;

    let entries = STEADY_PROFILE_SCENARIOS
        .iter()
        .map(|scenario_id| collect_entry(inputs, scenario_id))
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = MemoryEvidenceManifest {
        schema_version: MEMORY_MANIFEST_SCHEMA_VERSION,
        profile_id: STEADY_PROFILE_ID.to_string(),
        collector_version: "edge-memory-manifest-v1".to_string(),
        build_identity: inputs.build_identity.clone(),
        platform: inputs.platform.clone(),
        architecture: inputs.architecture.clone(),
        repetitions: inputs.repetitions,
        status: inputs.status,
        approval_blockers: APPROVAL_BLOCKERS
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        entries,
    };
    manifest.validate()?;
    Ok(manifest)
}

pub fn validate_manifest(
    inputs: &ManifestInputs,
    bytes: &[u8],
    expected_digest: &str,
) -> Result<MemoryEvidenceManifest, HarnessError> {
    if !valid_digest(expected_digest) || sha256_hex(bytes) != expected_digest {
        return Err(HarnessError::new("memory manifest digest mismatch"));
    }
    let supplied = MemoryEvidenceManifest::from_canonical_json(bytes)?;
    let collected = collect_manifest(inputs)?;
    if supplied != collected {
        return Err(HarnessError::new(
            "memory manifest does not match source reports",
        ));
    }
    Ok(supplied)
}

pub fn inspect_manifest(
    bytes: &[u8],
    expected_digest: &str,
    expected_build_identity: &str,
) -> Result<MemoryEvidenceManifest, HarnessError> {
    if !valid_digest(expected_digest) || sha256_hex(bytes) != expected_digest {
        return Err(HarnessError::new("memory manifest digest mismatch"));
    }
    let manifest = MemoryEvidenceManifest::from_canonical_json(bytes)?;
    if manifest.build_identity != expected_build_identity {
        return Err(HarnessError::new(
            "memory manifest source identity mismatch",
        ));
    }
    Ok(manifest)
}

fn validate_inputs(inputs: &ManifestInputs) -> Result<(), HarnessError> {
    if !valid_build_identity(&inputs.build_identity)
        || inputs.platform.is_empty()
        || inputs.architecture.is_empty()
        || inputs.repetitions != 1
        || inputs.status != MemoryManifestStatus::Partial
    {
        return Err(HarnessError::new("memory manifest inputs are invalid"));
    }
    let metadata = fs::symlink_metadata(&inputs.input_dir)
        .map_err(|_| HarnessError::new("memory manifest input directory is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HarnessError::new(
            "memory manifest input must be a physical directory",
        ));
    }
    Ok(())
}

fn collect_entry(
    inputs: &ManifestInputs,
    scenario_id: &str,
) -> Result<MemoryManifestEntry, HarnessError> {
    let contract = ScenarioContract::for_id(scenario_id)
        .ok_or_else(|| HarnessError::new("unknown memory manifest scenario"))?;
    let report_file = format!("{scenario_id}-v1.json");
    let digest_file = format!("{scenario_id}-v1.sha256");
    let driver_file = format!("{scenario_id}-driver-summary.json");
    let summary_file = format!("{scenario_id}-summary.txt");
    let report_bytes = read_regular(&inputs.input_dir.join(&report_file))?;
    let digest_bytes = read_regular(&inputs.input_dir.join(&digest_file))?;
    let driver_bytes = read_regular(&inputs.input_dir.join(&driver_file))?;
    let summary_bytes = read_regular(&inputs.input_dir.join(&summary_file))?;
    reject_sensitive_material(&report_bytes)?;
    reject_sensitive_material(&driver_bytes)?;
    reject_sensitive_material(&summary_bytes)?;

    let expected_report_digest = parse_digest_file(&digest_bytes)?;
    if sha256_hex(&report_bytes) != expected_report_digest {
        return Err(HarnessError::new("memory scenario report digest mismatch"));
    }
    let report = MemoryEvidenceReport::from_canonical_json(&report_bytes)
        .map_err(|_| HarnessError::new("memory scenario report is invalid"))?;
    if report.identity.scenario_id != contract.id
        || report.identity.scenario_version != "phase011-v1"
        || report.identity.build_identity != inputs.build_identity
        || report.identity.platform != inputs.platform
        || report.identity.architecture != inputs.architecture
        || report.state != ScenarioState::Passed
        || report.outcome != ScenarioOutcome::Passed
        || report.peak_rss_bytes > STEADY_RSS_CEILING_BYTES
    {
        return Err(HarnessError::new(
            "memory scenario report identity or outcome mismatch",
        ));
    }

    let driver = DriverSummary::from_canonical_json(&driver_bytes)?;
    if driver.expected != contract.expected_requests
        || driver.succeeded != contract.expected_requests
        || driver.failed != 0
        || driver.workers != contract.workers
        || driver.state != "completed"
    {
        return Err(HarnessError::new("memory driver summary contract mismatch"));
    }
    let terminal = TerminalSummary::parse(&summary_bytes, &contract)?;
    if terminal.peak_rss_bytes != report.peak_rss_bytes {
        return Err(HarnessError::new(
            "memory summary peak does not match report",
        ));
    }

    Ok(MemoryManifestEntry {
        scenario_id: contract.id.to_string(),
        scenario_version: report.identity.scenario_version,
        report_file,
        report_sha256: expected_report_digest,
        driver_summary_file: driver_file,
        driver_summary_sha256: sha256_hex(&driver_bytes),
        terminal_summary_file: summary_file,
        terminal_summary_sha256: sha256_hex(&summary_bytes),
        config_sha256: report.identity.config_sha256,
        expected_requests: driver.expected,
        succeeded_requests: driver.succeeded,
        failed_requests: driver.failed,
        workers: driver.workers,
        rejected_negatives: terminal.rejected_negatives,
        forwarded_requests: terminal.forwarded_requests,
        observed_status_samples: terminal.samples,
        max_active_connections: terminal.max_active,
        max_charged_payload_bytes: terminal.max_charge,
        cleanup_active_connections: terminal.cleanup_active,
        cleanup_charged_payload_bytes: terminal.cleanup_charge,
        cleanup_pressure: terminal.cleanup_pressure,
        recovery_status: terminal.recovery,
        peak_rss_bytes: report.peak_rss_bytes,
        rss_ceiling_bytes: STEADY_RSS_CEILING_BYTES,
    })
}

fn validate_entry(entry: &MemoryManifestEntry, expected_id: &str) -> Result<(), HarnessError> {
    let contract = ScenarioContract::for_id(expected_id)
        .ok_or_else(|| HarnessError::new("memory manifest contract is invalid"))?;
    if entry.scenario_id != expected_id
        || entry.scenario_version != "phase011-v1"
        || entry.report_file != format!("{expected_id}-v1.json")
        || entry.driver_summary_file != format!("{expected_id}-driver-summary.json")
        || entry.terminal_summary_file != format!("{expected_id}-summary.txt")
        || !valid_digest(&entry.report_sha256)
        || !valid_digest(&entry.driver_summary_sha256)
        || !valid_digest(&entry.terminal_summary_sha256)
        || !valid_digest(&entry.config_sha256)
        || entry.expected_requests != contract.expected_requests
        || entry.succeeded_requests != contract.expected_requests
        || entry.failed_requests != 0
        || entry.workers != contract.workers
        || entry.rejected_negatives != contract.rejected_negatives
        || entry.forwarded_requests != contract.expected_requests
        || entry.observed_status_samples == 0
        || entry.max_active_connections == 0
        || entry.max_active_connections > CONNECTION_LIMIT
        || entry.max_charged_payload_bytes > PAYLOAD_BUDGET_BYTES
        || entry.cleanup_active_connections != 0
        || entry.cleanup_charged_payload_bytes != 0
        || entry.cleanup_pressure != "normal"
        || entry.recovery_status != 200
        || entry.peak_rss_bytes == 0
        || entry.peak_rss_bytes > STEADY_RSS_CEILING_BYTES
        || entry.rss_ceiling_bytes != STEADY_RSS_CEILING_BYTES
    {
        return Err(HarnessError::new("memory manifest entry is invalid"));
    }
    Ok(())
}

fn reject_unknown_or_non_regular_inputs(input_dir: &Path) -> Result<(), HarnessError> {
    let expected = STEADY_PROFILE_SCENARIOS
        .iter()
        .flat_map(|id| {
            [
                format!("{id}-v1.json"),
                format!("{id}-v1.sha256"),
                format!("{id}-driver-summary.json"),
                format!("{id}-summary.txt"),
            ]
        })
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(input_dir)
        .map_err(|_| HarnessError::new("memory manifest input directory cannot be read"))?
    {
        let entry = entry.map_err(|_| HarnessError::new("memory manifest input entry failed"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| HarnessError::new("memory manifest input name is not UTF-8"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| HarnessError::new("memory manifest input metadata failed"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || !expected.contains(&name) {
            return Err(HarnessError::new(
                "memory manifest input contains an unknown path",
            ));
        }
        if !actual.insert(name) {
            return Err(HarnessError::new(
                "memory manifest input contains a duplicate path",
            ));
        }
    }
    if actual != expected {
        return Err(HarnessError::new("memory manifest input set is incomplete"));
    }
    Ok(())
}

fn read_regular(path: &Path) -> Result<Vec<u8>, HarnessError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HarnessError::new("memory manifest input file is missing"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HarnessError::new(
            "memory manifest input is not a physical regular file",
        ));
    }
    fs::read(path).map_err(|_| HarnessError::new("memory manifest input cannot be read"))
}

fn parse_digest_file(bytes: &[u8]) -> Result<String, HarnessError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HarnessError::new("memory report digest is not UTF-8"))?;
    let digest = text
        .strip_suffix('\n')
        .ok_or_else(|| HarnessError::new("memory report digest is not canonical"))?;
    if digest.contains('\n') || !valid_digest(digest) {
        return Err(HarnessError::new("memory report digest is invalid"));
    }
    Ok(digest.to_string())
}

fn reject_sensitive_material(bytes: &[u8]) -> Result<(), HarnessError> {
    let lowered = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let forbidden = [
        "authorization:",
        "cookie:",
        "private_key",
        "client_key",
        "passphrase",
        "begin certificate",
        "begin private",
        "\"pid\"",
        "/tmp/",
    ];
    if forbidden.iter().any(|needle| lowered.contains(needle)) {
        return Err(HarnessError::new(
            "memory evidence contains forbidden material",
        ));
    }
    Ok(())
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DriverSummary {
    schema_version: u32,
    expected: u64,
    succeeded: u64,
    failed: u64,
    workers: u64,
    state: String,
}

impl DriverSummary {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("memory driver summary is invalid"))?;
        if value.schema_version != 1 {
            return Err(HarnessError::new("memory driver summary schema is invalid"));
        }
        let canonical = serde_json::to_string(&value)
            .map_err(|_| HarnessError::new("memory driver summary encoding failed"))?;
        if canonical.as_bytes() != bytes {
            return Err(HarnessError::new("memory driver summary is not canonical"));
        }
        Ok(value)
    }
}

struct ScenarioContract {
    id: &'static str,
    label: &'static str,
    expected_requests: u64,
    workers: u64,
    rejected_negatives: u64,
}

impl ScenarioContract {
    fn for_id(id: &str) -> Option<Self> {
        match id {
            "http-steady" => Some(Self {
                id: "http-steady",
                label: "HTTP steady",
                expected_requests: 100_000,
                workers: 100,
                rejected_negatives: 0,
            }),
            "https-steady" => Some(Self {
                id: "https-steady",
                label: "HTTPS steady",
                expected_requests: 50_000,
                workers: 100,
                rejected_negatives: 2,
            }),
            "mtls-steady" => Some(Self {
                id: "mtls-steady",
                label: "mTLS steady",
                expected_requests: 25_000,
                workers: 64,
                rejected_negatives: 2,
            }),
            _ => None,
        }
    }
}

struct TerminalSummary {
    rejected_negatives: u64,
    forwarded_requests: u64,
    samples: u64,
    max_active: u64,
    max_charge: u64,
    cleanup_active: u64,
    cleanup_charge: u64,
    cleanup_pressure: String,
    recovery: u16,
    peak_rss_bytes: u64,
}

impl TerminalSummary {
    fn parse(bytes: &[u8], contract: &ScenarioContract) -> Result<Self, HarnessError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| HarnessError::new("memory terminal summary is not UTF-8"))?;
        let line = text
            .strip_suffix('\n')
            .ok_or_else(|| HarnessError::new("memory terminal summary is not canonical"))?;
        if line.contains('\n') {
            return Err(HarnessError::new(
                "memory terminal summary has multiple lines",
            ));
        }
        let prefix = format!("{} passed ", contract.label);
        let fields = line
            .strip_prefix(&prefix)
            .ok_or_else(|| HarnessError::new("memory terminal summary label mismatch"))?;
        let mut values = BTreeMap::new();
        for field in fields.split(' ') {
            let (key, value) = field
                .split_once('=')
                .ok_or_else(|| HarnessError::new("memory terminal summary field is invalid"))?;
            if values.insert(key, value).is_some() {
                return Err(HarnessError::new(
                    "memory terminal summary field is duplicated",
                ));
            }
        }
        let required = if contract.rejected_negatives == 0 {
            [
                "expected",
                "succeeded",
                "failed",
                "workers",
                "samples",
                "max_active",
                "max_charge",
                "final",
                "recovery",
                "peak_rss_bytes",
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
        } else {
            [
                "expected",
                "succeeded",
                "failed",
                "workers",
                "rejected_negatives",
                "forwarded",
                "samples",
                "max_active",
                "max_charge",
                "final",
                "recovery",
                "peak_rss_bytes",
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
        };
        if values.keys().copied().collect::<BTreeSet<_>>() != required {
            return Err(HarnessError::new(
                "memory terminal summary field set mismatch",
            ));
        }
        let expected = number(&values, "expected")?;
        let succeeded = number(&values, "succeeded")?;
        let failed = number(&values, "failed")?;
        let workers = number(&values, "workers")?;
        let rejected_negatives = optional_number(&values, "rejected_negatives")?.unwrap_or(0);
        let forwarded_requests = optional_number(&values, "forwarded")?.unwrap_or(expected);
        let samples = number(&values, "samples")?;
        let max_active = number(&values, "max_active")?;
        let max_charge = number(&values, "max_charge")?;
        let recovery = number(&values, "recovery")?
            .try_into()
            .map_err(|_| HarnessError::new("memory recovery status is invalid"))?;
        let peak_rss_bytes = number(&values, "peak_rss_bytes")?;
        let final_value = values
            .get("final")
            .ok_or_else(|| HarnessError::new("memory terminal cleanup is missing"))?;
        let mut cleanup = final_value.split('/');
        let cleanup_active = cleanup
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| HarnessError::new("memory terminal active cleanup is invalid"))?;
        let cleanup_charge = cleanup
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| HarnessError::new("memory terminal charge cleanup is invalid"))?;
        let cleanup_pressure = cleanup
            .next()
            .ok_or_else(|| HarnessError::new("memory terminal pressure cleanup is invalid"))?
            .to_string();
        if cleanup.next().is_some()
            || expected != contract.expected_requests
            || succeeded != expected
            || failed != 0
            || workers != contract.workers
            || rejected_negatives != contract.rejected_negatives
            || forwarded_requests != expected
            || samples == 0
            || max_active == 0
            || max_active > CONNECTION_LIMIT
            || max_charge > PAYLOAD_BUDGET_BYTES
            || cleanup_active != 0
            || cleanup_charge != 0
            || cleanup_pressure != "normal"
            || recovery != 200
            || peak_rss_bytes == 0
            || peak_rss_bytes > STEADY_RSS_CEILING_BYTES
        {
            return Err(HarnessError::new("memory terminal summary values mismatch"));
        }
        Ok(Self {
            rejected_negatives,
            forwarded_requests,
            samples,
            max_active,
            max_charge,
            cleanup_active,
            cleanup_charge,
            cleanup_pressure,
            recovery,
            peak_rss_bytes,
        })
    }
}

fn number(values: &BTreeMap<&str, &str>, key: &str) -> Result<u64, HarnessError> {
    values
        .get(key)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| HarnessError::new("memory terminal summary number is invalid"))
}

fn optional_number(values: &BTreeMap<&str, &str>, key: &str) -> Result<Option<u64>, HarnessError> {
    values
        .get(key)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| HarnessError::new("memory terminal summary number is invalid"))
        })
        .transpose()
}
