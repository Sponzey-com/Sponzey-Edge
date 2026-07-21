use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::memory_manifest::{
    validate_manifest, ManifestInputs, MemoryEvidenceManifest, MemoryManifestStatus,
    STEADY_PROFILE_ID, STEADY_PROFILE_SCENARIOS, STEADY_RSS_CEILING_BYTES,
};
use crate::report::MemoryEvidenceReport;
use crate::report_io::sha256_hex;
use crate::HarnessError;

pub const MEMORY_AGGREGATE_SCHEMA_VERSION: u32 = 1;
pub const THREE_RUN_PROFILE_ID: &str = "phase011-steady-3run-v1";
pub const THREE_RUN_REPETITIONS: u32 = 3;
pub const REPEATABILITY_FLOOR_BYTES: u64 = 16 * 1024 * 1024;

const CHILD_MANIFEST_FILE: &str = "phase011-steady-manifest-v1.json";
const CHILD_MANIFEST_DIGEST_FILE: &str = "phase011-steady-manifest-v1.sha256";

const APPROVAL_BLOCKERS: [&str; 3] = [
    "linux-x86_64-profile",
    "full-scenario-profile",
    "long-soak-and-deep-diagnostic",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAggregateStatus {
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateInputs {
    pub input_root: PathBuf,
    pub build_identity: String,
    pub platform: String,
    pub architecture: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateRunEvidence {
    pub run_index: u32,
    pub manifest_sha256: String,
    pub process_identity_sha256: String,
    pub cooldown_rss_by_scenario: BTreeMap<String, u64>,
    pub manifest: MemoryEvidenceManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryAggregateRun {
    pub run_index: u32,
    pub manifest_sha256: String,
    pub process_identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryAggregateScenario {
    pub scenario_id: String,
    pub run_count: u32,
    pub min_peak_rss_bytes: u64,
    pub max_peak_rss_bytes: u64,
    pub min_cooldown_rss_bytes: u64,
    pub max_cooldown_rss_bytes: u64,
    pub repeatability_tolerance_bytes: u64,
    pub repeatability_passed: bool,
    pub correctness_failures: u32,
    pub cleanup_failures: u32,
    pub rss_ceiling_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryEvidenceAggregate {
    pub schema_version: u32,
    pub profile_id: String,
    pub collector_version: String,
    pub source_profile_id: String,
    pub build_identity: String,
    pub platform: String,
    pub architecture: String,
    pub repetitions: u32,
    pub status: MemoryAggregateStatus,
    pub approval_blockers: Vec<String>,
    pub runs: Vec<MemoryAggregateRun>,
    pub scenarios: Vec<MemoryAggregateScenario>,
}

impl MemoryEvidenceAggregate {
    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.schema_version != MEMORY_AGGREGATE_SCHEMA_VERSION
            || self.profile_id != THREE_RUN_PROFILE_ID
            || self.collector_version != "edge-memory-aggregate-v1"
            || self.source_profile_id != STEADY_PROFILE_ID
            || !valid_build_identity(&self.build_identity)
            || self.platform.is_empty()
            || self.architecture.is_empty()
            || self.repetitions != THREE_RUN_REPETITIONS
            || self.status != MemoryAggregateStatus::Partial
            || self.approval_blockers != blockers()
        {
            return Err(HarnessError::new("memory aggregate header is invalid"));
        }
        if self.runs.len() != THREE_RUN_REPETITIONS as usize
            || self.scenarios.len() != STEADY_PROFILE_SCENARIOS.len()
        {
            return Err(HarnessError::new("memory aggregate cardinality is invalid"));
        }
        let mut fingerprints = BTreeSet::new();
        for (position, run) in self.runs.iter().enumerate() {
            if run.run_index != position as u32 + 1
                || !valid_digest(&run.manifest_sha256)
                || !valid_digest(&run.process_identity_sha256)
                || !fingerprints.insert(run.process_identity_sha256.as_str())
            {
                return Err(HarnessError::new("memory aggregate run is invalid"));
            }
        }
        for (scenario, expected_id) in self.scenarios.iter().zip(STEADY_PROFILE_SCENARIOS) {
            let tolerance = repeatability_tolerance(scenario.min_peak_rss_bytes)?;
            if scenario.scenario_id != expected_id
                || scenario.run_count != THREE_RUN_REPETITIONS
                || scenario.min_peak_rss_bytes == 0
                || scenario.max_peak_rss_bytes < scenario.min_peak_rss_bytes
                || scenario.max_peak_rss_bytes > STEADY_RSS_CEILING_BYTES
                || scenario.min_cooldown_rss_bytes == 0
                || scenario.max_cooldown_rss_bytes < scenario.min_cooldown_rss_bytes
                || scenario.repeatability_tolerance_bytes != tolerance
                || !scenario.repeatability_passed
                || scenario.correctness_failures != 0
                || scenario.cleanup_failures != 0
                || scenario.rss_ceiling_bytes != STEADY_RSS_CEILING_BYTES
                || !within_tolerance(
                    scenario.min_peak_rss_bytes,
                    scenario.max_peak_rss_bytes,
                    tolerance,
                )?
                || !within_tolerance(
                    scenario.min_cooldown_rss_bytes,
                    scenario.max_cooldown_rss_bytes,
                    tolerance,
                )?
            {
                return Err(HarnessError::new("memory aggregate scenario is invalid"));
            }
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, HarnessError> {
        self.validate()?;
        let mut encoded = serde_json::to_string_pretty(self)
            .map_err(|_| HarnessError::new("memory aggregate encoding failed"))?;
        encoded.push('\n');
        Ok(encoded)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        let aggregate: Self = serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("memory aggregate decoding failed"))?;
        aggregate.validate()?;
        if aggregate.to_canonical_json()?.as_bytes() != bytes {
            return Err(HarnessError::new("memory aggregate is not canonical"));
        }
        Ok(aggregate)
    }
}

pub fn collect_aggregate(
    inputs: &AggregateInputs,
) -> Result<MemoryEvidenceAggregate, HarnessError> {
    validate_inputs(inputs)?;
    reject_directory_entries(
        &inputs.input_root,
        &(1..=THREE_RUN_REPETITIONS)
            .map(run_directory_name)
            .collect::<BTreeSet<_>>(),
        true,
    )?;

    let mut runs = Vec::with_capacity(THREE_RUN_REPETITIONS as usize);
    for run_index in 1..=THREE_RUN_REPETITIONS {
        runs.push(collect_run(inputs, run_index)?);
    }
    build_aggregate(runs)
}

pub fn validate_aggregate(
    inputs: &AggregateInputs,
    bytes: &[u8],
    expected_digest: &str,
) -> Result<MemoryEvidenceAggregate, HarnessError> {
    if !valid_digest(expected_digest) || sha256_hex(bytes) != expected_digest {
        return Err(HarnessError::new("memory aggregate digest mismatch"));
    }
    let supplied = MemoryEvidenceAggregate::from_canonical_json(bytes)?;
    let collected = collect_aggregate(inputs)?;
    if supplied != collected {
        return Err(HarnessError::new(
            "memory aggregate does not match source evidence",
        ));
    }
    Ok(supplied)
}

pub fn inspect_aggregate(
    bytes: &[u8],
    expected_digest: &str,
    expected_build_identity: &str,
) -> Result<MemoryEvidenceAggregate, HarnessError> {
    if !valid_digest(expected_digest) || sha256_hex(bytes) != expected_digest {
        return Err(HarnessError::new("memory aggregate digest mismatch"));
    }
    let aggregate = MemoryEvidenceAggregate::from_canonical_json(bytes)?;
    if aggregate.build_identity != expected_build_identity {
        return Err(HarnessError::new(
            "memory aggregate source identity mismatch",
        ));
    }
    Ok(aggregate)
}

fn collect_run(
    inputs: &AggregateInputs,
    run_index: u32,
) -> Result<AggregateRunEvidence, HarnessError> {
    let run_dir = inputs.input_root.join(run_directory_name(run_index));
    reject_physical_directory(&run_dir, "memory aggregate run directory is unavailable")?;
    reject_directory_entries(
        &run_dir,
        &["manifest".to_string(), "profile".to_string()]
            .into_iter()
            .collect(),
        true,
    )?;
    let profile_dir = run_dir.join("profile");
    let manifest_dir = run_dir.join("manifest");
    reject_physical_directory(
        &profile_dir,
        "memory aggregate profile directory is unavailable",
    )?;
    reject_physical_directory(
        &manifest_dir,
        "memory aggregate manifest directory is unavailable",
    )?;
    reject_directory_entries(
        &manifest_dir,
        &[
            CHILD_MANIFEST_FILE.to_string(),
            CHILD_MANIFEST_DIGEST_FILE.to_string(),
        ]
        .into_iter()
        .collect(),
        false,
    )?;

    let manifest_bytes = read_regular(&manifest_dir.join(CHILD_MANIFEST_FILE))?;
    let digest_bytes = read_regular(&manifest_dir.join(CHILD_MANIFEST_DIGEST_FILE))?;
    let manifest_digest = parse_digest_file(&digest_bytes)?;
    let manifest = validate_manifest(
        &ManifestInputs {
            input_dir: profile_dir.clone(),
            build_identity: inputs.build_identity.clone(),
            platform: inputs.platform.clone(),
            architecture: inputs.architecture.clone(),
            repetitions: 1,
            status: MemoryManifestStatus::Partial,
        },
        &manifest_bytes,
        &manifest_digest,
    )?;

    let mut identities = BTreeSet::new();
    let mut identity_material = Vec::new();
    let mut cooldown_rss_by_scenario = BTreeMap::new();
    for scenario_id in STEADY_PROFILE_SCENARIOS {
        let report = MemoryEvidenceReport::from_canonical_json(&read_regular(
            &profile_dir.join(format!("{scenario_id}-v1.json")),
        )?)
        .map_err(|_| HarnessError::new("memory aggregate source report is invalid"))?;
        if report.identity.scenario_id != scenario_id
            || report.identity.build_identity != inputs.build_identity
            || !identities.insert(report.identity.process_start_identity.clone())
        {
            return Err(HarnessError::new(
                "memory aggregate process identity is invalid",
            ));
        }
        identity_material.extend_from_slice(scenario_id.as_bytes());
        identity_material.push(0);
        identity_material.extend_from_slice(report.identity.process_start_identity.as_bytes());
        identity_material.push(0);
        cooldown_rss_by_scenario.insert(scenario_id.to_string(), report.cooldown_rss_bytes);
    }

    Ok(AggregateRunEvidence {
        run_index,
        manifest_sha256: manifest_digest,
        process_identity_sha256: sha256_hex(&identity_material),
        cooldown_rss_by_scenario,
        manifest,
    })
}

fn validate_inputs(inputs: &AggregateInputs) -> Result<(), HarnessError> {
    if !valid_build_identity(&inputs.build_identity)
        || inputs.platform.is_empty()
        || inputs.architecture.is_empty()
    {
        return Err(HarnessError::new("memory aggregate inputs are invalid"));
    }
    reject_physical_directory(
        &inputs.input_root,
        "memory aggregate input root is unavailable",
    )
}

fn run_directory_name(run_index: u32) -> String {
    format!("run-{run_index:03}")
}

fn reject_physical_directory(path: &Path, message: &'static str) -> Result<(), HarnessError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| HarnessError::new(message))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HarnessError::new(message));
    }
    Ok(())
}

fn reject_directory_entries(
    directory: &Path,
    expected: &BTreeSet<String>,
    expect_directories: bool,
) -> Result<(), HarnessError> {
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(directory)
        .map_err(|_| HarnessError::new("memory aggregate directory cannot be read"))?
    {
        let entry = entry.map_err(|_| HarnessError::new("memory aggregate entry failed"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| HarnessError::new("memory aggregate path is not UTF-8"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| HarnessError::new("memory aggregate metadata failed"))?;
        let valid_type = if expect_directories {
            metadata.is_dir()
        } else {
            metadata.is_file()
        };
        if metadata.file_type().is_symlink() || !valid_type || !expected.contains(&name) {
            return Err(HarnessError::new(
                "memory aggregate contains an unknown path",
            ));
        }
        if !actual.insert(name) {
            return Err(HarnessError::new(
                "memory aggregate contains a duplicate path",
            ));
        }
    }
    if &actual != expected {
        return Err(HarnessError::new(
            "memory aggregate input set is incomplete",
        ));
    }
    Ok(())
}

fn read_regular(path: &Path) -> Result<Vec<u8>, HarnessError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HarnessError::new("memory aggregate input file is missing"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HarnessError::new(
            "memory aggregate input is not a physical regular file",
        ));
    }
    fs::read(path).map_err(|_| HarnessError::new("memory aggregate input cannot be read"))
}

fn parse_digest_file(bytes: &[u8]) -> Result<String, HarnessError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HarnessError::new("memory aggregate digest is not UTF-8"))?;
    let digest = text
        .strip_suffix('\n')
        .filter(|value| !value.contains('\n'))
        .ok_or_else(|| HarnessError::new("memory aggregate digest is not canonical"))?;
    if !valid_digest(digest) {
        return Err(HarnessError::new("memory aggregate digest is invalid"));
    }
    Ok(digest.to_string())
}

pub fn build_aggregate(
    mut runs: Vec<AggregateRunEvidence>,
) -> Result<MemoryEvidenceAggregate, HarnessError> {
    if runs.len() != THREE_RUN_REPETITIONS as usize {
        return Err(HarnessError::new(
            "memory aggregate requires exactly three runs",
        ));
    }
    runs.sort_by_key(|run| run.run_index);
    let first = runs
        .first()
        .ok_or_else(|| HarnessError::new("memory aggregate has no runs"))?;
    let build_identity = first.manifest.build_identity.clone();
    let platform = first.manifest.platform.clone();
    let architecture = first.manifest.architecture.clone();
    let mut process_fingerprints = BTreeSet::new();
    let mut run_records = Vec::with_capacity(runs.len());

    for (position, run) in runs.iter().enumerate() {
        run.manifest.validate()?;
        let canonical = run.manifest.to_canonical_json()?;
        if run.run_index != position as u32 + 1
            || run.manifest.status != MemoryManifestStatus::Partial
            || run.manifest.build_identity != build_identity
            || run.manifest.platform != platform
            || run.manifest.architecture != architecture
            || sha256_hex(canonical.as_bytes()) != run.manifest_sha256
            || !valid_digest(&run.process_identity_sha256)
            || !process_fingerprints.insert(run.process_identity_sha256.as_str())
            || run.cooldown_rss_by_scenario.len() != STEADY_PROFILE_SCENARIOS.len()
        {
            return Err(HarnessError::new(
                "memory aggregate run evidence is invalid",
            ));
        }
        run_records.push(MemoryAggregateRun {
            run_index: run.run_index,
            manifest_sha256: run.manifest_sha256.clone(),
            process_identity_sha256: run.process_identity_sha256.clone(),
        });
    }

    let scenarios = STEADY_PROFILE_SCENARIOS
        .iter()
        .map(|scenario_id| {
            let mut peaks = Vec::with_capacity(runs.len());
            let mut cooldowns = Vec::with_capacity(runs.len());
            for run in &runs {
                let entry = run
                    .manifest
                    .entries
                    .iter()
                    .find(|entry| entry.scenario_id == *scenario_id)
                    .ok_or_else(|| HarnessError::new("memory aggregate scenario is missing"))?;
                peaks.push(entry.peak_rss_bytes);
                cooldowns.push(*run.cooldown_rss_by_scenario.get(*scenario_id).ok_or_else(
                    || HarnessError::new("memory aggregate cooldown value is missing"),
                )?);
            }
            let min_peak = *peaks.iter().min().expect("three runs have a minimum");
            let max_peak = *peaks.iter().max().expect("three runs have a maximum");
            let min_cooldown = *cooldowns.iter().min().expect("three runs have a minimum");
            let max_cooldown = *cooldowns.iter().max().expect("three runs have a maximum");
            let tolerance = repeatability_tolerance(min_peak)?;
            if !within_tolerance(min_peak, max_peak, tolerance)?
                || !within_tolerance(min_cooldown, max_cooldown, tolerance)?
            {
                return Err(HarnessError::new(
                    "memory aggregate repeatability threshold exceeded",
                ));
            }
            Ok(MemoryAggregateScenario {
                scenario_id: (*scenario_id).to_string(),
                run_count: THREE_RUN_REPETITIONS,
                min_peak_rss_bytes: min_peak,
                max_peak_rss_bytes: max_peak,
                min_cooldown_rss_bytes: min_cooldown,
                max_cooldown_rss_bytes: max_cooldown,
                repeatability_tolerance_bytes: tolerance,
                repeatability_passed: true,
                correctness_failures: 0,
                cleanup_failures: 0,
                rss_ceiling_bytes: STEADY_RSS_CEILING_BYTES,
            })
        })
        .collect::<Result<Vec<_>, HarnessError>>()?;

    let aggregate = MemoryEvidenceAggregate {
        schema_version: MEMORY_AGGREGATE_SCHEMA_VERSION,
        profile_id: THREE_RUN_PROFILE_ID.to_string(),
        collector_version: "edge-memory-aggregate-v1".to_string(),
        source_profile_id: STEADY_PROFILE_ID.to_string(),
        build_identity,
        platform,
        architecture,
        repetitions: THREE_RUN_REPETITIONS,
        status: MemoryAggregateStatus::Partial,
        approval_blockers: blockers(),
        runs: run_records,
        scenarios,
    };
    aggregate.validate()?;
    Ok(aggregate)
}

fn blockers() -> Vec<String> {
    APPROVAL_BLOCKERS
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

fn repeatability_tolerance(baseline: u64) -> Result<u64, HarnessError> {
    if baseline == 0 {
        return Err(HarnessError::new(
            "memory aggregate repeatability baseline is invalid",
        ));
    }
    Ok(REPEATABILITY_FLOOR_BYTES.max(baseline / 10))
}

fn within_tolerance(minimum: u64, maximum: u64, tolerance: u64) -> Result<bool, HarnessError> {
    let limit = minimum
        .checked_add(tolerance)
        .ok_or_else(|| HarnessError::new("memory aggregate repeatability arithmetic overflow"))?;
    Ok(maximum <= limit)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_build_identity(value: &str) -> bool {
    value
        .strip_prefix("source-tree-sha256:")
        .is_some_and(valid_digest)
}
