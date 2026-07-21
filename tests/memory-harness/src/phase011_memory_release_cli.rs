use std::fs;
use std::path::{Path, PathBuf};

use crate::diagnostic_soak::DiagnosticSoakReport;
use crate::full_profile_readiness::{FullProfileInput, FullProfileReadinessReport};
use crate::phase011_memory_release::{
    evaluate_phase011_memory_release, MemoryReleaseEvent, MemoryReleaseInput,
    MemoryReleaseLifecycle, Phase011MemoryReleaseReport,
};
use crate::report_io::{publish_canonical_bytes, publish_digest, sha256_hex};
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryReleaseCollectOptions {
    pub expected_build_identity: String,
    pub expected_platform: String,
    pub expected_architecture: String,
    pub inventory: PathBuf,
    pub inventory_digest: PathBuf,
    pub readiness: PathBuf,
    pub readiness_digest: PathBuf,
    pub soak: PathBuf,
    pub soak_digest: PathBuf,
    pub output: PathBuf,
    pub output_digest: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryReleaseValidateOptions {
    pub expected_build_identity: String,
    pub report: PathBuf,
    pub digest: PathBuf,
}

pub fn collect_phase011_memory_release(
    options: MemoryReleaseCollectOptions,
) -> Result<String, HarnessError> {
    if options.output == options.output_digest {
        return Err(HarnessError::new("memory release outputs must differ"));
    }
    require_absent(&options.output)?;
    require_absent(&options.output_digest)?;
    let mut lifecycle = MemoryReleaseLifecycle::new();
    let (inventory_bytes, inventory_sha256) =
        read_verified(&options.inventory, &options.inventory_digest)?;
    let (readiness_bytes, readiness_sha256) =
        read_verified(&options.readiness, &options.readiness_digest)?;
    let (soak_bytes, soak_sha256) = read_verified(&options.soak, &options.soak_digest)?;
    reject_forbidden(&[&inventory_bytes, &readiness_bytes, &soak_bytes])?;
    lifecycle.transition(MemoryReleaseEvent::InputsVerified)?;

    let inventory = canonical_inventory(&inventory_bytes)?;
    let readiness = FullProfileReadinessReport::from_canonical_json(&readiness_bytes)?;
    let soak = DiagnosticSoakReport::from_canonical_json(&soak_bytes)?;
    lifecycle.transition(MemoryReleaseEvent::ReportsValidated)?;
    let report = evaluate_phase011_memory_release(MemoryReleaseInput {
        expected_build_identity: options.expected_build_identity,
        expected_platform: options.expected_platform,
        expected_architecture: options.expected_architecture,
        inventory,
        inventory_sha256,
        readiness,
        readiness_sha256,
        soak,
        soak_sha256,
    })?;
    lifecycle.transition(MemoryReleaseEvent::Bound)?;
    let encoded = report.to_canonical_json()?;
    let published = publish_canonical_bytes(&options.output, encoded.as_bytes())?;
    publish_digest(&options.output_digest, &published.sha256)?;
    lifecycle.transition(MemoryReleaseEvent::Published)?;
    Ok(format!(
        "Phase 011 memory release collected scenarios={} soak_observations={} digest={}",
        report.full_profile_scenarios, report.soak_observations, published.sha256
    ))
}

pub fn validate_phase011_memory_release(
    options: MemoryReleaseValidateOptions,
) -> Result<String, HarnessError> {
    let (report_bytes, digest) = read_verified(&options.report, &options.digest)?;
    reject_forbidden(&[&report_bytes])?;
    let report = Phase011MemoryReleaseReport::from_canonical_json(&report_bytes)?;
    if report.build_identity != options.expected_build_identity {
        return Err(HarnessError::new(
            "Phase 011 memory release source identity mismatch",
        ));
    }
    Ok(format!(
        "{} scenarios={} soak_observations={} digest={}",
        report.marker, report.full_profile_scenarios, report.soak_observations, digest
    ))
}

fn canonical_inventory(bytes: &[u8]) -> Result<FullProfileInput, HarnessError> {
    let inventory = FullProfileInput::from_json(bytes)?;
    let mut canonical = serde_json::to_string_pretty(&inventory)
        .map_err(|_| HarnessError::new("memory release inventory encoding failed"))?;
    canonical.push('\n');
    if canonical.as_bytes() != bytes {
        return Err(HarnessError::new(
            "memory release inventory is not canonical",
        ));
    }
    Ok(inventory)
}

fn read_verified(report: &Path, digest: &Path) -> Result<(Vec<u8>, String), HarnessError> {
    let report_bytes = read_regular(report)?;
    let digest = parse_digest(&read_regular(digest)?)?;
    if sha256_hex(&report_bytes) != digest {
        return Err(HarnessError::new("memory release input digest mismatch"));
    }
    Ok((report_bytes, digest))
}

fn read_regular(path: &Path) -> Result<Vec<u8>, HarnessError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HarnessError::new("memory release input is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HarnessError::new(
            "memory release input must be physical and regular",
        ));
    }
    fs::read(path).map_err(|_| HarnessError::new("memory release input cannot be read"))
}

fn parse_digest(bytes: &[u8]) -> Result<String, HarnessError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| HarnessError::new("memory release digest is not UTF-8"))?
        .strip_suffix('\n')
        .filter(|value| {
            value.len() == 64
                && !value.contains('\n')
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| HarnessError::new("memory release digest is not canonical"))?;
    Ok(value.to_string())
}

fn reject_forbidden(inputs: &[&[u8]]) -> Result<(), HarnessError> {
    const FORBIDDEN: [&str; 7] = [
        "authorization",
        "cookie",
        "private_key",
        "passphrase",
        "secret",
        "\"pid\"",
        "/tmp/",
    ];
    for input in inputs {
        let text = std::str::from_utf8(input)
            .map_err(|_| HarnessError::new("memory release input is not UTF-8"))?
            .to_ascii_lowercase();
        if FORBIDDEN.iter().any(|token| text.contains(token)) {
            return Err(HarnessError::new(
                "memory release input contains a forbidden field",
            ));
        }
    }
    Ok(())
}

fn require_absent(path: &Path) -> Result<(), HarnessError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(HarnessError::new("memory release output already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(HarnessError::new(
            "memory release output cannot be inspected",
        )),
    }
}
