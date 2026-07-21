use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::report::{MemoryEvidenceReport, ReportValidationError};
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedReport {
    pub bytes: u64,
    pub sha256: String,
}

pub struct AtomicReportWriter;

impl AtomicReportWriter {
    pub fn publish(
        path: &Path,
        report: &MemoryEvidenceReport,
    ) -> Result<PublishedReport, HarnessError> {
        let encoded = report
            .to_canonical_json()
            .map_err(|_| HarnessError::new("memory report validation failed before publish"))?;
        publish_canonical_bytes(path, encoded.as_bytes())
    }
}

pub fn publish_canonical_bytes(
    path: &Path,
    encoded: &[u8],
) -> Result<PublishedReport, HarnessError> {
    if encoded.is_empty() {
        return Err(HarnessError::new("canonical report bytes are empty"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| HarnessError::new("memory report path has no parent"))?;
    fs::create_dir_all(parent)
        .map_err(|_| HarnessError::new("memory report directory creation failed"))?;
    let temporary = temporary_path(path);
    let result = publish_bytes(&temporary, path, encoded);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(PublishedReport {
        bytes: encoded
            .len()
            .try_into()
            .map_err(|_| HarnessError::new("memory report byte length exceeds u64"))?,
        sha256: sha256_hex(encoded),
    })
}

pub fn publish_digest(path: &Path, digest: &str) -> Result<(), HarnessError> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HarnessError::new("memory report digest is invalid"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| HarnessError::new("memory digest path has no parent"))?;
    fs::create_dir_all(parent)
        .map_err(|_| HarnessError::new("memory digest directory creation failed"))?;
    let temporary = temporary_path(path);
    let contents = format!("{digest}\n");
    let result = publish_bytes(&temporary, path, contents.as_bytes());
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    static NEXT_TEMPORARY_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_TEMPORARY_ID.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("memory-report");
    path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), id))
}

fn publish_bytes(temporary: &Path, target: &Path, bytes: &[u8]) -> Result<(), HarnessError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(temporary)
        .map_err(|_| HarnessError::new("memory report temporary file creation failed"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| HarnessError::new("memory report temporary file persistence failed"))?;
    fs::rename(temporary, target)
        .map_err(|_| HarnessError::new("memory report atomic publish failed"))?;
    if let Some(parent) = target.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| HarnessError::new("memory report directory sync failed"))?;
    }
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportExpectations {
    pub scenario_id: String,
    pub scenario_version: String,
    pub build_identity: String,
    pub config_sha256: String,
}

pub struct ReportValidator {
    expected: ReportExpectations,
}

impl ReportValidator {
    pub fn new(expected: ReportExpectations) -> Self {
        Self { expected }
    }

    pub fn validate(
        &self,
        bytes: &[u8],
        expected_sha256: &str,
    ) -> Result<MemoryEvidenceReport, ReportValidationError> {
        if expected_sha256.len() != 64 || sha256_hex(bytes) != expected_sha256 {
            return Err(ReportValidationError::DigestMismatch);
        }
        let report = MemoryEvidenceReport::from_canonical_json(bytes)?;
        if report.identity.scenario_id != self.expected.scenario_id
            || report.identity.scenario_version != self.expected.scenario_version
            || report.identity.build_identity != self.expected.build_identity
            || report.identity.config_sha256 != self.expected.config_sha256
        {
            return Err(ReportValidationError::IdentityMismatch);
        }
        Ok(report)
    }
}
