use std::fs;
use std::path::{Path, PathBuf};

use crate::macos_leaks::{
    evaluate_macos_leaks, parse_leaks_summary, MacosLeaksEvent, MacosLeaksInput,
    MacosLeaksLifecycle, MacosLeaksReport,
};
use crate::report_io::{publish_canonical_bytes, publish_digest, sha256_hex};
use crate::HarnessError;

const MAX_RAW_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosLeaksCollectOptions {
    pub build_identity: String,
    pub architecture: String,
    pub original_binary_sha256: String,
    pub signed_binary_sha256: String,
    pub config_sha256: String,
    pub process_identity_sha256: String,
    pub tool_exit_code: i32,
    pub workload_expected: u64,
    pub workload_succeeded: u64,
    pub workload_failed: u64,
    pub cleanup_connections: u64,
    pub cleanup_payload_bytes: u64,
    pub cleanup_pressure: String,
    pub recovery_status: u16,
    pub raw: PathBuf,
    pub raw_digest: PathBuf,
    pub report: PathBuf,
    pub report_digest: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosLeaksValidateOptions {
    pub expected_build_identity: String,
    pub raw: PathBuf,
    pub raw_digest: PathBuf,
    pub report: PathBuf,
    pub report_digest: PathBuf,
}

pub fn collect_macos_leaks(options: MacosLeaksCollectOptions) -> Result<String, HarnessError> {
    if options.report == options.report_digest {
        return Err(HarnessError::new("macOS leaks outputs must differ"));
    }
    require_absent(&options.report)?;
    require_absent(&options.report_digest)?;
    let mut lifecycle = MacosLeaksLifecycle::new();
    let (raw, raw_sha256) = read_verified_raw(&options.raw, &options.raw_digest)?;
    lifecycle.transition(MacosLeaksEvent::InputsVerified)?;
    let raw_text = std::str::from_utf8(&raw)
        .map_err(|_| HarnessError::new("macOS leaks raw output is not UTF-8"))?;
    let summary = parse_leaks_summary(raw_text)?;
    lifecycle.transition(MacosLeaksEvent::Parsed)?;
    let report = evaluate_macos_leaks(MacosLeaksInput {
        build_identity: options.build_identity,
        architecture: options.architecture,
        original_binary_sha256: options.original_binary_sha256,
        signed_binary_sha256: options.signed_binary_sha256,
        config_sha256: options.config_sha256,
        process_identity_sha256: options.process_identity_sha256,
        raw_sha256,
        tool_exit_code: options.tool_exit_code,
        workload_expected: options.workload_expected,
        workload_succeeded: options.workload_succeeded,
        workload_failed: options.workload_failed,
        cleanup_connections: options.cleanup_connections,
        cleanup_payload_bytes: options.cleanup_payload_bytes,
        cleanup_pressure: options.cleanup_pressure,
        recovery_status: options.recovery_status,
        summary,
    })?;
    lifecycle.transition(MacosLeaksEvent::Validated)?;
    let encoded = report.to_canonical_json()?;
    let published = publish_canonical_bytes(&options.report, encoded.as_bytes())?;
    publish_digest(&options.report_digest, &published.sha256)?;
    lifecycle.transition(MacosLeaksEvent::Published)?;
    Ok(format!(
        "macOS leaks collected leaks=0 bytes=0 digest={}",
        published.sha256
    ))
}

pub fn validate_macos_leaks(options: MacosLeaksValidateOptions) -> Result<String, HarnessError> {
    let (raw, raw_sha256) = read_verified_raw(&options.raw, &options.raw_digest)?;
    let (report_bytes, report_sha256) =
        read_verified_regular(&options.report, &options.report_digest)?;
    let report = MacosLeaksReport::from_canonical_json(&report_bytes)?;
    if report.build_identity != options.expected_build_identity || report.raw_sha256 != raw_sha256 {
        return Err(HarnessError::new("macOS leaks evidence identity mismatch"));
    }
    let raw_text = std::str::from_utf8(&raw)
        .map_err(|_| HarnessError::new("macOS leaks raw output is not UTF-8"))?;
    let expected = evaluate_macos_leaks(MacosLeaksInput {
        build_identity: report.build_identity.clone(),
        architecture: report.architecture.clone(),
        original_binary_sha256: report.original_binary_sha256.clone(),
        signed_binary_sha256: report.signed_binary_sha256.clone(),
        config_sha256: report.config_sha256.clone(),
        process_identity_sha256: report.process_identity_sha256.clone(),
        raw_sha256,
        tool_exit_code: report.tool_exit_code,
        workload_expected: report.workload_expected,
        workload_succeeded: report.workload_succeeded,
        workload_failed: report.workload_failed,
        cleanup_connections: report.cleanup_connections,
        cleanup_payload_bytes: report.cleanup_payload_bytes,
        cleanup_pressure: report.cleanup_pressure.clone(),
        recovery_status: report.recovery_status,
        summary: parse_leaks_summary(raw_text)?,
    })?;
    if expected != report {
        return Err(HarnessError::new(
            "macOS leaks report does not match raw evidence",
        ));
    }
    Ok(format!(
        "macOS leaks validated leaks=0 bytes=0 digest={report_sha256}"
    ))
}

fn read_verified_raw(report: &Path, digest: &Path) -> Result<(Vec<u8>, String), HarnessError> {
    let metadata = physical_metadata(report)?;
    if metadata.len() == 0 || metadata.len() > MAX_RAW_BYTES {
        return Err(HarnessError::new("macOS leaks raw size is invalid"));
    }
    require_owner_only(&metadata)?;
    read_verified_with_metadata(report, digest)
}

fn read_verified_regular(report: &Path, digest: &Path) -> Result<(Vec<u8>, String), HarnessError> {
    physical_metadata(report)?;
    read_verified_with_metadata(report, digest)
}

fn read_verified_with_metadata(
    report: &Path,
    digest: &Path,
) -> Result<(Vec<u8>, String), HarnessError> {
    physical_metadata(digest)?;
    let bytes = fs::read(report).map_err(|_| HarnessError::new("macOS leaks file read failed"))?;
    let expected = parse_digest(
        &fs::read(digest).map_err(|_| HarnessError::new("macOS leaks digest read failed"))?,
    )?;
    if sha256_hex(&bytes) != expected {
        return Err(HarnessError::new("macOS leaks digest mismatch"));
    }
    Ok((bytes, expected))
}

fn physical_metadata(path: &Path) -> Result<fs::Metadata, HarnessError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HarnessError::new("macOS leaks file is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HarnessError::new(
            "macOS leaks file must be physical and regular",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(HarnessError::new(
                "macOS leaks file must have one hard link",
            ));
        }
    }
    Ok(metadata)
}

fn require_owner_only(metadata: &fs::Metadata) -> Result<(), HarnessError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(HarnessError::new("macOS leaks raw file must be owner-only"));
        }
    }
    Ok(())
}

fn parse_digest(bytes: &[u8]) -> Result<String, HarnessError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| HarnessError::new("macOS leaks digest is not UTF-8"))?
        .strip_suffix('\n')
        .filter(|value| {
            value.len() == 64
                && !value.contains('\n')
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| HarnessError::new("macOS leaks digest is not canonical"))?;
    Ok(value.to_string())
}

fn require_absent(path: &Path) -> Result<(), HarnessError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(HarnessError::new("macOS leaks output already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(HarnessError::new("macOS leaks output cannot be inspected")),
    }
}
