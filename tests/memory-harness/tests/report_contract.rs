use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use edge_memory_harness::orchestrator::{ScenarioOutcome, ScenarioRunRecord};
use edge_memory_harness::report::{EvidenceIdentity, MemoryEvidenceReport, ReportValidationError};
use edge_memory_harness::report_io::{AtomicReportWriter, ReportExpectations, ReportValidator};
use edge_memory_harness::scenario::ScenarioState;
use edge_memory_harness::MemorySample;

fn identity() -> EvidenceIdentity {
    EvidenceIdentity {
        scenario_id: "idle".to_string(),
        scenario_version: "phase011-v1".to_string(),
        platform: "macos".to_string(),
        architecture: "arm64".to_string(),
        build_identity: format!("source-tree-sha256:{}", "a".repeat(64)),
        config_sha256: "d".repeat(64),
        process_start_identity: "macos-lstart:now".to_string(),
    }
}

fn report() -> MemoryEvidenceReport {
    MemoryEvidenceReport::new(
        identity(),
        3,
        ScenarioRunRecord {
            state: ScenarioState::Passed,
            outcome: ScenarioOutcome::Passed,
            samples: vec![
                MemorySample {
                    elapsed_ms: 0,
                    rss_bytes: 10,
                },
                MemorySample {
                    elapsed_ms: 1_000,
                    rss_bytes: 15,
                },
                MemorySample {
                    elapsed_ms: 2_000,
                    rss_bytes: 12,
                },
            ],
            missing_samples: 0,
        },
    )
    .unwrap()
}

fn expectations() -> ReportExpectations {
    ReportExpectations {
        scenario_id: "idle".to_string(),
        scenario_version: "phase011-v1".to_string(),
        build_identity: format!("source-tree-sha256:{}", "a".repeat(64)),
        config_sha256: "d".repeat(64),
    }
}

#[test]
fn schema_v2_roundtrip_is_canonical_and_rejects_unknown_or_invalid_samples() {
    let report = report();
    let encoded = report.to_canonical_json().unwrap();
    assert!(encoded.ends_with('\n'));
    assert_eq!(report.baseline_rss_bytes, 10);
    assert_eq!(report.peak_rss_bytes, 15);
    assert_eq!(report.cooldown_rss_bytes, 12);
    assert!(!encoded.contains("\"pid\""));
    assert!(!encoded.contains("config_file"));
    assert!(!encoded.contains("private_key"));

    let decoded = MemoryEvidenceReport::from_canonical_json(encoded.as_bytes()).unwrap();
    assert_eq!(decoded, report);
    let unknown = encoded.replacen("{", "{\n  \"unexpected\": true,", 1);
    assert_eq!(
        MemoryEvidenceReport::from_canonical_json(unknown.as_bytes()),
        Err(ReportValidationError::InvalidSchema)
    );

    let mut zero = report.clone();
    zero.samples[1].rss_bytes = 0;
    assert_eq!(zero.validate(), Err(ReportValidationError::InvalidSamples));
    let mut reordered = report.clone();
    reordered.samples.swap(0, 1);
    assert_eq!(
        reordered.validate(),
        Err(ReportValidationError::InvalidSamples)
    );
    let mut invalid_identity = report.clone();
    invalid_identity.identity.config_sha256 = "not-a-digest".to_string();
    assert_eq!(
        invalid_identity.validate(),
        Err(ReportValidationError::InvalidIdentity)
    );
}

#[test]
fn atomic_writer_publishes_canonical_bytes_and_digest_without_temp_file() {
    let root = temp_root("report-publish");
    let path = root.join("memory-report.json");
    let published = AtomicReportWriter::publish(&path, &report()).unwrap();
    let encoded = std::fs::read(&path).unwrap();

    assert_eq!(published.bytes, encoded.len() as u64);
    assert_eq!(published.sha256.len(), 64);
    assert_eq!(
        published.sha256,
        edge_memory_harness::report_io::sha256_hex(&encoded)
    );
    assert!(!path.with_extension("tmp").exists());
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn atomic_writer_failure_does_not_publish_target_or_partial_success() {
    let root = temp_root("report-failure");
    std::fs::write(&root, b"not-a-directory").unwrap();
    let target = root.join("memory-report.json");

    assert!(AtomicReportWriter::publish(&target, &report()).is_err());
    assert!(!target.exists());
    std::fs::remove_file(root).ok();
}

#[test]
fn independent_validator_rejects_tamper_digest_and_stale_identity() {
    let encoded = report().to_canonical_json().unwrap().into_bytes();
    let digest = edge_memory_harness::report_io::sha256_hex(&encoded);
    let validator = ReportValidator::new(expectations());
    assert_eq!(validator.validate(&encoded, &digest).unwrap(), report());

    let mut tampered = encoded.clone();
    let last = tampered.len() - 2;
    tampered[last] = if tampered[last] == b'}' { b' ' } else { b'}' };
    assert_eq!(
        validator.validate(&tampered, &digest),
        Err(ReportValidationError::DigestMismatch)
    );
    assert_eq!(
        validator.validate(&encoded, &"0".repeat(64)),
        Err(ReportValidationError::DigestMismatch)
    );

    let mut stale = expectations();
    stale.build_identity = "source-tree-sha256:stale".to_string();
    assert_eq!(
        ReportValidator::new(stale).validate(&encoded, &digest),
        Err(ReportValidationError::IdentityMismatch)
    );
}

fn temp_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "edge-memory-{label}-{}-{nonce}",
        std::process::id()
    ))
}
