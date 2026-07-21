use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use edge_memory_harness::evaluator::{evaluate_scenario, AcceptancePolicy, ScenarioObservation};
use edge_memory_harness::http_driver::{
    HttpLoadCounters, RuntimePressure, RuntimeResourceObservation,
};
use edge_memory_harness::http_evidence::{
    HttpEvidenceExpectations, HttpEvidenceValidator, HttpEvidenceWriter, HttpMemoryEvidenceReport,
};
use edge_memory_harness::http_evidence_cli::{parse_http_evidence_command, HttpEvidenceCommand};
use edge_memory_harness::release_http_scenario::{
    ReleaseHttpScenarioRecord, ReleaseScenarioOutcome, ReleaseScenarioState,
};
use edge_memory_harness::report::EvidenceIdentity;
use edge_memory_harness::MemorySample;

#[test]
fn canonical_http_report_roundtrips_and_rejects_unknown_or_failed_cleanup() {
    let report = report("build-1");
    let canonical = report.to_canonical_json().unwrap();
    assert_eq!(
        HttpMemoryEvidenceReport::from_canonical_json(canonical.as_bytes()).unwrap(),
        report
    );
    assert_eq!(report.requests.expected, 3);
    assert_eq!(report.runtime.active_connections, 0);
    assert_eq!(report.runtime.used_payload_bytes, 0);
    assert_eq!(report.rss.peak_bytes, 20);
    assert_eq!(report.rss.cooldown_bytes.len(), 5);

    let unknown = canonical.replacen("\n}", ",\n  \"unknown\": true\n}", 1);
    assert!(HttpMemoryEvidenceReport::from_canonical_json(unknown.as_bytes()).is_err());

    let mut invalid = record();
    invalid.runtime_status.as_mut().unwrap().active_connections = 1;
    invalid
        .observation
        .as_mut()
        .unwrap()
        .active_connections_after_cooldown = 1;
    invalid.evaluation = Some(evaluate_scenario(
        &AcceptancePolicy::new(1024, 3).unwrap(),
        invalid.observation.as_ref().unwrap(),
    ));
    invalid.outcome = ReleaseScenarioOutcome::Failed;
    invalid.state = ReleaseScenarioState::Failed;
    assert!(HttpMemoryEvidenceReport::new(identity("build-1"), 1024, invalid).is_err());
}

#[test]
fn atomic_http_writer_and_validator_reject_tamper_and_stale_identity() {
    let root = temp_dir("http-evidence");
    let path = root.join("http.json");
    let report = report("build-current");
    let published = HttpEvidenceWriter::publish(&path, &report).unwrap();
    let bytes = fs::read(&path).unwrap();
    let validator = HttpEvidenceValidator::new(expectations("build-current"));

    assert_eq!(
        validator.validate(&bytes, &published.sha256).unwrap(),
        report
    );
    assert!(HttpEvidenceValidator::new(expectations("build-stale"))
        .validate(&bytes, &published.sha256)
        .is_err());

    let mut tampered = bytes;
    let index = tampered.iter().position(|byte| *byte == b'3').unwrap();
    tampered[index] = b'4';
    assert!(validator.validate(&tampered, &published.sha256).is_err());
    assert!(root.read_dir().unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn http_evidence_cli_parser_is_strict_before_effects() {
    let valid = valid_run_args();
    let parsed = parse_http_evidence_command(&valid).unwrap();
    assert!(matches!(parsed, HttpEvidenceCommand::Run(_)));

    let mut missing = valid.clone();
    missing.truncate(missing.len() - 2);
    assert!(parse_http_evidence_command(&missing).is_err());

    let mut duplicate = valid.clone();
    duplicate.extend(["--pid".to_string(), "43".to_string()]);
    assert!(parse_http_evidence_command(&duplicate).is_err());

    let mut unknown = valid;
    unknown.extend(["--unknown".to_string(), "value".to_string()]);
    assert!(parse_http_evidence_command(&unknown).is_err());

    let validate = [
        "validate",
        "--scenario",
        "http-churn-small",
        "--scenario-version",
        "phase011-v1",
        "--build-identity",
        "build-1",
        "--config-sha256",
        &"a".repeat(64),
        "--report",
        "report.json",
        "--digest",
        "report.sha256",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    assert!(matches!(
        parse_http_evidence_command(&validate).unwrap(),
        HttpEvidenceCommand::Validate(_)
    ));
}

fn report(build_identity: &str) -> HttpMemoryEvidenceReport {
    HttpMemoryEvidenceReport::new(identity(build_identity), 1024, record()).unwrap()
}

fn identity(build_identity: &str) -> EvidenceIdentity {
    EvidenceIdentity {
        scenario_id: "http-churn-small".to_string(),
        scenario_version: "phase011-v1".to_string(),
        platform: "test-os".to_string(),
        architecture: "test-arch".to_string(),
        build_identity: build_identity.to_string(),
        config_sha256: "a".repeat(64),
        process_start_identity: "process-start-1".to_string(),
    }
}

fn expectations(build_identity: &str) -> HttpEvidenceExpectations {
    HttpEvidenceExpectations {
        scenario_id: "http-churn-small".to_string(),
        scenario_version: "phase011-v1".to_string(),
        build_identity: build_identity.to_string(),
        config_sha256: "a".repeat(64),
    }
}

fn record() -> ReleaseHttpScenarioRecord {
    let observation = ScenarioObservation {
        peak_rss_bytes: 20,
        cooldown_cycle_medians: vec![18, 17, 16, 15, 14],
        process_alive: true,
        successful_requests: 3,
        failed_requests: 0,
        active_connections_after_cooldown: 0,
        charged_payload_bytes_after_cooldown: 0,
    };
    ReleaseHttpScenarioRecord {
        state: ReleaseScenarioState::Passed,
        outcome: ReleaseScenarioOutcome::Passed,
        samples: vec![
            sample(0, 10),
            sample(10, 20),
            sample(20, 18),
            sample(30, 17),
            sample(40, 16),
            sample(50, 15),
            sample(60, 14),
        ],
        counters: Some(HttpLoadCounters {
            expected: 3,
            succeeded: 3,
            failed: 0,
        }),
        runtime_status: Some(RuntimeResourceObservation {
            revision_id: "rev-1".to_string(),
            generation: 4,
            used_payload_bytes: 0,
            payload_limit_bytes: 128 * 1024 * 1024,
            active_connections: 0,
            pressure: RuntimePressure::Normal,
        }),
        evaluation: Some(evaluate_scenario(
            &AcceptancePolicy::new(1024, 3).unwrap(),
            &observation,
        )),
        observation: Some(observation),
    }
}

fn sample(elapsed_ms: u64, rss_bytes: u64) -> MemorySample {
    MemorySample {
        elapsed_ms,
        rss_bytes,
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("edge-{name}-{nanos}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn valid_run_args() -> Vec<String> {
    [
        "run",
        "--pid",
        "42",
        "--proxy-address",
        "127.0.0.1:8080",
        "--admin-address",
        "127.0.0.1:8081",
        "--host",
        "localhost",
        "--requests",
        "3",
        "--timeout-ms",
        "5000",
        "--max-response-bytes",
        "65536",
        "--expected-revision",
        "rev-1",
        "--ceiling-bytes",
        "268435456",
        "--cooldown-cycles",
        "5",
        "--cooldown-interval-ms",
        "200",
        "--scenario",
        "http-churn-small",
        "--scenario-version",
        "phase011-v1",
        "--build-identity",
        "build-1",
        "--config-sha256",
        &"a".repeat(64),
        "--output",
        "report.json",
        "--digest-output",
        "report.sha256",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
