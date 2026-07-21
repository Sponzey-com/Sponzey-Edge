use std::time::{SystemTime, UNIX_EPOCH};

use edge_memory_harness::evidence_cli::{
    collect_attached_process_report, parse_evidence_command, EvidenceCommand, SampleEvidenceOptions,
};
use edge_memory_harness::ports::ProcessSupervisor;
use edge_memory_harness::system_adapters::{ChildCommandSpec, SystemProcessSupervisor};

#[test]
fn evidence_cli_parser_rejects_missing_duplicate_unknown_and_zero_values() {
    let valid = vec![
        "sample",
        "--pid",
        "42",
        "--scenario",
        "idle",
        "--scenario-version",
        "v1",
        "--build-identity",
        "build",
        "--config-sha256",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "--samples",
        "3",
        "--interval-ms",
        "1",
        "--output",
        "report.json",
        "--digest-output",
        "report.sha256",
    ];
    assert!(matches!(
        parse_evidence_command(&strings(&valid)).unwrap(),
        EvidenceCommand::Sample(_)
    ));
    assert!(parse_evidence_command(&strings(&valid[..valid.len() - 2])).is_err());
    let mut duplicate = valid.clone();
    duplicate.extend(["--pid", "43"]);
    assert!(parse_evidence_command(&strings(&duplicate)).is_err());
    let mut unknown = valid.clone();
    unknown.extend(["--unknown", "x"]);
    assert!(parse_evidence_command(&strings(&unknown)).is_err());
    let mut zero = valid.clone();
    *zero.iter_mut().find(|value| **value == "3").unwrap() = "0";
    assert!(parse_evidence_command(&strings(&zero)).is_err());
}

#[test]
fn attached_child_sampling_publishes_source_bound_report_without_pid_or_path() {
    let root = temp_root();
    let report_path = root.join("idle.json");
    let digest_path = root.join("idle.sha256");
    let mut supervisor =
        SystemProcessSupervisor::new(ChildCommandSpec::new("sleep", ["5"]).unwrap());
    let child = supervisor.start().unwrap();
    let options = SampleEvidenceOptions {
        pid: child.pid,
        scenario_id: "idle".to_string(),
        scenario_version: "phase011-v1".to_string(),
        build_identity: format!("source-tree-sha256:{}", "a".repeat(64)),
        config_sha256: "d".repeat(64),
        sample_count: 3,
        interval_ms: 1,
        output: report_path.clone(),
        digest_output: digest_path.clone(),
    };

    collect_attached_process_report(&options).unwrap();

    let report = std::fs::read_to_string(report_path).unwrap();
    let digest = std::fs::read_to_string(digest_path).unwrap();
    assert!(report.contains("\"schema_version\": 2"));
    assert_eq!(digest.trim().len(), 64);
    assert!(!report.contains("\"pid\""));
    assert!(!report.contains("sleep"));
    assert!(!report.contains(root.to_string_lossy().as_ref()));
    supervisor.stop(&child).unwrap();
    std::fs::remove_dir_all(root).ok();
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn temp_root() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "edge-memory-evidence-{}-{nonce}",
        std::process::id()
    ))
}
