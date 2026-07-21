use edge_memory_harness::memory_aggregate::{
    build_aggregate, AggregateRunEvidence, MemoryAggregateStatus, THREE_RUN_REPETITIONS,
};
use edge_memory_harness::memory_manifest::{
    collect_manifest, ManifestInputs, MemoryEvidenceManifest, MemoryManifestEntry,
    MemoryManifestStatus, STEADY_PROFILE_SCENARIOS,
};
use edge_memory_harness::orchestrator::{ScenarioOutcome, ScenarioRunRecord};
use edge_memory_harness::report::{EvidenceIdentity, MemoryEvidenceReport};
use edge_memory_harness::report_io::sha256_hex;
use edge_memory_harness::scenario::ScenarioState;
use edge_memory_harness::MemorySample;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn three_distinct_valid_runs_build_canonical_partial_aggregate() {
    let runs = vec![run(1, 10_000_000), run(2, 11_000_000), run(3, 12_000_000)];

    let aggregate = build_aggregate(runs).unwrap();

    assert_eq!(aggregate.repetitions, THREE_RUN_REPETITIONS);
    assert_eq!(aggregate.status, MemoryAggregateStatus::Partial);
    assert_eq!(aggregate.runs.len(), 3);
    assert_eq!(aggregate.scenarios.len(), 3);
    assert!(aggregate
        .approval_blockers
        .contains(&"linux-x86_64-profile".to_string()));
    for scenario in &aggregate.scenarios {
        assert_eq!(scenario.run_count, 3);
        assert!(scenario.repeatability_passed);
        assert_eq!(scenario.cleanup_failures, 0);
        assert_eq!(scenario.correctness_failures, 0);
    }

    let canonical = aggregate.to_canonical_json().unwrap();
    assert_eq!(
        edge_memory_harness::memory_aggregate::MemoryEvidenceAggregate::from_canonical_json(
            canonical.as_bytes()
        )
        .unwrap(),
        aggregate
    );
}

#[test]
fn aggregate_rejects_wrong_count_duplicate_or_mixed_identity() {
    assert!(build_aggregate(vec![run(1, 10_000_000), run(2, 11_000_000)]).is_err());
    assert!(build_aggregate(vec![
        run(1, 10_000_000),
        run(1, 11_000_000),
        run(3, 12_000_000),
    ])
    .is_err());

    let mut mixed = run(3, 12_000_000);
    mixed.manifest.build_identity =
        "source-tree-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_string();
    mixed.manifest_sha256 = sha256_hex(mixed.manifest.to_canonical_json().unwrap().as_bytes());
    assert!(build_aggregate(vec![run(1, 10_000_000), run(2, 11_000_000), mixed,]).is_err());
}

#[test]
fn aggregate_rejects_duplicate_process_fingerprint_tamper_and_repeatability_failure() {
    let first = run(1, 10_000_000);
    let mut duplicate = run(2, 11_000_000);
    duplicate.process_identity_sha256 = first.process_identity_sha256.clone();
    assert!(build_aggregate(vec![first.clone(), duplicate, run(3, 12_000_000)]).is_err());

    let mut tampered = run(2, 11_000_000);
    tampered.manifest_sha256 = "0".repeat(64);
    assert!(build_aggregate(vec![first.clone(), tampered, run(3, 12_000_000)]).is_err());

    let excessive = 10_000_000 + 16 * 1024 * 1024 + 1;
    assert!(build_aggregate(vec![first, run(2, 10_000_000), run(3, excessive)]).is_err());
}

#[test]
fn aggregate_accepts_fresh_ephemeral_config_identity_for_each_independent_run() {
    let mut runs = vec![run(1, 10_000_000), run(2, 11_000_000), run(3, 12_000_000)];
    for (index, run) in runs.iter_mut().enumerate() {
        let config_identity = format!("{:064x}", index + 10);
        for entry in &mut run.manifest.entries {
            entry.config_sha256 = config_identity.clone();
        }
        run.manifest_sha256 = sha256_hex(run.manifest.to_canonical_json().unwrap().as_bytes());
    }

    assert!(build_aggregate(runs).is_ok());
}

#[test]
fn aggregate_cli_fails_closed_without_replacing_existing_output() {
    let root = std::env::temp_dir().join(format!(
        "sponzey-memory-aggregate-red-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let output = root.join("aggregate.json");
    let digest = root.join("aggregate.sha256");
    fs::write(&output, b"preserve\n").unwrap();
    fs::write(&digest, b"preserve-digest\n").unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_edge-memory-aggregate"))
        .arg("collect")
        .arg("--input-root")
        .arg(root.join("missing"))
        .arg("--build-identity")
        .arg(BUILD)
        .arg("--platform")
        .arg("macos")
        .arg("--architecture")
        .arg("aarch64")
        .arg("--output")
        .arg(&output)
        .arg("--digest-output")
        .arg(&digest)
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert_eq!(fs::read(&output).unwrap(), b"preserve\n");
    assert_eq!(fs::read(&digest).unwrap(), b"preserve-digest\n");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn aggregate_cli_collects_validates_and_inspects_three_physical_runs() {
    let root = TempDir::new("cli-valid");
    let input = root.path().join("input");
    let output = root.path().join("aggregate.json");
    let digest = root.path().join("aggregate.sha256");
    write_aggregate_input(&input);

    let collect = aggregate_command("collect", &input, &output, &digest)
        .output()
        .unwrap();
    assert!(
        collect.status.success(),
        "{}",
        String::from_utf8_lossy(&collect.stderr)
    );
    assert!(String::from_utf8_lossy(&collect.stdout).contains("runs=3 scenarios=3"));

    let validate = aggregate_command("validate", &input, &output, &digest)
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    assert!(String::from_utf8_lossy(&validate.stdout)
        .contains("validated profile=phase011-steady-3run-v1"));

    let inspect = Command::new(env!("CARGO_BIN_EXE_edge-memory-aggregate"))
        .arg("inspect")
        .arg("--build-identity")
        .arg(BUILD)
        .arg("--aggregate")
        .arg(&output)
        .arg("--digest")
        .arg(&digest)
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
}

#[test]
fn aggregate_cli_rejects_tamper_and_duplicate_run_identity_without_replacement() {
    let root = TempDir::new("cli-negative");
    let input = root.path().join("input");
    let output = root.path().join("aggregate.json");
    let digest = root.path().join("aggregate.sha256");
    write_aggregate_input(&input);
    fs::write(&output, b"preserve\n").unwrap();
    fs::write(&digest, b"preserve-digest\n").unwrap();

    fs::write(
        input.join("run-001/profile/http-steady-summary.txt"),
        b"tampered\n",
    )
    .unwrap();
    let tamper = aggregate_command("collect", &input, &output, &digest)
        .output()
        .unwrap();
    assert!(!tamper.status.success());
    assert_eq!(fs::read(&output).unwrap(), b"preserve\n");
    assert_eq!(fs::read(&digest).unwrap(), b"preserve-digest\n");

    write_run(&input, 1, 1, BUILD);
    write_run(&input, 2, 1, BUILD);
    let duplicate = aggregate_command("collect", &input, &output, &digest)
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert_eq!(fs::read(&output).unwrap(), b"preserve\n");
}

#[cfg(unix)]
#[test]
fn aggregate_cli_rejects_symlink_run_directory() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new("cli-symlink");
    let input = root.path().join("input");
    let output = root.path().join("aggregate.json");
    let digest = root.path().join("aggregate.sha256");
    write_aggregate_input(&input);
    let real = root.path().join("real-run-003");
    fs::rename(input.join("run-003"), &real).unwrap();
    symlink(&real, input.join("run-003")).unwrap();

    assert!(!aggregate_command("collect", &input, &output, &digest)
        .status()
        .unwrap()
        .success());
    assert!(!output.exists());
    assert!(!digest.exists());
}

fn run(index: u32, peak_rss_bytes: u64) -> AggregateRunEvidence {
    let manifest = manifest(peak_rss_bytes);
    let canonical = manifest.to_canonical_json().unwrap();
    AggregateRunEvidence {
        run_index: index,
        manifest_sha256: sha256_hex(canonical.as_bytes()),
        process_identity_sha256: sha256_hex(format!("run-{index}-processes").as_bytes()),
        cooldown_rss_by_scenario: STEADY_PROFILE_SCENARIOS
            .iter()
            .map(|scenario| ((*scenario).to_string(), peak_rss_bytes))
            .collect::<BTreeMap<_, _>>(),
        manifest,
    }
}

fn manifest(peak_rss_bytes: u64) -> MemoryEvidenceManifest {
    MemoryEvidenceManifest {
        schema_version: 1,
        profile_id: "phase011-steady-v1".to_string(),
        collector_version: "edge-memory-manifest-v1".to_string(),
        build_identity: BUILD.to_string(),
        platform: "macos".to_string(),
        architecture: "aarch64".to_string(),
        repetitions: 1,
        status: MemoryManifestStatus::Partial,
        approval_blockers: vec![
            "linux-x86_64-profile".to_string(),
            "three-independent-repetitions".to_string(),
            "long-soak-and-deep-diagnostic".to_string(),
        ],
        entries: STEADY_PROFILE_SCENARIOS
            .iter()
            .map(|scenario| entry(scenario, peak_rss_bytes))
            .collect(),
    }
}

fn entry(scenario: &str, peak_rss_bytes: u64) -> MemoryManifestEntry {
    let (requests, workers, negatives) = match scenario {
        "http-steady" => (100_000, 100, 0),
        "https-steady" => (50_000, 100, 2),
        "mtls-steady" => (25_000, 64, 2),
        _ => unreachable!(),
    };
    MemoryManifestEntry {
        scenario_id: scenario.to_string(),
        scenario_version: "phase011-v1".to_string(),
        report_file: format!("{scenario}-v1.json"),
        report_sha256: "1".repeat(64),
        driver_summary_file: format!("{scenario}-driver-summary.json"),
        driver_summary_sha256: "2".repeat(64),
        terminal_summary_file: format!("{scenario}-summary.txt"),
        terminal_summary_sha256: "3".repeat(64),
        config_sha256: "4".repeat(64),
        expected_requests: requests,
        succeeded_requests: requests,
        failed_requests: 0,
        workers,
        rejected_negatives: negatives,
        forwarded_requests: requests,
        observed_status_samples: 1,
        max_active_connections: workers,
        max_charged_payload_bytes: 1024,
        cleanup_active_connections: 0,
        cleanup_charged_payload_bytes: 0,
        cleanup_pressure: "normal".to_string(),
        recovery_status: 200,
        peak_rss_bytes,
        rss_ceiling_bytes: 402_653_184,
    }
}

fn aggregate_command(command: &str, input: &Path, output: &Path, digest: &Path) -> Command {
    let mut process = Command::new(env!("CARGO_BIN_EXE_edge-memory-aggregate"));
    process
        .arg(command)
        .arg("--input-root")
        .arg(input)
        .arg("--build-identity")
        .arg(BUILD)
        .arg("--platform")
        .arg("macos")
        .arg("--architecture")
        .arg("aarch64");
    if command == "collect" {
        process
            .arg("--output")
            .arg(output)
            .arg("--digest-output")
            .arg(digest);
    } else {
        process
            .arg("--aggregate")
            .arg(output)
            .arg("--digest")
            .arg(digest);
    }
    process
}

fn write_aggregate_input(root: &Path) {
    for run_index in 1..=3 {
        write_run(root, run_index, run_index, BUILD);
    }
}

fn write_run(root: &Path, run_index: u32, identity_index: u32, build_identity: &str) {
    let run_dir = root.join(format!("run-{run_index:03}"));
    if run_dir.exists() {
        fs::remove_dir_all(&run_dir).unwrap();
    }
    let profile = run_dir.join("profile");
    let manifest_dir = run_dir.join("manifest");
    fs::create_dir_all(&manifest_dir).unwrap();
    for scenario in STEADY_PROFILE_SCENARIOS {
        write_scenario(
            &profile,
            scenario,
            build_identity,
            identity_index,
            10_000_000 + u64::from(run_index) * 1_000_000,
        );
    }
    let manifest = collect_manifest(&ManifestInputs {
        input_dir: profile,
        build_identity: build_identity.to_string(),
        platform: "macos".to_string(),
        architecture: "aarch64".to_string(),
        repetitions: 1,
        status: MemoryManifestStatus::Partial,
    })
    .unwrap();
    let encoded = manifest.to_canonical_json().unwrap();
    fs::write(
        manifest_dir.join("phase011-steady-manifest-v1.json"),
        &encoded,
    )
    .unwrap();
    fs::write(
        manifest_dir.join("phase011-steady-manifest-v1.sha256"),
        format!("{}\n", sha256_hex(encoded.as_bytes())),
    )
    .unwrap();
}

fn write_scenario(
    root: &Path,
    scenario: &str,
    build_identity: &str,
    identity_index: u32,
    peak_rss_bytes: u64,
) {
    let (expected, workers, rejected_negatives, label) = match scenario {
        "http-steady" => (100_000, 100, 0, "HTTP steady"),
        "https-steady" => (50_000, 100, 2, "HTTPS steady"),
        "mtls-steady" => (25_000, 64, 2, "mTLS steady"),
        _ => unreachable!(),
    };
    fs::create_dir_all(root).unwrap();
    let report = MemoryEvidenceReport::new(
        EvidenceIdentity {
            scenario_id: scenario.to_string(),
            scenario_version: "phase011-v1".to_string(),
            platform: "macos".to_string(),
            architecture: "aarch64".to_string(),
            build_identity: build_identity.to_string(),
            config_sha256: CONFIG.to_string(),
            process_start_identity: format!("macos-lstart:run-{identity_index}-{scenario}"),
        },
        2,
        ScenarioRunRecord {
            state: ScenarioState::Passed,
            outcome: ScenarioOutcome::Passed,
            samples: vec![
                MemorySample {
                    elapsed_ms: 0,
                    rss_bytes: peak_rss_bytes.saturating_sub(1),
                },
                MemorySample {
                    elapsed_ms: 1,
                    rss_bytes: peak_rss_bytes,
                },
            ],
            missing_samples: 0,
        },
    )
    .unwrap();
    let report_bytes = report.to_canonical_json().unwrap();
    fs::write(root.join(format!("{scenario}-v1.json")), &report_bytes).unwrap();
    fs::write(
        root.join(format!("{scenario}-v1.sha256")),
        format!("{}\n", sha256_hex(report_bytes.as_bytes())),
    )
    .unwrap();
    fs::write(
        root.join(format!("{scenario}-driver-summary.json")),
        format!(
            "{{\"schema_version\":1,\"expected\":{expected},\"succeeded\":{expected},\"failed\":0,\"workers\":{workers},\"state\":\"completed\"}}"
        ),
    )
    .unwrap();
    let extras = if rejected_negatives == 0 {
        String::new()
    } else {
        format!(" rejected_negatives={rejected_negatives} forwarded={expected}")
    };
    fs::write(
        root.join(format!("{scenario}-summary.txt")),
        format!(
            "{label} passed expected={expected} succeeded={expected} failed=0 workers={workers}{extras} samples=2 max_active={workers} max_charge=4096 final=0/0/normal recovery=200 peak_rss_bytes={peak_rss_bytes}\n"
        ),
    )
    .unwrap();
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sponzey-memory-aggregate-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
