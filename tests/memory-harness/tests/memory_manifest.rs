use edge_memory_harness::memory_manifest::{
    collect_manifest, inspect_manifest, validate_manifest, ManifestInputs, MemoryManifestStatus,
    STEADY_PROFILE_SCENARIOS,
};
use edge_memory_harness::orchestrator::{ScenarioOutcome, ScenarioRunRecord};
use edge_memory_harness::report::{EvidenceIdentity, MemoryEvidenceReport};
use edge_memory_harness::report_io::sha256_hex;
use edge_memory_harness::scenario::ScenarioState;
use edge_memory_harness::MemorySample;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn canonical_partial_manifest_binds_exact_steady_profile_and_cleanup() {
    let root = TempDir::new("valid");
    write_profile(root.path(), BUILD);

    let manifest = collect_manifest(&inputs(root.path(), BUILD)).unwrap();
    assert_eq!(manifest.status, MemoryManifestStatus::Partial);
    assert_eq!(manifest.entries.len(), STEADY_PROFILE_SCENARIOS.len());
    assert_eq!(manifest.platform, "macos");
    assert_eq!(manifest.architecture, "aarch64");
    assert_eq!(manifest.repetitions, 1);
    assert_eq!(manifest.entries[0].scenario_id, "http-steady");
    assert_eq!(manifest.entries[0].cleanup_active_connections, 0);
    assert_eq!(manifest.entries[0].cleanup_charged_payload_bytes, 0);
    assert_eq!(manifest.entries[0].cleanup_pressure, "normal");
    assert_eq!(manifest.entries[0].recovery_status, 200);
    assert_eq!(manifest.entries[2].rejected_negatives, 2);
    assert!(manifest
        .approval_blockers
        .contains(&"linux-x86_64-profile".to_string()));

    let bytes = manifest.to_canonical_json().unwrap();
    let digest = sha256_hex(bytes.as_bytes());
    assert_eq!(
        validate_manifest(&inputs(root.path(), BUILD), bytes.as_bytes(), &digest).unwrap(),
        manifest
    );
}

#[test]
fn collector_rejects_missing_unknown_duplicate_stale_threshold_and_tamper() {
    let root = TempDir::new("negative");
    write_profile(root.path(), BUILD);

    fs::remove_file(root.path().join("https-steady-summary.txt")).unwrap();
    assert!(collect_manifest(&inputs(root.path(), BUILD)).is_err());
    write_profile(root.path(), BUILD);

    fs::write(root.path().join("unknown.txt"), b"unknown\n").unwrap();
    assert!(collect_manifest(&inputs(root.path(), BUILD)).is_err());
    fs::remove_file(root.path().join("unknown.txt")).unwrap();

    write_scenario(
        root.path(),
        "http-steady",
        ("stale", BUILD),
        100_000,
        100,
        0,
        0,
    );
    assert!(collect_manifest(&inputs(root.path(), BUILD)).is_err());
    write_profile(root.path(), BUILD);

    write_scenario(
        root.path(),
        "http-steady",
        (
            "http-steady",
            "source-tree-sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
        100_000,
        100,
        0,
        0,
    );
    assert!(collect_manifest(&inputs(root.path(), BUILD)).is_err());
    write_profile(root.path(), BUILD);

    write_scenario(
        root.path(),
        "http-steady",
        ("http-steady", BUILD),
        100_000,
        100,
        0,
        402_653_185,
    );
    assert!(collect_manifest(&inputs(root.path(), BUILD)).is_err());
    write_profile(root.path(), BUILD);

    fs::write(root.path().join("http-steady-v1.json"), b"{}\n").unwrap();
    assert!(collect_manifest(&inputs(root.path(), BUILD)).is_err());
    write_profile(root.path(), BUILD);

    let summary_path = root.path().join("http-steady-summary.txt");
    let summary = fs::read_to_string(&summary_path).unwrap();
    fs::write(
        &summary_path,
        summary.replace("max_active=100", "max_active=1025"),
    )
    .unwrap();
    assert!(collect_manifest(&inputs(root.path(), BUILD)).is_err());
}

#[test]
fn validator_rejects_noncanonical_digest_mismatch_and_approved_claim() {
    let root = TempDir::new("validator");
    write_profile(root.path(), BUILD);
    let manifest = collect_manifest(&inputs(root.path(), BUILD)).unwrap();
    let canonical = manifest.to_canonical_json().unwrap();

    let mut noncanonical = canonical.clone();
    noncanonical.push('\n');
    assert!(validate_manifest(
        &inputs(root.path(), BUILD),
        noncanonical.as_bytes(),
        &sha256_hex(noncanonical.as_bytes())
    )
    .is_err());
    assert!(validate_manifest(
        &inputs(root.path(), BUILD),
        canonical.as_bytes(),
        &"0".repeat(64)
    )
    .is_err());

    let approved = canonical.replace("\"partial\"", "\"approved\"");
    assert!(validate_manifest(
        &inputs(root.path(), BUILD),
        approved.as_bytes(),
        &sha256_hex(approved.as_bytes())
    )
    .is_err());
    assert_eq!(
        inspect_manifest(
            canonical.as_bytes(),
            &sha256_hex(canonical.as_bytes()),
            BUILD
        )
        .unwrap(),
        manifest
    );
    assert!(inspect_manifest(
        canonical.as_bytes(),
        &sha256_hex(canonical.as_bytes()),
        "source-tree-sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn collector_rejects_symlink_inputs() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new("symlink");
    write_profile(root.path(), BUILD);
    let target = root.path().join("real-summary.txt");
    fs::rename(root.path().join("http-steady-summary.txt"), &target).unwrap();
    symlink(&target, root.path().join("http-steady-summary.txt")).unwrap();
    assert!(collect_manifest(&inputs(root.path(), BUILD)).is_err());
}

#[test]
fn separate_process_collects_validates_and_preserves_target_on_failure() {
    let root = TempDir::new("cli");
    let input = root.path().join("input");
    let output = root.path().join("manifest.json");
    let digest = root.path().join("manifest.sha256");
    write_profile(&input, BUILD);

    let collect = manifest_command("collect", &input, &output, &digest, "partial")
        .output()
        .unwrap();
    assert!(
        collect.status.success(),
        "{}",
        String::from_utf8_lossy(&collect.stderr)
    );
    assert!(String::from_utf8_lossy(&collect.stdout).contains("status=partial entries=3"));

    let validate = manifest_command("validate", &input, &output, &digest, "partial")
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    assert!(
        String::from_utf8_lossy(&validate.stdout).contains("validated profile=phase011-steady-v1")
    );

    let inspect = Command::new(env!("CARGO_BIN_EXE_edge-memory-manifest"))
        .arg("inspect")
        .arg("--build-identity")
        .arg(BUILD)
        .arg("--manifest")
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
    assert!(
        String::from_utf8_lossy(&inspect.stdout).contains("inspected profile=phase011-steady-v1")
    );

    fs::write(&output, b"preserve-on-failure\n").unwrap();
    fs::write(input.join("http-steady-summary.txt"), b"tampered\n").unwrap();
    let failed = manifest_command("collect", &input, &output, &digest, "partial")
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert_eq!(fs::read(&output).unwrap(), b"preserve-on-failure\n");

    write_profile(&input, BUILD);
    let approved = manifest_command("collect", &input, &output, &digest, "approved")
        .output()
        .unwrap();
    assert!(!approved.status.success());
    assert_eq!(fs::read(&output).unwrap(), b"preserve-on-failure\n");
}

fn manifest_command(
    command: &str,
    input: &Path,
    output: &Path,
    digest: &Path,
    status: &str,
) -> Command {
    let mut process = Command::new(env!("CARGO_BIN_EXE_edge-memory-manifest"));
    process
        .arg(command)
        .arg("--input-dir")
        .arg(input)
        .arg("--build-identity")
        .arg(BUILD)
        .arg("--platform")
        .arg("macos")
        .arg("--architecture")
        .arg("aarch64")
        .arg("--repetitions")
        .arg("1")
        .arg("--status")
        .arg(status);
    if command == "collect" {
        process
            .arg("--output")
            .arg(output)
            .arg("--digest-output")
            .arg(digest);
    } else {
        process
            .arg("--manifest")
            .arg(output)
            .arg("--digest")
            .arg(digest);
    }
    process
}

fn inputs(root: &Path, build_identity: &str) -> ManifestInputs {
    ManifestInputs {
        input_dir: root.to_path_buf(),
        build_identity: build_identity.to_string(),
        platform: "macos".to_string(),
        architecture: "aarch64".to_string(),
        repetitions: 1,
        status: MemoryManifestStatus::Partial,
    }
}

fn write_profile(root: &Path, build_identity: &str) {
    write_scenario(
        root,
        "http-steady",
        ("http-steady", build_identity),
        100_000,
        100,
        0,
        10_000_000,
    );
    write_scenario(
        root,
        "https-steady",
        ("https-steady", build_identity),
        50_000,
        100,
        2,
        12_000_000,
    );
    write_scenario(
        root,
        "mtls-steady",
        ("mtls-steady", build_identity),
        25_000,
        64,
        2,
        13_000_000,
    );
}

fn write_scenario(
    root: &Path,
    file_stem: &str,
    identity: (&str, &str),
    expected: usize,
    workers: usize,
    rejected_negatives: usize,
    peak_rss_bytes: u64,
) {
    fs::create_dir_all(root).unwrap();
    let report = MemoryEvidenceReport::new(
        EvidenceIdentity {
            scenario_id: identity.0.to_string(),
            scenario_version: "phase011-v1".to_string(),
            platform: "macos".to_string(),
            architecture: "aarch64".to_string(),
            build_identity: identity.1.to_string(),
            config_sha256: CONFIG.to_string(),
            process_start_identity: "macos-lstart:test".to_string(),
        },
        2,
        ScenarioRunRecord {
            state: ScenarioState::Passed,
            outcome: ScenarioOutcome::Passed,
            samples: vec![
                MemorySample {
                    elapsed_ms: 0,
                    rss_bytes: peak_rss_bytes.saturating_sub(1).max(1),
                },
                MemorySample {
                    elapsed_ms: 1,
                    rss_bytes: peak_rss_bytes.max(1),
                },
            ],
            missing_samples: 0,
        },
    )
    .unwrap();
    let report_bytes = report.to_canonical_json().unwrap();
    fs::write(root.join(format!("{file_stem}-v1.json")), &report_bytes).unwrap();
    fs::write(
        root.join(format!("{file_stem}-v1.sha256")),
        format!("{}\n", sha256_hex(report_bytes.as_bytes())),
    )
    .unwrap();
    fs::write(
        root.join(format!("{file_stem}-driver-summary.json")),
        format!(
            "{{\"schema_version\":1,\"expected\":{expected},\"succeeded\":{expected},\"failed\":0,\"workers\":{workers},\"state\":\"completed\"}}"
        ),
    )
    .unwrap();
    let label = match file_stem {
        "http-steady" => "HTTP steady",
        "https-steady" => "HTTPS steady",
        _ => "mTLS steady",
    };
    let extras = if rejected_negatives == 0 {
        String::new()
    } else {
        format!(" rejected_negatives={rejected_negatives} forwarded={expected}")
    };
    fs::write(
        root.join(format!("{file_stem}-summary.txt")),
        format!(
            "{label} passed expected={expected} succeeded={expected} failed=0 workers={workers}{extras} samples=2 max_active={workers} max_charge=4096 final=0/0/normal recovery=200 peak_rss_bytes={}\n",
            peak_rss_bytes.max(1)
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
            "sponzey-memory-manifest-{label}-{}-{nonce}",
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
