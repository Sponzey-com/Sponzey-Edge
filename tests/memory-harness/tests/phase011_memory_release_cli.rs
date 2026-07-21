use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use edge_memory_harness::diagnostic_soak::{
    evaluate_diagnostic_soak, DiagnosticSoakObservation, SoakWorkload, SOAK_OBSERVATION_COUNT,
};
use edge_memory_harness::full_profile_readiness::{
    evaluate_full_profile, FullProfileEntry, FullProfileInput, FULL_PROFILE_SCENARIOS,
};
use edge_memory_harness::phase011_memory_release::PHASE011_MEMORY_RELEASE_MARKER;
use edge_memory_harness::phase011_memory_release_cli::{
    collect_phase011_memory_release, validate_phase011_memory_release, MemoryReleaseCollectOptions,
    MemoryReleaseValidateOptions,
};
use edge_memory_harness::report_io::sha256_hex;

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn adapter_collects_and_validates_physical_canonical_inputs() {
    let fixture = Fixture::new();

    let summary = collect_phase011_memory_release(fixture.collect_options()).unwrap();
    assert!(summary.contains("scenarios=12"));
    assert!(fixture.output.is_file());
    assert!(fixture.output_digest.is_file());

    let validated = validate_phase011_memory_release(MemoryReleaseValidateOptions {
        expected_build_identity: BUILD.to_string(),
        report: fixture.output.clone(),
        digest: fixture.output_digest.clone(),
    })
    .unwrap();
    assert!(validated.contains(PHASE011_MEMORY_RELEASE_MARKER));
}

#[test]
fn adapter_rejects_tamper_forbidden_input_and_existing_output_without_publication() {
    let fixture = Fixture::new();
    fs::write(&fixture.soak_digest, format!("{}\n", "c".repeat(64))).unwrap();
    assert!(collect_phase011_memory_release(fixture.collect_options()).is_err());
    assert!(!fixture.output.exists());
    assert!(!fixture.output_digest.exists());

    let forbidden = Fixture::new();
    let mut bytes = fs::read(&forbidden.inventory).unwrap();
    bytes.extend_from_slice(b"secret");
    fs::write(&forbidden.inventory, bytes).unwrap();
    write_digest(&forbidden.inventory, &forbidden.inventory_digest);
    assert!(collect_phase011_memory_release(forbidden.collect_options()).is_err());

    let existing = Fixture::new();
    fs::write(&existing.output, b"existing").unwrap();
    assert!(collect_phase011_memory_release(existing.collect_options()).is_err());
    assert_eq!(fs::read(&existing.output).unwrap(), b"existing");
}

#[cfg(unix)]
#[test]
fn adapter_rejects_symlink_input() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let linked = fixture.root.join("linked-readiness.json");
    symlink(&fixture.readiness, &linked).unwrap();
    let mut options = fixture.collect_options();
    options.readiness = linked;
    assert!(collect_phase011_memory_release(options).is_err());
}

struct Fixture {
    root: PathBuf,
    inventory: PathBuf,
    inventory_digest: PathBuf,
    readiness: PathBuf,
    readiness_digest: PathBuf,
    soak: PathBuf,
    soak_digest: PathBuf,
    output: PathBuf,
    output_digest: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let root = std::env::temp_dir().join(format!(
            "edge-phase011-memory-release-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let inventory = valid_inventory();
        let readiness = evaluate_full_profile(inventory.clone()).unwrap();
        let soak = valid_soak();
        let inventory_path = root.join("inventory.json");
        let readiness_path = root.join("readiness.json");
        let soak_path = root.join("soak.json");
        let mut inventory_json = serde_json::to_string_pretty(&inventory).unwrap();
        inventory_json.push('\n');
        fs::write(&inventory_path, inventory_json).unwrap();
        fs::write(&readiness_path, readiness.to_canonical_json().unwrap()).unwrap();
        fs::write(&soak_path, soak.to_canonical_json().unwrap()).unwrap();
        let fixture = Self {
            inventory: inventory_path,
            inventory_digest: root.join("inventory.sha256"),
            readiness: readiness_path,
            readiness_digest: root.join("readiness.sha256"),
            soak: soak_path,
            soak_digest: root.join("soak.sha256"),
            output: root.join("release.json"),
            output_digest: root.join("release.sha256"),
            root,
        };
        write_digest(&fixture.inventory, &fixture.inventory_digest);
        write_digest(&fixture.readiness, &fixture.readiness_digest);
        write_digest(&fixture.soak, &fixture.soak_digest);
        fixture
    }

    fn collect_options(&self) -> MemoryReleaseCollectOptions {
        MemoryReleaseCollectOptions {
            expected_build_identity: BUILD.to_string(),
            expected_platform: "macos".to_string(),
            expected_architecture: "arm64".to_string(),
            inventory: self.inventory.clone(),
            inventory_digest: self.inventory_digest.clone(),
            readiness: self.readiness.clone(),
            readiness_digest: self.readiness_digest.clone(),
            soak: self.soak.clone(),
            soak_digest: self.soak_digest.clone(),
            output: self.output.clone(),
            output_digest: self.output_digest.clone(),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_digest(source: &Path, target: &Path) {
    let digest = sha256_hex(&fs::read(source).unwrap());
    fs::write(target, format!("{digest}\n")).unwrap();
}

fn valid_inventory() -> FullProfileInput {
    FullProfileInput {
        current_build_identity: BUILD.to_string(),
        platform: "macos".to_string(),
        architecture: "arm64".to_string(),
        entries: FULL_PROFILE_SCENARIOS
            .iter()
            .map(|contract| FullProfileEntry {
                scenario_id: contract.scenario_id.to_string(),
                evidence_kind: contract.evidence_kind,
                build_identity: BUILD.to_string(),
                report_sha256: DIGEST.to_string(),
                validation_passed: true,
            })
            .collect(),
    }
}

fn valid_soak() -> edge_memory_harness::diagnostic_soak::DiagnosticSoakReport {
    evaluate_diagnostic_soak(
        (0..SOAK_OBSERVATION_COUNT)
            .map(|index| {
                let workload = if index == 0 {
                    SoakWorkload::Baseline
                } else if index % 2 == 1 {
                    SoakWorkload::Churn
                } else {
                    SoakWorkload::Websocket
                };
                let expected = match workload {
                    SoakWorkload::Baseline => 0,
                    SoakWorkload::Churn => 1_000,
                    SoakWorkload::Websocket => 128,
                };
                DiagnosticSoakObservation {
                    index,
                    elapsed_seconds: u64::from(index) * 60,
                    workload,
                    build_identity: BUILD.to_string(),
                    config_sha256: DIGEST.to_string(),
                    process_start_identity: "fixture-process".to_string(),
                    expected,
                    succeeded: expected,
                    failed: 0,
                    process_alive: true,
                    rss_bytes: 8 * 1024 * 1024,
                    cleanup_connections: 0,
                    cleanup_payload_bytes: 0,
                    cleanup_pressure: "normal".to_string(),
                    recovery_status: 200,
                }
            })
            .collect(),
    )
    .unwrap()
}
