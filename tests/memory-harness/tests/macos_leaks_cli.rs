use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use edge_memory_harness::macos_leaks_cli::{
    collect_macos_leaks, validate_macos_leaks, MacosLeaksCollectOptions, MacosLeaksValidateOptions,
};
use edge_memory_harness::report_io::sha256_hex;

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn adapter_collects_and_revalidates_physical_zero_leak_artifact() {
    let fixture = Fixture::new();
    let summary = collect_macos_leaks(fixture.collect_options()).unwrap();
    assert!(summary.contains("leaks=0 bytes=0"));

    let validated = validate_macos_leaks(MacosLeaksValidateOptions {
        expected_build_identity: BUILD.to_string(),
        raw: fixture.raw.clone(),
        raw_digest: fixture.raw_digest.clone(),
        report: fixture.report.clone(),
        report_digest: fixture.report_digest.clone(),
    })
    .unwrap();
    assert!(validated.contains("validated leaks=0 bytes=0"));
}

#[test]
fn adapter_rejects_tamper_definite_leak_and_existing_output_without_publication() {
    let fixture = Fixture::new();
    fs::write(&fixture.raw_digest, format!("{}\n", "c".repeat(64))).unwrap();
    assert!(collect_macos_leaks(fixture.collect_options()).is_err());
    assert!(!fixture.report.exists());

    let leaked = Fixture::new();
    write_owner_only(
        &leaked.raw,
        b"Process 7: 1 leak for 81920 total leaked bytes.\n",
    );
    write_digest(&leaked.raw, &leaked.raw_digest);
    let mut options = leaked.collect_options();
    options.tool_exit_code = 1;
    assert!(collect_macos_leaks(options).is_err());
    assert!(!leaked.report.exists());

    let existing = Fixture::new();
    fs::write(&existing.report, b"existing").unwrap();
    assert!(collect_macos_leaks(existing.collect_options()).is_err());
    assert_eq!(fs::read(&existing.report).unwrap(), b"existing");
}

#[cfg(unix)]
#[test]
fn adapter_rejects_symlink_and_non_owner_only_raw_artifact() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let fixture = Fixture::new();
    let link = fixture.root.join("linked.raw");
    symlink(&fixture.raw, &link).unwrap();
    let mut options = fixture.collect_options();
    options.raw = link;
    assert!(collect_macos_leaks(options).is_err());

    let open = Fixture::new();
    fs::set_permissions(&open.raw, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(collect_macos_leaks(open.collect_options()).is_err());
}

struct Fixture {
    root: PathBuf,
    raw: PathBuf,
    raw_digest: PathBuf,
    report: PathBuf,
    report_digest: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let root = std::env::temp_dir().join(format!(
            "edge-macos-leaks-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let fixture = Self {
            raw: root.join("leaks.raw"),
            raw_digest: root.join("leaks.raw.sha256"),
            report: root.join("report.json"),
            report_digest: root.join("report.sha256"),
            root,
        };
        write_owner_only(
            &fixture.raw,
            b"Process 123: 0 leaks for 0 total leaked bytes.\n",
        );
        write_digest(&fixture.raw, &fixture.raw_digest);
        fixture
    }

    fn collect_options(&self) -> MacosLeaksCollectOptions {
        MacosLeaksCollectOptions {
            build_identity: BUILD.to_string(),
            architecture: "arm64".to_string(),
            original_binary_sha256: DIGEST.to_string(),
            signed_binary_sha256: "c".repeat(64),
            config_sha256: "d".repeat(64),
            process_identity_sha256: "e".repeat(64),
            tool_exit_code: 0,
            workload_expected: 1_000,
            workload_succeeded: 1_000,
            workload_failed: 0,
            cleanup_connections: 0,
            cleanup_payload_bytes: 0,
            cleanup_pressure: "normal".to_string(),
            recovery_status: 200,
            raw: self.raw.clone(),
            raw_digest: self.raw_digest.clone(),
            report: self.report.clone(),
            report_digest: self.report_digest.clone(),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_digest(source: &Path, target: &Path) {
    fs::write(
        target,
        format!("{}\n", sha256_hex(&fs::read(source).unwrap())),
    )
    .unwrap();
}

fn write_owner_only(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
