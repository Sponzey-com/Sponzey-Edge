use edge_memory_harness::diagnostic_soak::{
    evaluate_diagnostic_soak, DiagnosticSoakObservation, SoakWorkload, SOAK_OBSERVATION_COUNT,
};
use edge_memory_harness::full_profile_readiness::{
    evaluate_full_profile, FullProfileEntry, FullProfileInput, FULL_PROFILE_SCENARIOS,
};
use edge_memory_harness::phase011_memory_release::{
    evaluate_phase011_memory_release, MemoryReleaseEvent, MemoryReleaseInput,
    MemoryReleaseLifecycle, MemoryReleaseState, Phase011MemoryReleaseReport,
    PHASE011_MEMORY_RELEASE_MARKER,
};

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[test]
fn release_binding_accepts_exact_full_profile_and_soak_and_roundtrips_canonically() {
    let input = valid_input();

    let report = evaluate_phase011_memory_release(input).expect("valid release binding");

    assert_eq!(report.schema_version, 1);
    assert_eq!(report.profile_id, "phase011-memory-release-v1");
    assert_eq!(report.build_identity, BUILD);
    assert_eq!(report.platform, "macos");
    assert_eq!(report.architecture, "arm64");
    assert_eq!(report.full_profile_scenarios, 12);
    assert_eq!(report.soak_observations, 121);
    assert_eq!(report.marker, PHASE011_MEMORY_RELEASE_MARKER);
    let encoded = report.to_canonical_json().expect("canonical report");
    assert_eq!(
        Phase011MemoryReleaseReport::from_canonical_json(encoded.as_bytes()).unwrap(),
        report
    );
}

#[test]
fn release_binding_rejects_stale_non_ready_or_wrong_platform_evidence() {
    let mut stale = valid_input();
    stale.soak.build_identity =
        "source-tree-sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            .to_string();
    assert!(evaluate_phase011_memory_release(stale)
        .unwrap_err()
        .to_string()
        .contains("source identity"));

    let mut non_ready = valid_input();
    non_ready.readiness.ready = false;
    assert!(evaluate_phase011_memory_release(non_ready).is_err());

    let mut wrong_platform = valid_input();
    wrong_platform.expected_platform = "linux".to_string();
    assert!(evaluate_phase011_memory_release(wrong_platform).is_err());
}

#[test]
fn release_binding_rejects_invalid_digest_and_noncanonical_report() {
    let mut input = valid_input();
    input.soak_sha256 = "not-a-digest".to_string();
    assert!(evaluate_phase011_memory_release(input).is_err());

    let report = evaluate_phase011_memory_release(valid_input()).unwrap();
    let mut encoded = report.to_canonical_json().unwrap().into_bytes();
    encoded.extend_from_slice(b"\n");
    assert!(Phase011MemoryReleaseReport::from_canonical_json(&encoded).is_err());
}

#[test]
fn release_binding_revalidates_profile_completeness_and_soak_safety() {
    let mut blocked = valid_input();
    blocked.readiness.blockers.push("missing:idle".to_string());
    blocked.readiness.ready = false;
    assert!(evaluate_phase011_memory_release(blocked).is_err());

    let mut missing_scenario = valid_input();
    missing_scenario.inventory.entries.pop();
    assert!(evaluate_phase011_memory_release(missing_scenario).is_err());

    let mut short = valid_input();
    short.soak.duration_seconds -= 60;
    assert!(evaluate_phase011_memory_release(short).is_err());

    let mut over_ceiling = valid_input();
    over_ceiling.soak.peak_rss_bytes = over_ceiling.soak.rss_ceiling_bytes + 1;
    assert!(evaluate_phase011_memory_release(over_ceiling).is_err());

    let mut incorrect = valid_input();
    incorrect.soak.correctness_failures = 1;
    assert!(evaluate_phase011_memory_release(incorrect).is_err());

    let mut leaked = valid_input();
    leaked.soak.cleanup_failures = 1;
    assert!(evaluate_phase011_memory_release(leaked).is_err());
}

#[test]
fn release_binding_lifecycle_is_ordered_and_terminal() {
    let mut lifecycle = MemoryReleaseLifecycle::new();
    assert_eq!(lifecycle.state(), MemoryReleaseState::Created);
    lifecycle
        .transition(MemoryReleaseEvent::InputsVerified)
        .unwrap();
    lifecycle
        .transition(MemoryReleaseEvent::ReportsValidated)
        .unwrap();
    lifecycle.transition(MemoryReleaseEvent::Bound).unwrap();
    lifecycle.transition(MemoryReleaseEvent::Published).unwrap();
    assert_eq!(lifecycle.state(), MemoryReleaseState::Published);
    assert!(lifecycle.transition(MemoryReleaseEvent::Fail).is_err());

    let mut invalid = MemoryReleaseLifecycle::new();
    assert!(invalid.transition(MemoryReleaseEvent::Published).is_err());
    assert_eq!(invalid.state(), MemoryReleaseState::Failed);
}

fn valid_input() -> MemoryReleaseInput {
    let full_profile = FullProfileInput {
        current_build_identity: BUILD.to_string(),
        platform: "macos".to_string(),
        architecture: "arm64".to_string(),
        entries: FULL_PROFILE_SCENARIOS
            .iter()
            .map(|contract| FullProfileEntry {
                scenario_id: contract.scenario_id.to_string(),
                evidence_kind: contract.evidence_kind,
                build_identity: BUILD.to_string(),
                report_sha256: DIGEST_A.to_string(),
                validation_passed: true,
            })
            .collect(),
    };
    let readiness = evaluate_full_profile(full_profile.clone()).unwrap();
    let soak = evaluate_diagnostic_soak(
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
                    config_sha256: DIGEST_B.to_string(),
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
    .unwrap();
    MemoryReleaseInput {
        expected_build_identity: BUILD.to_string(),
        expected_platform: "macos".to_string(),
        expected_architecture: "arm64".to_string(),
        inventory: full_profile,
        inventory_sha256: DIGEST_A.to_string(),
        readiness,
        readiness_sha256: DIGEST_B.to_string(),
        soak,
        soak_sha256: DIGEST_C.to_string(),
    }
}
