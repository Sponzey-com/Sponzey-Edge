use edge_memory_harness::full_profile_readiness::{
    evaluate_full_profile, EvidenceKind, FullProfileEntry, FullProfileInput,
    FullProfileReadinessReport, ScenarioReadiness, FULL_PROFILE_SCENARIOS,
};

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn exact_allowlist_and_all_current_verified_entries_are_ready() {
    assert_eq!(FULL_PROFILE_SCENARIOS.len(), 12);
    let report = evaluate_full_profile(input(all_entries())).unwrap();

    assert!(report.ready);
    assert!(report.blockers.is_empty());
    assert!(report
        .scenarios
        .iter()
        .all(|scenario| scenario.readiness == ScenarioReadiness::Verified));
    let canonical = report.to_canonical_json().unwrap();
    assert_eq!(
        FullProfileReadinessReport::from_canonical_json(canonical.as_bytes()).unwrap(),
        report
    );
}

#[test]
fn missing_stale_failed_and_wrong_kind_are_partial_with_ordered_blockers() {
    let mut entries = all_entries();
    entries.retain(|entry| entry.scenario_id != "idle");
    entries
        .iter_mut()
        .find(|entry| entry.scenario_id == "http-steady")
        .unwrap()
        .build_identity = format!("source-tree-sha256:{}", "b".repeat(64));
    entries
        .iter_mut()
        .find(|entry| entry.scenario_id == "http-idle-1024")
        .unwrap()
        .validation_passed = false;
    entries
        .iter_mut()
        .find(|entry| entry.scenario_id == "slow-header")
        .unwrap()
        .evidence_kind = EvidenceKind::SingleRun;

    let report = evaluate_full_profile(input(entries)).unwrap();
    assert!(!report.ready);
    assert_eq!(
        report
            .scenarios
            .iter()
            .take(4)
            .map(|entry| entry.readiness)
            .collect::<Vec<_>>(),
        vec![
            ScenarioReadiness::Missing,
            ScenarioReadiness::Stale,
            ScenarioReadiness::Failed,
            ScenarioReadiness::Failed,
        ]
    );
    assert_eq!(report.blockers.len(), 4);
}

#[test]
fn duplicate_unknown_invalid_identity_and_digest_fail_input() {
    let mut entries = all_entries();
    entries.push(entries[0].clone());
    assert!(evaluate_full_profile(input(entries)).is_err());

    let mut entries = all_entries();
    entries[0].scenario_id = "unknown".to_string();
    assert!(evaluate_full_profile(input(entries)).is_err());

    let mut invalid = input(all_entries());
    invalid.current_build_identity = "invalid".to_string();
    assert!(evaluate_full_profile(invalid).is_err());

    let mut entries = all_entries();
    entries[0].report_sha256 = "bad".to_string();
    assert!(evaluate_full_profile(input(entries)).is_err());
}

fn input(entries: Vec<FullProfileEntry>) -> FullProfileInput {
    FullProfileInput {
        current_build_identity: BUILD.to_string(),
        platform: "macos".to_string(),
        architecture: "aarch64".to_string(),
        entries,
    }
}

fn all_entries() -> Vec<FullProfileEntry> {
    FULL_PROFILE_SCENARIOS
        .iter()
        .map(|contract| FullProfileEntry {
            scenario_id: contract.scenario_id.to_string(),
            evidence_kind: contract.evidence_kind,
            build_identity: BUILD.to_string(),
            report_sha256: "c".repeat(64),
            validation_passed: true,
        })
        .collect()
}
