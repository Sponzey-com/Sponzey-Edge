use edge_memory_harness::macos_leaks::{
    evaluate_macos_leaks, parse_leaks_summary, MacosLeaksEvent, MacosLeaksInput,
    MacosLeaksLifecycle, MacosLeaksReport, MacosLeaksState,
};

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn zero_leak_output_builds_canonical_redacted_report() {
    let raw = "Process 123: 192 nodes malloced for 92 KB\nProcess 123: 0 leaks for 0 total leaked bytes.\n";
    let parsed = parse_leaks_summary(raw).expect("strict summary");
    assert_eq!(parsed.leak_count, 0);
    assert_eq!(parsed.leaked_bytes, 0);

    let report = evaluate_macos_leaks(valid_input(parsed)).expect("accepted diagnostic");
    assert_eq!(report.profile_id, "phase011-macos-leaks-v1");
    assert_eq!(report.leak_count, 0);
    assert_eq!(report.leaked_bytes, 0);
    assert_eq!(report.cleanup_pressure, "normal");
    let encoded = report.to_canonical_json().unwrap();
    assert!(!encoded.contains("Process 123"));
    assert_eq!(
        MacosLeaksReport::from_canonical_json(encoded.as_bytes()).unwrap(),
        report
    );
}

#[test]
fn definite_leak_malformed_duplicate_overflow_and_tool_failure_are_rejected() {
    let leaked = parse_leaks_summary("Process 9: 1 leak for 81920 total leaked bytes.\n").unwrap();
    assert!(evaluate_macos_leaks(MacosLeaksInput {
        tool_exit_code: 1,
        ..valid_input(leaked)
    })
    .unwrap_err()
    .to_string()
    .contains("definite leak"));

    for raw in [
        "no summary\n",
        "Process 1: 0 leaks for 0 total leaked bytes.\nProcess 1: 0 leaks for 0 total leaked bytes.\n",
        "Process x: 0 leaks for 0 total leaked bytes.\n",
        "Process 1: 0 leaks for 18446744073709551616 total leaked bytes.\n",
        "leaks[1]: [fatal] Couldn't get task port\nProcess 1: 0 leaks for 0 total leaked bytes.\n",
    ] {
        assert!(parse_leaks_summary(raw).is_err(), "accepted {raw:?}");
    }

    let parsed = parse_leaks_summary("Process 1: 0 leaks for 0 total leaked bytes.\n").unwrap();
    assert!(evaluate_macos_leaks(MacosLeaksInput {
        tool_exit_code: 255,
        ..valid_input(parsed)
    })
    .is_err());
}

#[test]
fn identity_cleanup_and_workload_must_be_exact() {
    let parsed = parse_leaks_summary("Process 1: 0 leaks for 0 total leaked bytes.\n").unwrap();
    let mut stale = valid_input(parsed);
    stale.build_identity = "stale".to_string();
    assert!(evaluate_macos_leaks(stale).is_err());

    let mut dirty = valid_input(parsed);
    dirty.cleanup_connections = 1;
    assert!(evaluate_macos_leaks(dirty).is_err());

    let mut failed = valid_input(parsed);
    failed.workload_failed = 1;
    assert!(evaluate_macos_leaks(failed).is_err());
}

#[test]
fn lifecycle_is_ordered_and_terminal() {
    let mut lifecycle = MacosLeaksLifecycle::new();
    for event in [
        MacosLeaksEvent::InputsVerified,
        MacosLeaksEvent::Parsed,
        MacosLeaksEvent::Validated,
        MacosLeaksEvent::Published,
    ] {
        lifecycle.transition(event).unwrap();
    }
    assert_eq!(lifecycle.state(), MacosLeaksState::Published);
    assert!(lifecycle.transition(MacosLeaksEvent::Fail).is_err());

    let mut invalid = MacosLeaksLifecycle::new();
    assert!(invalid.transition(MacosLeaksEvent::Published).is_err());
    assert_eq!(invalid.state(), MacosLeaksState::Failed);
}

fn valid_input(summary: edge_memory_harness::macos_leaks::LeaksSummary) -> MacosLeaksInput {
    MacosLeaksInput {
        build_identity: BUILD.to_string(),
        architecture: "arm64".to_string(),
        original_binary_sha256: DIGEST.to_string(),
        signed_binary_sha256: "c".repeat(64),
        config_sha256: "d".repeat(64),
        process_identity_sha256: "e".repeat(64),
        raw_sha256: "f".repeat(64),
        tool_exit_code: 0,
        workload_expected: 1_000,
        workload_succeeded: 1_000,
        workload_failed: 0,
        cleanup_connections: 0,
        cleanup_payload_bytes: 0,
        cleanup_pressure: "normal".to_string(),
        recovery_status: 200,
        summary,
    }
}
