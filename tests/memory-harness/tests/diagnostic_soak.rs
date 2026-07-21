use edge_memory_harness::diagnostic_soak::{
    evaluate_diagnostic_soak, DiagnosticSoakEvent, DiagnosticSoakLifecycle,
    DiagnosticSoakObservation, DiagnosticSoakReport, DiagnosticSoakState, SoakWorkload,
    SOAK_OBSERVATION_COUNT,
};

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROCESS: &str = "macos-lstart:soak-process";

#[test]
fn exact_two_hour_alternating_clean_observations_pass() {
    let report = evaluate_diagnostic_soak(observations(10_000_000, 20_000_000)).unwrap();
    assert_eq!(report.observation_count, SOAK_OBSERVATION_COUNT);
    assert_eq!(report.duration_seconds, 7_200);
    assert_eq!(report.churn_windows, 60);
    assert_eq!(report.websocket_windows, 60);
    assert_eq!(report.churn_requests, 60_000);
    assert_eq!(report.websocket_lifecycles, 7_680);
    assert!(report.plateau_passed);
    let canonical = report.to_canonical_json().unwrap();
    assert_eq!(
        DiagnosticSoakReport::from_canonical_json(canonical.as_bytes()).unwrap(),
        report
    );
}

#[test]
fn short_reordered_wrong_workload_and_stale_identity_fail() {
    let mut short = observations(10_000_000, 10_000_000);
    short.pop();
    assert!(evaluate_diagnostic_soak(short).is_err());

    let mut reordered = observations(10_000_000, 10_000_000);
    reordered[20].elapsed_seconds += 1;
    assert!(evaluate_diagnostic_soak(reordered).is_err());

    let mut wrong_workload = observations(10_000_000, 10_000_000);
    wrong_workload[2].workload = SoakWorkload::Churn;
    assert!(evaluate_diagnostic_soak(wrong_workload).is_err());

    let mut stale = observations(10_000_000, 10_000_000);
    stale[80].process_start_identity = "macos-lstart:other".to_string();
    assert!(evaluate_diagnostic_soak(stale).is_err());
}

#[test]
fn correctness_cleanup_liveness_and_ceiling_fail_closed() {
    let mut failed = observations(10_000_000, 10_000_000);
    failed[3].failed = 1;
    assert!(evaluate_diagnostic_soak(failed).is_err());

    let mut dirty = observations(10_000_000, 10_000_000);
    dirty[4].cleanup_payload_bytes = 1;
    assert!(evaluate_diagnostic_soak(dirty).is_err());

    let mut dead = observations(10_000_000, 10_000_000);
    dead[5].process_alive = false;
    assert!(evaluate_diagnostic_soak(dead).is_err());

    let mut ceiling = observations(10_000_000, 10_000_000);
    ceiling[6].rss_bytes = 384 * 1024 * 1024 + 1;
    assert!(evaluate_diagnostic_soak(ceiling).is_err());
}

#[test]
fn plateau_threshold_is_inclusive_and_plus_one_fails() {
    let baseline = 10_000_000;
    let tolerance = 16 * 1024 * 1024;
    assert!(evaluate_diagnostic_soak(observations(baseline, baseline + tolerance)).is_ok());
    assert!(evaluate_diagnostic_soak(observations(baseline, baseline + tolerance + 1)).is_err());
}

#[test]
fn lifecycle_requires_all_windows_in_order_before_publish() {
    let mut lifecycle = DiagnosticSoakLifecycle::new();
    lifecycle
        .transition(DiagnosticSoakEvent::CaptureBaseline)
        .unwrap();
    for index in 1..=120 {
        lifecycle
            .transition(DiagnosticSoakEvent::CaptureWindow { index })
            .unwrap();
    }
    assert_eq!(
        lifecycle.state(),
        DiagnosticSoakState::Running {
            completed_windows: 120
        }
    );
    lifecycle
        .transition(DiagnosticSoakEvent::CompleteWindows)
        .unwrap();
    assert_eq!(lifecycle.state(), DiagnosticSoakState::Cooling);
    lifecycle.transition(DiagnosticSoakEvent::Publish).unwrap();
    assert_eq!(lifecycle.state(), DiagnosticSoakState::Published);
    assert!(lifecycle.transition(DiagnosticSoakEvent::Publish).is_err());
}

#[test]
fn lifecycle_fails_closed_on_skipped_or_duplicate_window() {
    let mut skipped = DiagnosticSoakLifecycle::new();
    skipped
        .transition(DiagnosticSoakEvent::CaptureBaseline)
        .unwrap();
    assert!(skipped
        .transition(DiagnosticSoakEvent::CaptureWindow { index: 2 })
        .is_err());
    assert_eq!(skipped.state(), DiagnosticSoakState::Failed);

    let mut duplicate = DiagnosticSoakLifecycle::new();
    duplicate
        .transition(DiagnosticSoakEvent::CaptureBaseline)
        .unwrap();
    duplicate
        .transition(DiagnosticSoakEvent::CaptureWindow { index: 1 })
        .unwrap();
    assert!(duplicate
        .transition(DiagnosticSoakEvent::CaptureWindow { index: 1 })
        .is_err());
    assert_eq!(duplicate.state(), DiagnosticSoakState::Failed);
}

fn observations(first_rss: u64, last_rss: u64) -> Vec<DiagnosticSoakObservation> {
    (0..SOAK_OBSERVATION_COUNT)
        .map(|index| {
            let baseline = index == 0;
            let workload = if baseline {
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
            let rss_bytes = if index < 5 {
                first_rss
            } else if index >= SOAK_OBSERVATION_COUNT - 5 {
                last_rss
            } else {
                first_rss
            };
            DiagnosticSoakObservation {
                index,
                elapsed_seconds: index as u64 * 60,
                workload,
                build_identity: BUILD.to_string(),
                config_sha256: CONFIG.to_string(),
                process_start_identity: PROCESS.to_string(),
                expected,
                succeeded: expected,
                failed: 0,
                process_alive: true,
                rss_bytes,
                cleanup_connections: 0,
                cleanup_payload_bytes: 0,
                cleanup_pressure: "normal".to_string(),
                recovery_status: 200,
            }
        })
        .collect()
}
