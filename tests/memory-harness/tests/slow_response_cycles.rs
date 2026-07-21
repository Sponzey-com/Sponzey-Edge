use edge_memory_harness::slow_response_cycles::{
    evaluate_slow_response_cycles, SlowResponseCycleObservation, SlowResponseCycleReport,
    SLOW_RESPONSE_CYCLE_COUNT,
};

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROCESS: &str = "macos-lstart:slow-response-process";

#[test]
fn exactly_five_clean_cycles_pass_median_plateau_and_roundtrip() {
    let report = evaluate_slow_response_cycles(cycles([11, 13, 18, 15, 17])).unwrap();

    assert_eq!(report.cycle_count, SLOW_RESPONSE_CYCLE_COUNT);
    assert_eq!(report.first_cooldown_median_rss_bytes, 12);
    assert_eq!(report.last_cooldown_median_rss_bytes, 16);
    assert!(report.plateau_passed);
    let canonical = report.to_canonical_json().unwrap();
    assert_eq!(
        SlowResponseCycleReport::from_canonical_json(canonical.as_bytes()).unwrap(),
        report
    );
}

#[test]
fn count_order_identity_correctness_payload_and_cleanup_fail_closed() {
    assert!(evaluate_slow_response_cycles(cycles([1, 1, 1, 1])).is_err());

    let mut invalid = cycles([1, 1, 1, 1, 1]);
    invalid[2].cycle_index = 4;
    assert!(evaluate_slow_response_cycles(invalid).is_err());

    let mut invalid = cycles([1, 1, 1, 1, 1]);
    invalid[2].process_start_identity = "macos-lstart:other".to_string();
    assert!(evaluate_slow_response_cycles(invalid).is_err());

    let mut invalid = cycles([1, 1, 1, 1, 1]);
    invalid[2].held = 127;
    assert!(evaluate_slow_response_cycles(invalid).is_err());

    let mut invalid = cycles([1, 1, 1, 1, 1]);
    invalid[2].released = 127;
    invalid[2].failed = 1;
    assert!(evaluate_slow_response_cycles(invalid).is_err());

    let mut invalid = cycles([1, 1, 1, 1, 1]);
    invalid[2].held_payload_bytes = 8 * 1024 * 1024 - 1;
    assert!(evaluate_slow_response_cycles(invalid).is_err());

    let mut invalid = cycles([1, 1, 1, 1, 1]);
    invalid[4].cleanup_connections = 1;
    assert!(evaluate_slow_response_cycles(invalid).is_err());
}

#[test]
fn ceiling_and_plateau_threshold_plus_one_fail() {
    let mut invalid = cycles([1, 1, 1, 1, 1]);
    invalid[1].peak_rss_bytes = 512 * 1024 * 1024 + 1;
    assert!(evaluate_slow_response_cycles(invalid).is_err());

    let baseline = 10_000_000;
    let tolerance = 16 * 1024 * 1024;
    assert!(evaluate_slow_response_cycles(cycles([
        baseline,
        baseline,
        baseline,
        baseline + tolerance + 1,
        baseline + tolerance + 1,
    ]))
    .is_err());
    assert!(evaluate_slow_response_cycles(cycles([
        baseline,
        baseline,
        baseline,
        baseline + tolerance,
        baseline + tolerance,
    ]))
    .is_ok());
}

fn cycles<const N: usize>(cooldowns: [u64; N]) -> Vec<SlowResponseCycleObservation> {
    cooldowns
        .into_iter()
        .enumerate()
        .map(|(position, cooldown)| observation(position as u32 + 1, cooldown + 1, cooldown))
        .collect()
}

fn observation(index: u32, peak: u64, cooldown: u64) -> SlowResponseCycleObservation {
    SlowResponseCycleObservation {
        cycle_index: index,
        build_identity: BUILD.to_string(),
        config_sha256: CONFIG.to_string(),
        process_start_identity: PROCESS.to_string(),
        expected: 128,
        held: 128,
        released: 128,
        failed: 0,
        held_payload_bytes: 8 * 1024 * 1024,
        peak_rss_bytes: peak,
        cooldown_rss_bytes: cooldown,
        cleanup_connections: 0,
        cleanup_payload_bytes: 0,
        cleanup_pressure: "normal".to_string(),
        recovery_status: 200,
    }
}
