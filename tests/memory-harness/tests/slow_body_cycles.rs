use edge_memory_harness::slow_body_cycles::{
    evaluate_slow_body_cycles, SlowBodyCycleObservation, SlowBodyCycleReport, SLOW_BODY_CYCLE_COUNT,
};

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROCESS: &str = "macos-lstart:cycle-process";

#[test]
fn exactly_five_clean_same_process_cycles_pass_median_plateau() {
    let report = evaluate_slow_body_cycles(cycles([11, 13, 18, 15, 17])).unwrap();

    assert_eq!(report.cycle_count, SLOW_BODY_CYCLE_COUNT);
    assert_eq!(report.first_cooldown_median_rss_bytes, 12);
    assert_eq!(report.last_cooldown_median_rss_bytes, 16);
    assert!(report.plateau_passed);
    assert_eq!(report.correctness_failures, 0);
    assert_eq!(report.cleanup_failures, 0);
    let canonical = report.to_canonical_json().unwrap();
    assert_eq!(
        SlowBodyCycleReport::from_canonical_json(canonical.as_bytes()).unwrap(),
        report
    );
}

#[test]
fn wrong_count_order_identity_correctness_and_cleanup_fail_closed() {
    assert!(evaluate_slow_body_cycles(cycles([1, 1, 1, 1])).is_err());

    let mut out_of_order = cycles([1, 1, 1, 1, 1]);
    out_of_order[2].cycle_index = 4;
    assert!(evaluate_slow_body_cycles(out_of_order).is_err());

    let mut stale = cycles([1, 1, 1, 1, 1]);
    stale[2].process_start_identity = "macos-lstart:other".to_string();
    assert!(evaluate_slow_body_cycles(stale).is_err());

    let mut incorrect = cycles([1, 1, 1, 1, 1]);
    incorrect[2].succeeded = 127;
    incorrect[2].failed = 1;
    assert!(evaluate_slow_body_cycles(incorrect).is_err());

    let mut dirty = cycles([1, 1, 1, 1, 1]);
    dirty[4].cleanup_payload_bytes = 1;
    assert!(evaluate_slow_body_cycles(dirty).is_err());

    let mut undercharged = cycles([1, 1, 1, 1, 1]);
    undercharged[1].held_payload_bytes = 4_194_303;
    assert!(evaluate_slow_body_cycles(undercharged).is_err());
}

#[test]
fn ceiling_and_last_median_threshold_plus_one_fail() {
    let ceiling = 512 * 1024 * 1024;
    let mut over_ceiling = cycles([1, 1, 1, 1, 1]);
    over_ceiling[2].peak_rss_bytes = ceiling + 1;
    assert!(evaluate_slow_body_cycles(over_ceiling).is_err());

    let baseline = 10_000_000;
    let tolerance = 16 * 1024 * 1024;
    let threshold_plus_one = baseline + tolerance + 1;
    assert!(evaluate_slow_body_cycles(cycles([
        baseline,
        baseline,
        baseline,
        threshold_plus_one,
        threshold_plus_one,
    ]))
    .is_err());

    assert!(evaluate_slow_body_cycles(cycles([
        baseline,
        baseline,
        baseline,
        baseline + tolerance,
        baseline + tolerance,
    ]))
    .is_ok());
}

fn cycles<const N: usize>(cooldowns: [u64; N]) -> Vec<SlowBodyCycleObservation> {
    cooldowns
        .into_iter()
        .enumerate()
        .map(|(position, cooldown)| cycle(position as u32 + 1, cooldown + 1, cooldown))
        .collect()
}

fn cycle(index: u32, peak: u64, cooldown: u64) -> SlowBodyCycleObservation {
    SlowBodyCycleObservation {
        cycle_index: index,
        build_identity: BUILD.to_string(),
        config_sha256: CONFIG.to_string(),
        process_start_identity: PROCESS.to_string(),
        expected: 128,
        succeeded: 128,
        failed: 0,
        held_payload_bytes: 4_194_304,
        peak_rss_bytes: peak,
        cooldown_rss_bytes: cooldown,
        cleanup_connections: 0,
        cleanup_payload_bytes: 0,
        cleanup_pressure: "normal".to_string(),
        recovery_status: 200,
    }
}
