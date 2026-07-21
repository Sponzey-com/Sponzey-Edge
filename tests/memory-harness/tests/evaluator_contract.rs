use edge_memory_harness::evaluator::{
    evaluate_scenario, AcceptanceFailure, AcceptancePolicy, AcceptanceResult, ScenarioObservation,
};

const MIB: u64 = 1024 * 1024;

fn policy() -> AcceptancePolicy {
    AcceptancePolicy::new(128 * MIB, 100).unwrap()
}

fn observation() -> ScenarioObservation {
    ScenarioObservation {
        peak_rss_bytes: 128 * MIB,
        cooldown_cycle_medians: vec![100 * MIB, 100 * MIB, 108 * MIB, 116 * MIB, 116 * MIB],
        process_alive: true,
        successful_requests: 100,
        failed_requests: 0,
        active_connections_after_cooldown: 0,
        charged_payload_bytes_after_cooldown: 0,
    }
}

#[test]
fn ceiling_and_plateau_threshold_boundaries_are_inclusive() {
    let accepted = evaluate_scenario(&policy(), &observation());
    assert_eq!(accepted.result, AcceptanceResult::Passed);
    assert_eq!(accepted.plateau_tolerance_bytes, 16 * MIB);
    assert_eq!(accepted.first_cooldown_median_bytes, 100 * MIB);
    assert_eq!(accepted.last_cooldown_median_bytes, 116 * MIB);

    let mut ceiling_exceeded = observation();
    ceiling_exceeded.peak_rss_bytes += 1;
    assert_eq!(
        evaluate_scenario(&policy(), &ceiling_exceeded).result,
        AcceptanceResult::Failed(vec![AcceptanceFailure::AbsoluteCeilingExceeded])
    );

    let mut plateau_exceeded = observation();
    plateau_exceeded.cooldown_cycle_medians[3] += 2;
    plateau_exceeded.cooldown_cycle_medians[4] += 2;
    assert_eq!(
        evaluate_scenario(&policy(), &plateau_exceeded).result,
        AcceptanceResult::Failed(vec![AcceptanceFailure::CooldownPlateauExceeded])
    );
}

#[test]
fn evaluator_rejects_insufficient_cycles_and_checked_overflow() {
    let mut too_short = observation();
    too_short.cooldown_cycle_medians.truncate(4);
    assert_eq!(
        evaluate_scenario(&policy(), &too_short).result,
        AcceptanceResult::Failed(vec![AcceptanceFailure::InsufficientCooldownCycles])
    );

    let mut overflow = observation();
    overflow.cooldown_cycle_medians = vec![u64::MAX, u64::MAX, 1, u64::MAX, u64::MAX];
    assert_eq!(
        evaluate_scenario(&policy(), &overflow).result,
        AcceptanceResult::Failed(vec![AcceptanceFailure::ArithmeticOverflow])
    );
    assert!(AcceptancePolicy::new(0, 0).is_err());
    assert!(AcceptancePolicy::new(1, 0).is_ok());
}

#[test]
fn correctness_and_cleanup_failures_cannot_be_hidden_by_low_rss() {
    let mut failed = observation();
    failed.peak_rss_bytes = 1;
    failed.cooldown_cycle_medians = vec![1; 5];
    failed.process_alive = false;
    failed.successful_requests = 98;
    failed.failed_requests = 1;
    failed.active_connections_after_cooldown = 2;
    failed.charged_payload_bytes_after_cooldown = 4_096;

    assert_eq!(
        evaluate_scenario(&policy(), &failed).result,
        AcceptanceResult::Failed(vec![
            AcceptanceFailure::ProcessNotAlive,
            AcceptanceFailure::RequestCountMismatch,
            AcceptanceFailure::RequestsFailed,
            AcceptanceFailure::ActiveConnectionsRemain,
            AcceptanceFailure::PayloadChargesRemain,
        ])
    );
}
