use edge_memory_harness::payload_pressure::{
    parse_payload_pressure_options, PayloadPressureScenario, PayloadPressureState,
};

#[test]
fn evaluator_accepts_exact_pressure_rejection_and_recovery_sequence() {
    let mut scenario = PayloadPressureScenario::new(13, 16_777_216).unwrap();
    scenario.observe_hold(13, 13_625_000, "pressured").unwrap();
    scenario
        .observe_rejection(13, 1, 1, "payload", "payload_pressure")
        .unwrap();
    let result = scenario.observe_recovery(0, 0, "normal", 200).unwrap();

    assert_eq!(scenario.state(), PayloadPressureState::Recovered);
    assert_eq!(result.held_connections, 13);
    assert_eq!(result.rejection_metric, 1);
    assert_eq!(result.recovery_status, 200);
}

#[test]
fn evaluator_fails_closed_for_invalid_hold_rejection_and_recovery() {
    let mut below = PayloadPressureScenario::new(13, 16_777_216).unwrap();
    assert!(below.observe_hold(13, 13_000_000, "pressured").is_err());
    assert_eq!(below.state(), PayloadPressureState::Failed);

    let mut lost = held_scenario();
    assert!(lost
        .observe_rejection(12, 1, 1, "payload", "payload_pressure")
        .is_err());

    let mut wrong_class = held_scenario();
    assert!(wrong_class
        .observe_rejection(13, 1, 1, "connection", "connection_limit")
        .is_err());

    let mut dirty = rejected_scenario();
    assert!(dirty.observe_recovery(0, 1, "normal", 200).is_err());

    let mut duplicate = rejected_scenario();
    duplicate.observe_recovery(0, 0, "normal", 200).unwrap();
    assert!(duplicate.observe_recovery(0, 0, "normal", 200).is_err());
}

#[test]
fn strict_cli_rejects_missing_duplicate_unknown_and_zero_values() {
    let valid = valid_args();
    let parsed = parse_payload_pressure_options(&valid).unwrap();
    assert_eq!(parsed.expected_connections, 13);
    assert_eq!(parsed.held_payload_bytes, 13_625_000);

    let mut missing = valid.clone();
    missing.truncate(missing.len() - 2);
    assert!(parse_payload_pressure_options(&missing).is_err());

    let mut duplicate = valid.clone();
    duplicate.extend(["--metric-value".to_string(), "1".to_string()]);
    assert!(parse_payload_pressure_options(&duplicate).is_err());

    let mut unknown = valid.clone();
    unknown.extend(["--unknown".to_string(), "x".to_string()]);
    assert!(parse_payload_pressure_options(&unknown).is_err());

    let mut zero = valid;
    zero[3] = "0".to_string();
    assert!(parse_payload_pressure_options(&zero).is_err());
}

fn held_scenario() -> PayloadPressureScenario {
    let mut scenario = PayloadPressureScenario::new(13, 16_777_216).unwrap();
    scenario.observe_hold(13, 13_625_000, "pressured").unwrap();
    scenario
}

fn rejected_scenario() -> PayloadPressureScenario {
    let mut scenario = held_scenario();
    scenario
        .observe_rejection(13, 1, 1, "payload", "payload_pressure")
        .unwrap();
    scenario
}

fn valid_args() -> Vec<String> {
    [
        "--expected-connections",
        "13",
        "--payload-limit-bytes",
        "16777216",
        "--held-connections",
        "13",
        "--held-payload-bytes",
        "13625000",
        "--held-pressure",
        "pressured",
        "--preserved-connections",
        "13",
        "--metric-value",
        "1",
        "--product-events",
        "1",
        "--resource-kind",
        "payload",
        "--reason",
        "payload_pressure",
        "--final-connections",
        "0",
        "--final-payload-bytes",
        "0",
        "--final-pressure",
        "normal",
        "--recovery-status",
        "200",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
