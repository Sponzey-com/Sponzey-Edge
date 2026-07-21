use edge_memory_harness::private_https::{
    parse_private_https_options, PrivateHttpsScenario, PrivateHttpsState,
};

#[test]
fn exact_success_negative_and_cleanup_sequence_is_accepted() {
    let mut scenario = PrivateHttpsScenario::new(100, 2).unwrap();
    scenario.observe_load(100, 0).unwrap();
    scenario.observe_negatives(2, 0).unwrap();
    let result = scenario.observe_recovery(0, 0, "normal", 200).unwrap();
    assert_eq!(scenario.state(), PrivateHttpsState::Recovered);
    assert_eq!(result.succeeded, 100);
    assert_eq!(result.rejected_negatives, 2);
}

#[test]
fn partial_fail_open_dirty_cleanup_and_duplicate_transition_fail_closed() {
    let mut partial = PrivateHttpsScenario::new(100, 2).unwrap();
    assert!(partial.observe_load(99, 1).is_err());
    assert_eq!(partial.state(), PrivateHttpsState::Failed);

    let mut fail_open = loaded();
    assert!(fail_open.observe_negatives(1, 1).is_err());

    let mut dirty = negative_verified();
    assert!(dirty.observe_recovery(0, 1, "normal", 200).is_err());

    let mut duplicate = negative_verified();
    duplicate.observe_recovery(0, 0, "normal", 200).unwrap();
    assert!(duplicate.observe_recovery(0, 0, "normal", 200).is_err());
}

#[test]
fn strict_cli_rejects_missing_duplicate_unknown_and_zero_values() {
    let valid = valid_args();
    assert_eq!(parse_private_https_options(&valid).unwrap().expected, 100);

    let mut missing = valid.clone();
    missing.truncate(missing.len() - 2);
    assert!(parse_private_https_options(&missing).is_err());

    let mut duplicate = valid.clone();
    duplicate.extend(["--succeeded".to_string(), "100".to_string()]);
    assert!(parse_private_https_options(&duplicate).is_err());

    let mut unknown = valid.clone();
    unknown.extend(["--unknown".to_string(), "x".to_string()]);
    assert!(parse_private_https_options(&unknown).is_err());

    let mut zero = valid;
    zero[1] = "0".to_string();
    assert!(parse_private_https_options(&zero).is_err());
}

fn loaded() -> PrivateHttpsScenario {
    let mut scenario = PrivateHttpsScenario::new(100, 2).unwrap();
    scenario.observe_load(100, 0).unwrap();
    scenario
}

fn negative_verified() -> PrivateHttpsScenario {
    let mut scenario = loaded();
    scenario.observe_negatives(2, 0).unwrap();
    scenario
}

fn valid_args() -> Vec<String> {
    [
        "--expected",
        "100",
        "--succeeded",
        "100",
        "--failed",
        "0",
        "--expected-negatives",
        "2",
        "--rejected-negatives",
        "2",
        "--accepted-negatives",
        "0",
        "--final-connections",
        "0",
        "--final-payload",
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
