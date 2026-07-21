use edge_memory_harness::slow_body::{parse_slow_body_options, SlowBodyScenario, SlowBodyState};

#[test]
fn lifecycle_counts_exact_408_terminals() {
    let mut scenario = SlowBodyScenario::new(3, 1024).unwrap();
    scenario.start_opening().unwrap();
    scenario.opened(3).unwrap();
    assert_eq!(scenario.state(), SlowBodyState::Holding);
    scenario.begin_collecting().unwrap();
    for _ in 0..3 {
        scenario.record_response(408, 64).unwrap();
    }
    let result = scenario.finish().unwrap();

    assert_eq!(scenario.state(), SlowBodyState::Completed);
    assert_eq!(result.expected, 3);
    assert_eq!(result.succeeded, 3);
    assert_eq!(result.failed, 0);
}

#[test]
fn partial_open_non_408_oversize_and_duplicate_transitions_fail_closed() {
    let mut partial = SlowBodyScenario::new(2, 1024).unwrap();
    partial.start_opening().unwrap();
    assert!(partial.opened(1).is_err());
    assert_eq!(partial.state(), SlowBodyState::Failed);

    let mut invalid = SlowBodyScenario::new(2, 128).unwrap();
    invalid.start_opening().unwrap();
    invalid.opened(2).unwrap();
    invalid.begin_collecting().unwrap();
    invalid.record_response(408, 64).unwrap();
    invalid.record_response(200, 64).unwrap();
    let result = invalid.finish().unwrap();
    assert_eq!(result.succeeded, 1);
    assert_eq!(result.failed, 1);

    let mut oversize = SlowBodyScenario::new(1, 64).unwrap();
    oversize.start_opening().unwrap();
    oversize.opened(1).unwrap();
    oversize.begin_collecting().unwrap();
    oversize.record_response(408, 65).unwrap();
    assert_eq!(oversize.finish().unwrap().failed, 1);
    assert!(oversize.finish().is_err());
    assert_eq!(oversize.state(), SlowBodyState::Failed);
}

#[test]
fn strict_cli_rejects_missing_duplicate_unknown_zero_and_invalid_body_relation() {
    let valid = valid_args();
    let parsed = parse_slow_body_options(&valid).unwrap();
    assert_eq!(parsed.connections, 32);
    assert_eq!(parsed.declared_body_bytes, 65_536);
    assert_eq!(parsed.sent_body_bytes, 32_768);

    let mut missing = valid.clone();
    missing.truncate(missing.len() - 2);
    assert!(parse_slow_body_options(&missing).is_err());

    let mut duplicate = valid.clone();
    duplicate.extend(["--connections".to_string(), "1".to_string()]);
    assert!(parse_slow_body_options(&duplicate).is_err());

    let mut unknown = valid.clone();
    unknown.extend(["--unknown".to_string(), "x".to_string()]);
    assert!(parse_slow_body_options(&unknown).is_err());

    let mut zero = valid.clone();
    zero[3] = "0".to_string();
    assert!(parse_slow_body_options(&zero).is_err());

    let mut equal = valid.clone();
    equal[5] = "32768".to_string();
    assert!(parse_slow_body_options(&equal).is_err());

    let mut reversed = valid;
    reversed[5] = "1024".to_string();
    assert!(parse_slow_body_options(&reversed).is_err());
}

fn valid_args() -> Vec<String> {
    [
        "--address",
        "127.0.0.1:8080",
        "--connections",
        "32",
        "--declared-body-bytes",
        "65536",
        "--sent-body-bytes",
        "32768",
        "--connect-timeout-ms",
        "5000",
        "--terminal-timeout-ms",
        "40000",
        "--max-response-bytes",
        "4096",
        "--ready-output",
        "ready.txt",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
