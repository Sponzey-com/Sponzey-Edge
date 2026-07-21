use edge_memory_harness::slow_header::{
    parse_slow_header_options, SlowHeaderScenario, SlowHeaderState,
};

#[test]
fn lifecycle_counts_exact_408_terminals() {
    let mut scenario = SlowHeaderScenario::new(3, 1024).unwrap();
    scenario.start_opening().unwrap();
    scenario.opened(3).unwrap();
    assert_eq!(scenario.state(), SlowHeaderState::Holding);
    scenario.begin_collecting().unwrap();
    for _ in 0..3 {
        scenario.record_response(408, 64).unwrap();
    }
    let result = scenario.finish().unwrap();

    assert_eq!(scenario.state(), SlowHeaderState::Completed);
    assert_eq!(result.expected, 3);
    assert_eq!(result.succeeded, 3);
    assert_eq!(result.failed, 0);
}

#[test]
fn partial_open_non_408_oversize_and_duplicate_transitions_fail_closed() {
    let mut partial = SlowHeaderScenario::new(2, 1024).unwrap();
    partial.start_opening().unwrap();
    assert!(partial.opened(1).is_err());
    assert_eq!(partial.state(), SlowHeaderState::Failed);

    let mut invalid = SlowHeaderScenario::new(2, 128).unwrap();
    invalid.start_opening().unwrap();
    invalid.opened(2).unwrap();
    invalid.begin_collecting().unwrap();
    invalid.record_response(408, 64).unwrap();
    invalid.record_response(200, 64).unwrap();
    let result = invalid.finish().unwrap();
    assert_eq!(result.succeeded, 1);
    assert_eq!(result.failed, 1);

    let mut oversize = SlowHeaderScenario::new(1, 64).unwrap();
    oversize.start_opening().unwrap();
    oversize.opened(1).unwrap();
    oversize.begin_collecting().unwrap();
    oversize.record_response(408, 65).unwrap();
    assert_eq!(oversize.finish().unwrap().failed, 1);
    assert!(oversize.finish().is_err());
    assert_eq!(oversize.state(), SlowHeaderState::Failed);
}

#[test]
fn strict_cli_rejects_missing_duplicate_unknown_and_zero_values() {
    let valid = valid_args();
    assert_eq!(parse_slow_header_options(&valid).unwrap().connections, 64);

    let mut missing = valid.clone();
    missing.truncate(missing.len() - 2);
    assert!(parse_slow_header_options(&missing).is_err());

    let mut duplicate = valid.clone();
    duplicate.extend(["--connections".to_string(), "1".to_string()]);
    assert!(parse_slow_header_options(&duplicate).is_err());

    let mut unknown = valid.clone();
    unknown.extend(["--unknown".to_string(), "x".to_string()]);
    assert!(parse_slow_header_options(&unknown).is_err());

    let mut zero = valid;
    zero[3] = "0".to_string();
    assert!(parse_slow_header_options(&zero).is_err());
}

fn valid_args() -> Vec<String> {
    [
        "--address",
        "127.0.0.1:8080",
        "--connections",
        "64",
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
