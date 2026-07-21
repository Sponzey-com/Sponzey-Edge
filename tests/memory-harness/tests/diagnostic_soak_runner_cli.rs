use edge_memory_harness::diagnostic_soak_runner_cli::parse_diagnostic_soak_runner_options;

#[test]
fn strict_options_accept_only_fixed_runner_inputs() {
    let options = parse_diagnostic_soak_runner_options(&valid_args()).unwrap();
    assert_eq!(options.pid, 42);
    assert_eq!(options.proxy_address.to_string(), "127.0.0.1:8080");
    assert_eq!(options.admin_address.to_string(), "127.0.0.1:8081");
    assert_eq!(options.expected_revision, "bootstrap-seed");
}

#[test]
fn duration_count_unknown_duplicate_and_zero_pid_are_rejected() {
    let mut duration = valid_args();
    duration.extend(["--duration-seconds".to_string(), "1".to_string()]);
    assert!(parse_diagnostic_soak_runner_options(&duration).is_err());

    let mut count = valid_args();
    count.extend(["--websocket-count".to_string(), "1".to_string()]);
    assert!(parse_diagnostic_soak_runner_options(&count).is_err());

    let mut duplicate = valid_args();
    duplicate[2] = "--pid".to_string();
    assert!(parse_diagnostic_soak_runner_options(&duplicate).is_err());

    let mut zero = valid_args();
    zero[1] = "0".to_string();
    assert!(parse_diagnostic_soak_runner_options(&zero).is_err());
}

fn valid_args() -> Vec<String> {
    [
        "--pid",
        "42",
        "--proxy-address",
        "127.0.0.1:8080",
        "--admin-address",
        "127.0.0.1:8081",
        "--host",
        "localhost",
        "--expected-revision",
        "bootstrap-seed",
        "--build-identity",
        "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--config-sha256",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--output",
        "out/report.json",
        "--digest-output",
        "out/report.sha256",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
