use edge_memory_harness::tls_connection_holder::{
    parse_tls_holder_options, TlsHolderLifecycle, TlsHolderState,
};

#[test]
fn progressive_tls_holder_reaches_512_and_releases_exactly() {
    let mut lifecycle = TlsHolderLifecycle::new(512).unwrap();
    for target in [64, 128, 256, 512] {
        lifecycle.ramp_completed(target).unwrap();
    }
    assert_eq!(lifecycle.state(), TlsHolderState::Holding);
    assert_eq!(lifecycle.held_count(), 512);
    assert_eq!(lifecycle.release().unwrap(), 512);
    assert_eq!(lifecycle.state(), TlsHolderState::Completed);
}

#[test]
fn decreasing_partial_over_limit_and_duplicate_release_fail_closed() {
    let mut decreasing = TlsHolderLifecycle::new(512).unwrap();
    decreasing.ramp_completed(64).unwrap();
    assert!(decreasing.ramp_completed(32).is_err());

    let mut partial = TlsHolderLifecycle::new(512).unwrap();
    assert!(partial.ramp_result(64, 63).is_err());

    let mut over = TlsHolderLifecycle::new(512).unwrap();
    assert!(over.ramp_completed(513).is_err());

    let mut duplicate = TlsHolderLifecycle::new(64).unwrap();
    duplicate.ramp_completed(64).unwrap();
    duplicate.release().unwrap();
    assert!(duplicate.release().is_err());
    assert_eq!(duplicate.state(), TlsHolderState::Failed);
}

#[test]
fn strict_cli_rejects_missing_duplicate_unknown_and_zero_values() {
    let valid = valid_args();
    assert_eq!(parse_tls_holder_options(&valid).unwrap().connections, 512);

    let mut missing = valid.clone();
    missing.truncate(missing.len() - 2);
    assert!(parse_tls_holder_options(&missing).is_err());

    let mut duplicate = valid.clone();
    duplicate.extend(["--connections".to_string(), "1".to_string()]);
    assert!(parse_tls_holder_options(&duplicate).is_err());

    let mut unknown = valid.clone();
    unknown.extend(["--unknown".to_string(), "x".to_string()]);
    assert!(parse_tls_holder_options(&unknown).is_err());

    let mut zero = valid;
    zero[3] = "0".to_string();
    assert!(parse_tls_holder_options(&zero).is_err());
}

fn valid_args() -> Vec<String> {
    [
        "--address",
        "127.0.0.1:8443",
        "--connections",
        "512",
        "--server-name",
        "localhost",
        "--root-pem",
        "root.pem",
        "--timeout-ms",
        "5000",
        "--hold-timeout-ms",
        "60000",
        "--ready-output",
        "ready.txt",
        "--stop-file",
        "stop.txt",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
