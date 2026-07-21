use edge_memory_harness::mtls_steady::{
    build_mtls_steady_client_config, parse_mtls_steady_options,
};

#[test]
fn malformed_material_fails_before_socket_effects() {
    assert!(build_mtls_steady_client_config(b"bad", b"bad", b"bad").is_err());
}

#[test]
fn strict_cli_accepts_explicit_material_and_rejects_invalid_options() {
    let valid = strings(&[
        "--address",
        "127.0.0.1:8443",
        "--host",
        "localhost",
        "--server-name",
        "localhost",
        "--root-pem",
        "root.pem",
        "--client-chain-pem",
        "client.pem",
        "--client-key-pem",
        "client.key",
        "--requests",
        "25000",
        "--workers",
        "64",
        "--timeout-ms",
        "30000",
        "--max-response-bytes",
        "4096",
        "--ready-output",
        "ready",
        "--start-file",
        "start",
        "--summary-output",
        "summary",
        "--start-timeout-ms",
        "30000",
    ]);
    let options = parse_mtls_steady_options(&valid).unwrap();
    assert_eq!((options.requests, options.workers), (25_000, 64));
    assert!(parse_mtls_steady_options(&valid[..valid.len() - 2]).is_err());
    let mut duplicate = valid.clone();
    duplicate[2] = "--address".into();
    assert!(parse_mtls_steady_options(&duplicate).is_err());
    let mut unknown = valid.clone();
    unknown[0] = "--unknown".into();
    assert!(parse_mtls_steady_options(&unknown).is_err());
    let mut zero = valid;
    zero[13] = "0".into();
    assert!(parse_mtls_steady_options(&zero).is_err());
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}
