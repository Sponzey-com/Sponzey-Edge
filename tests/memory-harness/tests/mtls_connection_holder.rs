use edge_memory_harness::mtls_connection_holder::{
    build_mtls_client_config, parse_mtls_holder_options,
};

#[test]
fn strict_mtls_cli_accepts_explicit_client_material() {
    let options = parse_mtls_holder_options(&valid_args()).unwrap();
    assert_eq!(options.connections, 256);
    assert_eq!(options.server_name, "localhost");
    assert_eq!(
        options.client_chain_pem.to_string_lossy(),
        "client-chain.pem"
    );
    assert_eq!(options.client_key_pem.to_string_lossy(), "client-key.pem");
}

#[test]
fn strict_mtls_cli_rejects_missing_duplicate_unknown_and_zero_values() {
    let mut missing = valid_args();
    missing.truncate(missing.len() - 2);
    assert!(parse_mtls_holder_options(&missing).is_err());

    let mut duplicate = valid_args();
    duplicate.extend(["--client-key-pem".to_string(), "other.pem".to_string()]);
    assert!(parse_mtls_holder_options(&duplicate).is_err());

    let mut unknown = valid_args();
    unknown.extend(["--system-trust".to_string(), "true".to_string()]);
    assert!(parse_mtls_holder_options(&unknown).is_err());

    let mut zero = valid_args();
    zero[3] = "0".to_string();
    assert!(parse_mtls_holder_options(&zero).is_err());
}

#[test]
fn malformed_root_chain_and_key_fail_before_socket_effects() {
    assert!(build_mtls_client_config(b"invalid", b"invalid", b"invalid").is_err());
}

fn valid_args() -> Vec<String> {
    [
        "--address",
        "127.0.0.1:8443",
        "--connections",
        "256",
        "--server-name",
        "localhost",
        "--root-pem",
        "root.pem",
        "--client-chain-pem",
        "client-chain.pem",
        "--client-key-pem",
        "client-key.pem",
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
