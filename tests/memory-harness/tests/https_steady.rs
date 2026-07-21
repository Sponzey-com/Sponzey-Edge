use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use edge_memory_harness::https_steady::{
    build_https_client_config, parse_https_steady_options, HttpsSteadyDriver, HttpsSteadySpec,
    HttpsSteadyState,
};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

const LOOPBACK_FIXTURE_TIMEOUT: Duration = Duration::from_secs(30);

#[test]
fn trusted_private_pki_driver_aggregates_exact_concurrent_requests() {
    let (root_pem, server_config) = private_pki();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = serve_tls(listener, server_config, 10);
    let config = build_https_client_config(root_pem.as_bytes()).unwrap();
    let spec = HttpsSteadySpec::new(
        address,
        "localhost",
        "localhost",
        10,
        4,
        LOOPBACK_FIXTURE_TIMEOUT,
        4096,
    )
    .unwrap();
    let mut driver = HttpsSteadyDriver::new(spec, config);

    let counters = driver.run().unwrap();

    assert_eq!(
        (counters.expected, counters.succeeded, counters.failed),
        (10, 10, 0)
    );
    assert_eq!(driver.state(), HttpsSteadyState::Completed);
    assert_eq!(server.join().unwrap(), 10);
    assert!(driver.run().is_err());
}

#[test]
fn invalid_distribution_and_root_fail_before_network_effects() {
    assert!(build_https_client_config(b"not a certificate").is_err());
    assert!(HttpsSteadySpec::new(
        "127.0.0.1:1".parse().unwrap(),
        "localhost",
        "localhost",
        3,
        4,
        Duration::from_secs(1),
        4096,
    )
    .is_err());
}

#[test]
fn wrong_root_and_wrong_server_name_are_failed_terminals() {
    let (root_pem, server_config) = private_pki();
    let (wrong_root_pem, _) = private_pki();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = serve_tls(listener, Arc::clone(&server_config), 1);
    let spec = HttpsSteadySpec::new(
        address,
        "localhost",
        "localhost",
        1,
        1,
        LOOPBACK_FIXTURE_TIMEOUT,
        4096,
    )
    .unwrap();
    let mut wrong_root = HttpsSteadyDriver::new(
        spec,
        build_https_client_config(wrong_root_pem.as_bytes()).unwrap(),
    );
    let counters = wrong_root.run().unwrap();
    assert_eq!((counters.succeeded, counters.failed), (0, 1));
    assert_eq!(wrong_root.state(), HttpsSteadyState::Failed);
    assert_eq!(server.join().unwrap(), 0);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = serve_tls(listener, server_config, 1);
    let spec = HttpsSteadySpec::new(
        address,
        "localhost",
        "wrong.localhost",
        1,
        1,
        LOOPBACK_FIXTURE_TIMEOUT,
        4096,
    )
    .unwrap();
    let mut wrong_name = HttpsSteadyDriver::new(
        spec,
        build_https_client_config(root_pem.as_bytes()).unwrap(),
    );
    let counters = wrong_name.run().unwrap();
    assert_eq!((counters.succeeded, counters.failed), (0, 1));
    assert_eq!(wrong_name.state(), HttpsSteadyState::Failed);
    assert_eq!(server.join().unwrap(), 0);
}

#[test]
fn strict_cli_rejects_missing_duplicate_unknown_and_zero_values() {
    let valid = strings(&[
        "--address",
        "127.0.0.1:8443",
        "--host",
        "localhost",
        "--server-name",
        "localhost",
        "--root-pem",
        "root.pem",
        "--requests",
        "100",
        "--workers",
        "10",
        "--timeout-ms",
        "5000",
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
    assert!(parse_https_steady_options(&valid).is_ok());
    assert!(parse_https_steady_options(&valid[..valid.len() - 2]).is_err());
    let mut duplicate = valid.clone();
    duplicate[2] = "--address".into();
    assert!(parse_https_steady_options(&duplicate).is_err());
    let mut unknown = valid.clone();
    unknown[0] = "--unknown".into();
    assert!(parse_https_steady_options(&unknown).is_err());
    let mut zero = valid;
    zero[9] = "0".into();
    assert!(parse_https_steady_options(&zero).is_err());
}

fn private_pki() -> (String, Arc<rustls::ServerConfig>) {
    let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&server_key, &root)
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone(), root.der().clone()],
            rustls_pki_types::PrivateKeyDer::try_from(server_key.serialize_der()).unwrap(),
        )
        .unwrap();
    (root.pem(), Arc::new(config))
}

fn serve_tls(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    expected: usize,
) -> thread::JoinHandle<usize> {
    thread::spawn(move || {
        let mut handles = Vec::with_capacity(expected);
        while handles.len() < expected {
            let (stream, _) = listener.accept().unwrap();
            let config = Arc::clone(&config);
            handles.push(thread::spawn(move || {
                serve_tls_connection(stream, config).unwrap_or(0)
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .sum()
    })
}

fn serve_tls_connection(
    stream: std::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> std::io::Result<usize> {
    let connection = rustls::ServerConnection::new(config)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut stream = rustls::StreamOwned::new(connection, stream);
    let mut request = Vec::new();
    let mut buffer = [0_u8; 512];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(0);
        }
        request.extend_from_slice(&buffer[..read]);
    }
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nsteady-ok")?;
    stream.conn.send_close_notify();
    stream.flush()?;
    Ok(1)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}
