use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use edge_memory_harness::http_steady::{
    parse_steady_options, SteadyHttpLoadDriver, SteadyLoadSpec, SteadyLoadState,
};

const LOOPBACK_FIXTURE_TIMEOUT: Duration = Duration::from_secs(30);

#[test]
fn driver_distributes_and_aggregates_exact_concurrent_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = serve(listener, 20, 200);
    let spec =
        SteadyLoadSpec::new(address, "localhost", 20, 4, LOOPBACK_FIXTURE_TIMEOUT, 4096).unwrap();
    let mut driver = SteadyHttpLoadDriver::new(spec);

    let counters = driver.run().unwrap();

    assert_eq!(counters.expected, 20);
    assert_eq!(counters.succeeded, 20);
    assert_eq!(counters.failed, 0);
    assert_eq!(driver.state(), SteadyLoadState::Completed);
    assert_eq!(server.join().unwrap(), 20);
    assert!(driver.run().is_err());
}

#[test]
fn invalid_distribution_and_wrong_response_fail_closed() {
    let address = "127.0.0.1:1".parse().unwrap();
    assert!(
        SteadyLoadSpec::new(address, "localhost", 10, 4, Duration::from_secs(1), 4096,).is_err()
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = serve(listener, 2, 503);
    let mut driver = SteadyHttpLoadDriver::new(
        SteadyLoadSpec::new(address, "localhost", 2, 2, LOOPBACK_FIXTURE_TIMEOUT, 4096).unwrap(),
    );

    let counters = driver.run().unwrap();
    assert_eq!(counters.succeeded, 0);
    assert_eq!(counters.failed, 2);
    assert_eq!(driver.state(), SteadyLoadState::Failed);
    assert_eq!(server.join().unwrap(), 2);
}

#[test]
fn strict_cli_rejects_missing_duplicate_unknown_and_zero_values() {
    let valid = strings(&[
        "--address",
        "127.0.0.1:8080",
        "--host",
        "localhost",
        "--requests",
        "100",
        "--workers",
        "10",
        "--timeout-ms",
        "5000",
        "--max-response-bytes",
        "4096",
        "--ready-output",
        "/tmp/ready",
        "--start-file",
        "/tmp/start",
        "--summary-output",
        "/tmp/summary",
        "--start-timeout-ms",
        "30000",
    ]);
    assert!(parse_steady_options(&valid).is_ok());
    assert!(parse_steady_options(&valid[..valid.len() - 2]).is_err());
    let mut duplicate = valid.clone();
    duplicate[2] = "--address".into();
    assert!(parse_steady_options(&duplicate).is_err());
    let mut zero = valid;
    zero[5] = "0".into();
    assert!(parse_steady_options(&zero).is_err());
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn serve(listener: TcpListener, expected: usize, status: u16) -> thread::JoinHandle<usize> {
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut served = 0;
        while served < expected && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(LOOPBACK_FIXTURE_TIMEOUT))
                        .unwrap();
                    if read_request_headers(&mut stream) {
                        let body = b"steady-ok";
                        let mut response = format!(
                            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        response.extend_from_slice(body);
                        stream.write_all(&response).unwrap();
                        served += 1;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("steady fixture accept failed: {error}"),
            }
        }
        served
    })
}

fn read_request_headers(stream: &mut TcpStream) -> bool {
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    while request.len() < 1024 && !request.ends_with(b"\r\n\r\n") {
        let read = match stream.read(&mut byte) {
            Ok(read) => read,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return false;
            }
            Err(error) => panic!("steady fixture request read failed: {error}"),
        };
        if read == 0 {
            break;
        }
        request.push(byte[0]);
    }
    request.ends_with(b"\r\n\r\n")
}
