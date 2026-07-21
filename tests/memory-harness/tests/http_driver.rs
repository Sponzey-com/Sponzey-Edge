use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use edge_memory_harness::http_driver::{
    parse_runtime_resource_status, HttpLoadDriver, HttpLoadSpec, HttpScenarioPhase, RuntimePressure,
};

const LOOPBACK_FIXTURE_TIMEOUT: Duration = Duration::from_secs(30);

#[test]
fn bounded_churn_driver_preserves_expected_success_failure_counts() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = serve_responses(
        listener,
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".to_vec(); 3],
    );
    let spec = HttpLoadSpec::new(address, "localhost", 3, LOOPBACK_FIXTURE_TIMEOUT, 1024).unwrap();
    let mut driver = HttpLoadDriver::new(spec);

    driver.warm().unwrap();
    let counters = driver.load().unwrap();
    driver.cool().unwrap();

    assert_eq!(counters.expected, 3);
    assert_eq!(counters.succeeded, 3);
    assert_eq!(counters.failed, 0);
    assert_eq!(driver.phase(), HttpScenarioPhase::Completed);
    assert_eq!(server.join().unwrap(), 3);
}

#[test]
fn malformed_and_oversized_responses_are_counted_as_failures() {
    for response in [
        b"not-http".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nsmall".to_vec(),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}",
            "x".repeat(100)
        )
        .into_bytes(),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = serve_responses(listener, vec![response]);
        let spec =
            HttpLoadSpec::new(address, "localhost", 1, LOOPBACK_FIXTURE_TIMEOUT, 64).unwrap();
        let mut driver = HttpLoadDriver::new(spec);
        driver.warm().unwrap();
        let counters = driver.load().unwrap();
        assert_eq!(counters.succeeded, 0);
        assert_eq!(counters.failed, 1);
        assert_eq!(server.join().unwrap(), 1);
    }
    assert!(HttpLoadSpec::new(
        "127.0.0.1:1".parse().unwrap(),
        "",
        1,
        Duration::from_secs(1),
        1
    )
    .is_err());
}

#[test]
fn out_of_order_phase_transitions_fail_closed() {
    let spec = HttpLoadSpec::new(
        "127.0.0.1:1".parse().unwrap(),
        "localhost",
        1,
        Duration::from_secs(1),
        64,
    )
    .unwrap();
    let mut driver = HttpLoadDriver::new(spec);

    assert!(driver.load().is_err());
    assert_eq!(driver.phase(), HttpScenarioPhase::Failed);
    assert!(driver.warm().is_err());
    assert_eq!(driver.phase(), HttpScenarioPhase::Failed);
}

#[test]
fn runtime_status_parser_requires_live_matching_revision_and_closed_pressure() {
    let json = br#"{
      "active_revision_id":"rev-active",
      "live_resource_status":{
        "revision_id":"rev-active",
        "generation":7,
        "used_payload_bytes":0,
        "payload_limit_bytes":134217728,
        "active_connections":0,
        "pressure":"normal"
      }
    }"#;
    let status = parse_runtime_resource_status(json, "rev-active").unwrap();
    assert_eq!(status.active_connections, 0);
    assert_eq!(status.used_payload_bytes, 0);
    assert_eq!(status.pressure, RuntimePressure::Normal);

    let unavailable = br#"{"active_revision_id":"rev-active","live_resource_status":null}"#;
    assert!(parse_runtime_resource_status(unavailable, "rev-active").is_err());
    assert!(parse_runtime_resource_status(json, "rev-stale").is_err());
    let unknown = String::from_utf8(json.to_vec())
        .unwrap()
        .replace("\"normal\"", "\"unknown\"");
    assert!(parse_runtime_resource_status(unknown.as_bytes(), "rev-active").is_err());
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
            Err(error) => panic!("loopback request read failed: {error}"),
        };
        if read == 0 {
            break;
        }
        request.push(byte[0]);
    }
    request.ends_with(b"\r\n\r\n")
}

fn serve_responses(listener: TcpListener, responses: Vec<Vec<u8>>) -> thread::JoinHandle<usize> {
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + LOOPBACK_FIXTURE_TIMEOUT;
        let mut served = 0;
        while served < responses.len() && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(LOOPBACK_FIXTURE_TIMEOUT))
                        .unwrap();
                    if read_request_headers(&mut stream) {
                        stream.write_all(&responses[served]).unwrap();
                        served += 1;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("loopback accept failed: {error}"),
            }
        }
        served
    })
}
