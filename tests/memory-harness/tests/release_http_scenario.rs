use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use edge_memory_harness::evaluator::AcceptanceResult;
use edge_memory_harness::http_driver::{
    HttpLoadCounters, RuntimePressure, RuntimeResourceObservation,
};
use edge_memory_harness::release_http_cli::parse_release_http_options;
use edge_memory_harness::release_http_scenario::{
    AdminStatusHttpProbe, DelayPort, HttpLoadPort, ProcessObservationPort,
    ReleaseHttpScenarioRunner, ReleaseHttpScenarioSpec, ReleaseScenarioOutcome, RuntimeStatusPort,
};
use edge_memory_harness::HarnessError;

const LOOPBACK_FIXTURE_TIMEOUT: Duration = Duration::from_secs(30);

#[test]
fn admin_status_probe_accepts_only_bounded_matching_live_status() {
    let body = br#"{"active_revision_id":"rev-1","live_resource_status":{"revision_id":"rev-1","generation":2,"used_payload_bytes":0,"payload_limit_bytes":134217728,"active_connections":0,"pressure":"normal"}}"#;
    let address = serve_once(http_response(body));
    let mut probe = AdminStatusHttpProbe::new(address, LOOPBACK_FIXTURE_TIMEOUT, 1024).unwrap();

    let status = probe.observe("rev-1").unwrap();

    assert_eq!(status.revision_id, "rev-1");
    assert_eq!(status.active_connections, 0);
    assert_eq!(status.used_payload_bytes, 0);
    assert_eq!(status.pressure, RuntimePressure::Normal);

    for response in [
        b"not-http".to_vec(),
        http_response(&vec![b'x'; 1024]),
        http_response(br#"{"active_revision_id":"stale","live_resource_status":null}"#),
    ] {
        let address = serve_once(response);
        let mut probe = AdminStatusHttpProbe::new(address, LOOPBACK_FIXTURE_TIMEOUT, 256).unwrap();
        assert!(probe.observe("rev-1").is_err());
    }
}

#[test]
fn runner_combines_request_rss_and_cleanup_into_acceptance() {
    let process = FakeProcess {
        rss: VecDeque::from(vec![10, 20, 18, 17, 16, 15, 14]),
        identity_matches: true,
    };
    let load = FakeLoad {
        counters: HttpLoadCounters {
            expected: 3,
            succeeded: 3,
            failed: 0,
        },
    };
    let status = FakeStatus(clean_status());
    let delay = FakeDelay { elapsed_ms: 0 };
    let spec = ReleaseHttpScenarioSpec::new("rev-1", 3, 64 * 1024 * 1024, 5, 1).unwrap();
    let mut runner = ReleaseHttpScenarioRunner::new(process, load, status, delay);

    let record = runner.run(&spec);

    assert_eq!(record.outcome, ReleaseScenarioOutcome::Passed);
    assert_eq!(record.counters.unwrap().succeeded, 3);
    assert_eq!(record.samples.len(), 7);
    assert_eq!(record.observation.unwrap().peak_rss_bytes, 20);
    assert!(matches!(
        record.evaluation.unwrap().result,
        AcceptanceResult::Passed
    ));

    let repeated = runner.run(&spec);
    assert_eq!(repeated.outcome, ReleaseScenarioOutcome::InvalidEvidence);
}

#[test]
fn runner_rejects_changed_process_identity_as_invalid_evidence() {
    let process = FakeProcess {
        rss: VecDeque::from(vec![10]),
        identity_matches: false,
    };
    let load = FakeLoad {
        counters: HttpLoadCounters {
            expected: 1,
            succeeded: 1,
            failed: 0,
        },
    };
    let spec = ReleaseHttpScenarioSpec::new("rev-1", 1, 64 * 1024 * 1024, 5, 1).unwrap();
    let mut runner = ReleaseHttpScenarioRunner::new(
        process,
        load,
        FakeStatus(clean_status()),
        FakeDelay { elapsed_ms: 0 },
    );

    let record = runner.run(&spec);

    assert_eq!(record.outcome, ReleaseScenarioOutcome::InvalidEvidence);
    assert!(record.evaluation.is_none());
    assert!(record.observation.is_none());
}

#[test]
fn release_http_cli_rejects_missing_duplicate_unknown_and_zero_values() {
    let valid = valid_cli_args();
    let parsed = parse_release_http_options(&valid).unwrap();
    assert_eq!(parsed.pid, 42);
    assert_eq!(parsed.request_count, 3);
    assert_eq!(parsed.expected_revision, "rev-1");

    let mut missing = valid.clone();
    missing.truncate(missing.len() - 2);
    assert!(parse_release_http_options(&missing).is_err());

    let mut duplicate = valid.clone();
    duplicate.extend(["--pid".to_string(), "43".to_string()]);
    assert!(parse_release_http_options(&duplicate).is_err());

    let mut unknown = valid.clone();
    unknown.extend(["--unknown".to_string(), "value".to_string()]);
    assert!(parse_release_http_options(&unknown).is_err());

    let mut zero = valid;
    let value = zero.iter().position(|value| value == "--requests").unwrap() + 1;
    zero[value] = "0".to_string();
    assert!(parse_release_http_options(&zero).is_err());
}

struct FakeProcess {
    rss: VecDeque<u64>,
    identity_matches: bool,
}

impl ProcessObservationPort for FakeProcess {
    fn is_alive(&mut self) -> Result<bool, HarnessError> {
        Ok(true)
    }

    fn identity_matches(&mut self) -> Result<bool, HarnessError> {
        Ok(self.identity_matches)
    }

    fn sample_rss_bytes(&mut self) -> Result<u64, HarnessError> {
        self.rss
            .pop_front()
            .ok_or_else(|| HarnessError::new("fake RSS exhausted"))
    }
}

struct FakeLoad {
    counters: HttpLoadCounters,
}

impl HttpLoadPort for FakeLoad {
    fn warm(&mut self) -> Result<(), HarnessError> {
        Ok(())
    }

    fn load(&mut self) -> Result<HttpLoadCounters, HarnessError> {
        Ok(self.counters)
    }

    fn cool(&mut self) -> Result<(), HarnessError> {
        Ok(())
    }
}

struct FakeStatus(RuntimeResourceObservation);

impl RuntimeStatusPort for FakeStatus {
    fn observe(
        &mut self,
        _expected_revision: &str,
    ) -> Result<RuntimeResourceObservation, HarnessError> {
        Ok(self.0.clone())
    }
}

struct FakeDelay {
    elapsed_ms: u64,
}

impl DelayPort for FakeDelay {
    fn wait(&mut self, interval_ms: u64) {
        self.elapsed_ms += interval_ms;
    }

    fn elapsed_ms(&mut self) -> u64 {
        self.elapsed_ms
    }
}

fn clean_status() -> RuntimeResourceObservation {
    RuntimeResourceObservation {
        revision_id: "rev-1".to_string(),
        generation: 1,
        used_payload_bytes: 0,
        payload_limit_bytes: 128 * 1024 * 1024,
        active_connections: 0,
        pressure: RuntimePressure::Normal,
    }
}

fn http_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn serve_once(response: Vec<u8>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + LOOPBACK_FIXTURE_TIMEOUT;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_millis(500)))
                        .unwrap();
                    if read_request_headers(&mut stream) {
                        stream.write_all(&response).unwrap();
                        return;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("Admin fixture accept failed: {error}"),
            }
        }
        panic!("no complete request was received");
    });
    address
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
            Err(error) => panic!("Admin fixture request read failed: {error}"),
        };
        if read == 0 {
            break;
        }
        request.push(byte[0]);
    }
    request.ends_with(b"\r\n\r\n")
}

fn valid_cli_args() -> Vec<String> {
    [
        "--pid",
        "42",
        "--proxy-address",
        "127.0.0.1:8080",
        "--admin-address",
        "127.0.0.1:8081",
        "--host",
        "localhost",
        "--requests",
        "3",
        "--timeout-ms",
        "5000",
        "--max-response-bytes",
        "4096",
        "--expected-revision",
        "rev-1",
        "--ceiling-bytes",
        "268435456",
        "--cooldown-cycles",
        "5",
        "--cooldown-interval-ms",
        "100",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
