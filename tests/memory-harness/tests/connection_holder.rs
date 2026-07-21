use std::io::{ErrorKind, Read};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use edge_memory_harness::connection_holder::{
    parse_connection_holder_options, ConnectionHolder, ConnectionHolderSpec, ConnectionHolderState,
};

const LOOPBACK_FIXTURE_TIMEOUT: Duration = Duration::from_secs(30);

#[test]
fn bounded_holder_ramps_holds_and_releases_exact_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = accept_incomplete_connections(listener, 3);
    let spec = ConnectionHolderSpec::new(address, 3, LOOPBACK_FIXTURE_TIMEOUT).unwrap();
    let mut holder = ConnectionHolder::new(spec);

    holder.ramp_to(1).unwrap();
    assert_eq!(holder.held_count(), 1);
    holder.ramp_to(3).unwrap();
    assert_eq!(holder.state(), ConnectionHolderState::Held);
    assert_eq!(holder.held_count(), 3);
    assert_eq!(server.join().unwrap(), 3);

    holder.release().unwrap();
    assert_eq!(holder.state(), ConnectionHolderState::Released);
    assert_eq!(holder.held_count(), 0);
}

#[test]
fn holder_rejects_decreasing_over_limit_and_duplicate_release() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let spec = ConnectionHolderSpec::new(address, 2, LOOPBACK_FIXTURE_TIMEOUT).unwrap();
    let mut holder = ConnectionHolder::new(spec);

    assert!(holder.release().is_err());
    assert_eq!(holder.state(), ConnectionHolderState::Failed);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server2 = accept_incomplete_connections(listener, 2);
    let mut holder = ConnectionHolder::new(
        ConnectionHolderSpec::new(address, 2, LOOPBACK_FIXTURE_TIMEOUT).unwrap(),
    );
    holder.ramp_to(2).unwrap();
    assert!(holder.ramp_to(1).is_err());
    assert_eq!(holder.state(), ConnectionHolderState::Failed);
    assert_eq!(holder.held_count(), 0);
    assert_eq!(server2.join().unwrap(), 2);
}

#[test]
fn holder_cli_rejects_missing_duplicate_unknown_and_zero_values() {
    let valid = valid_args();
    let parsed = parse_connection_holder_options(&valid).unwrap();
    assert_eq!(parsed.connection_count, 1024);

    let mut missing = valid.clone();
    missing.truncate(missing.len() - 2);
    assert!(parse_connection_holder_options(&missing).is_err());

    let mut duplicate = valid.clone();
    duplicate.extend(["--connections".to_string(), "2".to_string()]);
    assert!(parse_connection_holder_options(&duplicate).is_err());

    let mut unknown = valid.clone();
    unknown.extend(["--unknown".to_string(), "x".to_string()]);
    assert!(parse_connection_holder_options(&unknown).is_err());

    let mut zero = valid;
    let index = zero
        .iter()
        .position(|value| value == "--connections")
        .unwrap()
        + 1;
    zero[index] = "0".to_string();
    assert!(parse_connection_holder_options(&zero).is_err());
}

fn accept_incomplete_connections(
    listener: TcpListener,
    expected: usize,
) -> thread::JoinHandle<usize> {
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + LOOPBACK_FIXTURE_TIMEOUT;
        let mut streams = Vec::new();
        while streams.len() < expected && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_millis(500)))
                        .unwrap();
                    let mut byte = [0_u8; 1];
                    match stream.read(&mut byte) {
                        Ok(1) if byte[0] == b'G' => streams.push(stream),
                        Ok(_) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                ErrorKind::WouldBlock | ErrorKind::TimedOut
                            ) => {}
                        Err(error) => panic!("holder fixture read failed: {error}"),
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("holder fixture accept failed: {error}"),
            }
        }
        streams.len()
    })
}

fn valid_args() -> Vec<String> {
    [
        "--address",
        "127.0.0.1:8080",
        "--connections",
        "1024",
        "--timeout-ms",
        "5000",
        "--hold-timeout-ms",
        "60000",
        "--ready-output",
        "ready.txt",
        "--stop-file",
        "stop",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
