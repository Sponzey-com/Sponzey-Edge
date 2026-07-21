use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::thread;
use std::time::{Duration, Instant};

use edge_memory_harness::slow_response::{SlowResponseHolder, SlowResponseSpec, SlowResponseState};

const LOOPBACK_FIXTURE_TIMEOUT: Duration = Duration::from_secs(30);

#[test]
fn holder_progressively_opens_response_started_connections_and_releases() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = serve_response_headers(listener, 3, 200);
    let spec = SlowResponseSpec::new(
        address,
        "localhost",
        3,
        LOOPBACK_FIXTURE_TIMEOUT,
        8192,
        4096,
    )
    .unwrap();
    let mut holder = SlowResponseHolder::new(spec);

    holder.ramp_to(1).unwrap();
    holder.ramp_to(3).unwrap();

    assert_eq!(holder.state(), SlowResponseState::Holding);
    assert_eq!(holder.held_count(), 3);
    assert_eq!(server.join().unwrap(), 3);
    assert_eq!(holder.release().unwrap(), 3);
    assert_eq!(holder.state(), SlowResponseState::Completed);
    assert_eq!(holder.held_count(), 0);
}

#[test]
fn holder_rejects_wrong_status_over_limit_and_duplicate_release() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = serve_response_headers(listener, 1, 503);
    let mut holder = SlowResponseHolder::new(
        SlowResponseSpec::new(
            address,
            "localhost",
            1,
            LOOPBACK_FIXTURE_TIMEOUT,
            8192,
            4096,
        )
        .unwrap(),
    );

    assert!(holder.ramp_to(1).is_err());
    assert_eq!(holder.state(), SlowResponseState::Failed);
    assert_eq!(holder.held_count(), 0);
    assert_eq!(server.join().unwrap(), 1);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut holder = SlowResponseHolder::new(
        SlowResponseSpec::new(
            address,
            "localhost",
            1,
            LOOPBACK_FIXTURE_TIMEOUT,
            8192,
            4096,
        )
        .unwrap(),
    );
    assert!(holder.ramp_to(2).is_err());
    assert!(holder.release().is_err());
    assert_eq!(holder.state(), SlowResponseState::Failed);
}

fn serve_response_headers(
    listener: TcpListener,
    expected: usize,
    status: u16,
) -> thread::JoinHandle<usize> {
    thread::spawn(move || {
        let mut served = 0;
        let deadline = Instant::now() + LOOPBACK_FIXTURE_TIMEOUT;
        while served < expected && Instant::now() < deadline {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 128];
            while !request.ends_with(b"\r\n\r\n") && request.len() < 1024 {
                let read = stream.read(&mut chunk).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            if !request.ends_with(b"\r\n\r\n") {
                continue;
            }
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
            let _ = stream.shutdown(Shutdown::Write);
            served += 1;
        }
        served
    })
}
