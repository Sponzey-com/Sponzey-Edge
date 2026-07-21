use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use crate::HarnessError;

pub(crate) fn connect_with_deadline(
    address: SocketAddr,
    timeout: Duration,
    failure_message: &str,
) -> Result<TcpStream, HarnessError> {
    let started_at = Instant::now();
    let attempt_timeout = timeout.min(Duration::from_millis(250));
    loop {
        match TcpStream::connect_timeout(&address, attempt_timeout) {
            Ok(stream) => return Ok(stream),
            Err(_) if started_at.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(HarnessError::new(format!("{failure_message}: {error}"))),
        }
    }
}
