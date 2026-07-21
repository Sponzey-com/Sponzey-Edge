use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::bounded_net::connect_with_deadline;
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpLoadSpec {
    address: SocketAddr,
    host: String,
    request_count: u64,
    timeout: Duration,
    max_response_bytes: usize,
}

impl HttpLoadSpec {
    pub fn new(
        address: SocketAddr,
        host: impl Into<String>,
        request_count: usize,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, HarnessError> {
        let host = host.into();
        if host.is_empty() || request_count == 0 || timeout.is_zero() || max_response_bytes == 0 {
            return Err(HarnessError::new("HTTP load specification is invalid"));
        }
        Ok(Self {
            address,
            host,
            request_count: request_count
                .try_into()
                .map_err(|_| HarnessError::new("HTTP request count exceeds u64"))?,
            timeout,
            max_response_bytes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpScenarioPhase {
    Ready,
    Warming,
    Loading,
    Cooling,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpLoadCounters {
    pub expected: u64,
    pub succeeded: u64,
    pub failed: u64,
}

pub struct HttpLoadDriver {
    spec: HttpLoadSpec,
    phase: HttpScenarioPhase,
}

impl HttpLoadDriver {
    pub fn new(spec: HttpLoadSpec) -> Self {
        Self {
            spec,
            phase: HttpScenarioPhase::Ready,
        }
    }

    pub fn phase(&self) -> HttpScenarioPhase {
        self.phase
    }

    pub fn warm(&mut self) -> Result<(), HarnessError> {
        self.transition(HttpScenarioPhase::Ready, HttpScenarioPhase::Warming)
    }

    pub fn load(&mut self) -> Result<HttpLoadCounters, HarnessError> {
        self.transition(HttpScenarioPhase::Warming, HttpScenarioPhase::Loading)?;
        let mut counters = HttpLoadCounters {
            expected: self.spec.request_count,
            succeeded: 0,
            failed: 0,
        };
        for _ in 0..self.spec.request_count {
            if execute_request(&self.spec).is_ok() {
                counters.succeeded += 1;
            } else {
                counters.failed += 1;
            }
        }
        self.phase = HttpScenarioPhase::Cooling;
        Ok(counters)
    }

    pub fn cool(&mut self) -> Result<(), HarnessError> {
        self.transition(HttpScenarioPhase::Cooling, HttpScenarioPhase::Completed)
    }

    fn transition(
        &mut self,
        expected: HttpScenarioPhase,
        next: HttpScenarioPhase,
    ) -> Result<(), HarnessError> {
        if self.phase != expected {
            self.phase = HttpScenarioPhase::Failed;
            return Err(HarnessError::new("HTTP load phase transition is invalid"));
        }
        self.phase = next;
        Ok(())
    }
}

pub(crate) fn execute_request(spec: &HttpLoadSpec) -> Result<(), HarnessError> {
    let mut stream =
        connect_with_deadline(spec.address, spec.timeout, "HTTP load connection failed")?;
    stream
        .set_read_timeout(Some(spec.timeout))
        .and_then(|_| stream.set_write_timeout(Some(spec.timeout)))
        .map_err(|_| HarnessError::new("HTTP load timeout configuration failed"))?;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        spec.host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|_| HarnessError::new("HTTP load request write failed"))?;
    let mut response = Vec::with_capacity(spec.max_response_bytes.min(8 * 1024));
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|_| HarnessError::new("HTTP load response read failed"))?;
        if read == 0 {
            break;
        }
        if response.len().checked_add(read).is_none()
            || response.len() + read > spec.max_response_bytes
        {
            return Err(HarnessError::new("HTTP load response exceeds bound"));
        }
        response.extend_from_slice(&chunk[..read]);
    }
    validate_response(&response)
}

pub(crate) fn validate_response(response: &[u8]) -> Result<(), HarnessError> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or_else(|| HarnessError::new("HTTP load response headers are incomplete"))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| HarnessError::new("HTTP load response headers are invalid"))?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| HarnessError::new("HTTP load status is invalid"))?;
    if status != 200 {
        return Err(HarnessError::new("HTTP load status is not successful"));
    }
    let lengths = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then_some(value.trim())
        })
        .collect::<Vec<_>>();
    if lengths.len() != 1 {
        return Err(HarnessError::new(
            "HTTP load Content-Length is missing or duplicated",
        ));
    }
    let expected = lengths[0]
        .parse::<usize>()
        .map_err(|_| HarnessError::new("HTTP load Content-Length is invalid"))?;
    if response.len().checked_sub(header_end) != Some(expected) {
        return Err(HarnessError::new("HTTP load body length does not match"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressure {
    Normal,
    Pressured,
    Exhausted,
    FailedClosed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeResourceObservation {
    pub revision_id: String,
    pub generation: u64,
    pub used_payload_bytes: u64,
    pub payload_limit_bytes: u64,
    pub active_connections: u64,
    pub pressure: RuntimePressure,
}

#[derive(Deserialize)]
struct AdminStatusProjection {
    active_revision_id: String,
    live_resource_status: Option<RuntimeResourceProjection>,
}

#[derive(Deserialize)]
struct RuntimeResourceProjection {
    revision_id: String,
    generation: u64,
    used_payload_bytes: u64,
    payload_limit_bytes: u64,
    active_connections: u64,
    pressure: RuntimePressure,
}

pub fn parse_runtime_resource_status(
    json: &[u8],
    expected_revision: &str,
) -> Result<RuntimeResourceObservation, HarnessError> {
    let status: AdminStatusProjection = serde_json::from_slice(json)
        .map_err(|_| HarnessError::new("Admin runtime status JSON is invalid"))?;
    let live = status
        .live_resource_status
        .ok_or_else(|| HarnessError::new("Admin runtime resource status is unavailable"))?;
    if expected_revision.is_empty()
        || status.active_revision_id != expected_revision
        || live.revision_id != expected_revision
        || live.payload_limit_bytes == 0
    {
        return Err(HarnessError::new(
            "Admin runtime resource revision or limit is invalid",
        ));
    }
    Ok(RuntimeResourceObservation {
        revision_id: live.revision_id,
        generation: live.generation,
        used_payload_bytes: live.used_payload_bytes,
        payload_limit_bytes: live.payload_limit_bytes,
        active_connections: live.active_connections,
        pressure: live.pressure,
    })
}
