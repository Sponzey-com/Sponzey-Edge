use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use crate::bounded_net::connect_with_deadline;
use crate::evaluator::{
    evaluate_scenario, AcceptanceEvaluation, AcceptancePolicy, AcceptanceResult,
    ScenarioObservation,
};
use crate::http_driver::{
    parse_runtime_resource_status, HttpLoadCounters, HttpLoadDriver, RuntimePressure,
    RuntimeResourceObservation,
};
use crate::ports::{ChildProcess, RssSampler};
use crate::system_adapters::{
    attach_process, attached_process_identity_matches, attached_process_is_alive,
    PlatformRssSampler,
};
use crate::{HarnessError, MemorySample};

const MAX_HTTP_HEADER_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseHttpScenarioSpec {
    expected_revision: String,
    expected_requests: u64,
    absolute_ceiling_bytes: u64,
    cooldown_cycles: usize,
    cooldown_interval_ms: u64,
}

impl ReleaseHttpScenarioSpec {
    pub fn new(
        expected_revision: impl Into<String>,
        expected_requests: u64,
        absolute_ceiling_bytes: u64,
        cooldown_cycles: usize,
        cooldown_interval_ms: u64,
    ) -> Result<Self, HarnessError> {
        let expected_revision = expected_revision.into();
        if expected_revision.is_empty()
            || expected_requests == 0
            || absolute_ceiling_bytes == 0
            || cooldown_cycles < 5
            || cooldown_interval_ms == 0
        {
            return Err(HarnessError::new(
                "release HTTP scenario specification is invalid",
            ));
        }
        Ok(Self {
            expected_revision,
            expected_requests,
            absolute_ceiling_bytes,
            cooldown_cycles,
            cooldown_interval_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseScenarioState {
    Created,
    Attached,
    Baseline,
    Warming,
    Loading,
    Cooling,
    Analyzing,
    Passed,
    Failed,
    InvalidEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseScenarioOutcome {
    Passed,
    Failed,
    InvalidEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseHttpScenarioRecord {
    pub state: ReleaseScenarioState,
    pub outcome: ReleaseScenarioOutcome,
    pub samples: Vec<MemorySample>,
    pub counters: Option<HttpLoadCounters>,
    pub runtime_status: Option<RuntimeResourceObservation>,
    pub observation: Option<ScenarioObservation>,
    pub evaluation: Option<AcceptanceEvaluation>,
}

pub trait ProcessObservationPort {
    fn is_alive(&mut self) -> Result<bool, HarnessError>;
    fn identity_matches(&mut self) -> Result<bool, HarnessError>;
    fn sample_rss_bytes(&mut self) -> Result<u64, HarnessError>;
}

pub trait HttpLoadPort {
    fn warm(&mut self) -> Result<(), HarnessError>;
    fn load(&mut self) -> Result<HttpLoadCounters, HarnessError>;
    fn cool(&mut self) -> Result<(), HarnessError>;
}

impl HttpLoadPort for HttpLoadDriver {
    fn warm(&mut self) -> Result<(), HarnessError> {
        HttpLoadDriver::warm(self)
    }

    fn load(&mut self) -> Result<HttpLoadCounters, HarnessError> {
        HttpLoadDriver::load(self)
    }

    fn cool(&mut self) -> Result<(), HarnessError> {
        HttpLoadDriver::cool(self)
    }
}

pub trait RuntimeStatusPort {
    fn observe(
        &mut self,
        expected_revision: &str,
    ) -> Result<RuntimeResourceObservation, HarnessError>;
}

pub trait DelayPort {
    fn wait(&mut self, interval_ms: u64);
    fn elapsed_ms(&mut self) -> u64;
}

pub struct ReleaseHttpScenarioRunner<P, L, R, D> {
    process: P,
    load: L,
    status: R,
    delay: D,
    state: ReleaseScenarioState,
}

impl<P, L, R, D> ReleaseHttpScenarioRunner<P, L, R, D>
where
    P: ProcessObservationPort,
    L: HttpLoadPort,
    R: RuntimeStatusPort,
    D: DelayPort,
{
    pub fn new(process: P, load: L, status: R, delay: D) -> Self {
        Self {
            process,
            load,
            status,
            delay,
            state: ReleaseScenarioState::Created,
        }
    }

    pub fn run(&mut self, spec: &ReleaseHttpScenarioSpec) -> ReleaseHttpScenarioRecord {
        if self.state != ReleaseScenarioState::Created {
            return terminal_record(
                ReleaseScenarioState::InvalidEvidence,
                ReleaseScenarioOutcome::InvalidEvidence,
                Vec::new(),
                None,
                None,
                None,
                None,
            );
        }
        self.state = ReleaseScenarioState::Attached;
        let mut samples = Vec::with_capacity(spec.cooldown_cycles + 2);
        let baseline = match self.sample_checked() {
            Ok(value) => value,
            Err(()) => return self.invalid(samples),
        };
        samples.push(MemorySample {
            elapsed_ms: 0,
            rss_bytes: baseline,
        });
        self.state = ReleaseScenarioState::Baseline;
        self.state = ReleaseScenarioState::Warming;
        if self.load.warm().is_err() {
            return self.failed(samples, None, None, None, None);
        }
        self.state = ReleaseScenarioState::Loading;
        let counters = match self.load.load() {
            Ok(counters) => counters,
            Err(_) => return self.failed(samples, None, None, None, None),
        };
        let loaded = match self.sample_checked() {
            Ok(value) => value,
            Err(()) => return self.invalid(samples),
        };
        samples.push(MemorySample {
            elapsed_ms: self.delay.elapsed_ms(),
            rss_bytes: loaded,
        });
        self.state = ReleaseScenarioState::Cooling;
        if self.load.cool().is_err() {
            return self.failed(samples, Some(counters), None, None, None);
        }
        let mut cooldown = Vec::with_capacity(spec.cooldown_cycles);
        for _ in 0..spec.cooldown_cycles {
            self.delay.wait(spec.cooldown_interval_ms);
            let rss = match self.sample_checked() {
                Ok(value) => value,
                Err(()) => return self.invalid(samples),
            };
            cooldown.push(rss);
            samples.push(MemorySample {
                elapsed_ms: self.delay.elapsed_ms(),
                rss_bytes: rss,
            });
        }
        self.state = ReleaseScenarioState::Analyzing;
        let runtime = match self.status.observe(&spec.expected_revision) {
            Ok(runtime) => runtime,
            Err(_) => return self.failed(samples, Some(counters), None, None, None),
        };
        let peak_rss_bytes = samples
            .iter()
            .map(|sample| sample.rss_bytes)
            .max()
            .unwrap_or(0);
        let observation = ScenarioObservation {
            peak_rss_bytes,
            cooldown_cycle_medians: cooldown,
            process_alive: true,
            successful_requests: counters.succeeded,
            failed_requests: counters.failed,
            active_connections_after_cooldown: runtime.active_connections,
            charged_payload_bytes_after_cooldown: runtime.used_payload_bytes,
        };
        let policy =
            match AcceptancePolicy::new(spec.absolute_ceiling_bytes, spec.expected_requests) {
                Ok(policy) => policy,
                Err(_) => return self.invalid(samples),
            };
        let evaluation = evaluate_scenario(&policy, &observation);
        let passed = matches!(evaluation.result, AcceptanceResult::Passed)
            && runtime.pressure == RuntimePressure::Normal;
        self.state = if passed {
            ReleaseScenarioState::Passed
        } else {
            ReleaseScenarioState::Failed
        };
        terminal_record(
            self.state,
            if passed {
                ReleaseScenarioOutcome::Passed
            } else {
                ReleaseScenarioOutcome::Failed
            },
            samples,
            Some(counters),
            Some(runtime),
            Some(observation),
            Some(evaluation),
        )
    }

    fn sample_checked(&mut self) -> Result<u64, ()> {
        if self.process.is_alive().ok() != Some(true)
            || self.process.identity_matches().ok() != Some(true)
        {
            return Err(());
        }
        match self.process.sample_rss_bytes() {
            Ok(value) if value > 0 => Ok(value),
            _ => Err(()),
        }
    }

    fn invalid(&mut self, samples: Vec<MemorySample>) -> ReleaseHttpScenarioRecord {
        self.state = ReleaseScenarioState::InvalidEvidence;
        terminal_record(
            self.state,
            ReleaseScenarioOutcome::InvalidEvidence,
            samples,
            None,
            None,
            None,
            None,
        )
    }

    fn failed(
        &mut self,
        samples: Vec<MemorySample>,
        counters: Option<HttpLoadCounters>,
        runtime_status: Option<RuntimeResourceObservation>,
        observation: Option<ScenarioObservation>,
        evaluation: Option<AcceptanceEvaluation>,
    ) -> ReleaseHttpScenarioRecord {
        self.state = ReleaseScenarioState::Failed;
        terminal_record(
            self.state,
            ReleaseScenarioOutcome::Failed,
            samples,
            counters,
            runtime_status,
            observation,
            evaluation,
        )
    }
}

fn terminal_record(
    state: ReleaseScenarioState,
    outcome: ReleaseScenarioOutcome,
    samples: Vec<MemorySample>,
    counters: Option<HttpLoadCounters>,
    runtime_status: Option<RuntimeResourceObservation>,
    observation: Option<ScenarioObservation>,
    evaluation: Option<AcceptanceEvaluation>,
) -> ReleaseHttpScenarioRecord {
    ReleaseHttpScenarioRecord {
        state,
        outcome,
        samples,
        counters,
        runtime_status,
        observation,
        evaluation,
    }
}

pub struct AttachedProcessObservation {
    child: ChildProcess,
    sampler: PlatformRssSampler,
}

impl AttachedProcessObservation {
    pub fn attach(pid: u32) -> Result<Self, HarnessError> {
        let child = attach_process(pid)
            .map_err(|_| HarnessError::new("release HTTP process attach failed"))?;
        Ok(Self {
            child,
            sampler: PlatformRssSampler,
        })
    }

    pub fn start_identity(&self) -> &str {
        &self.child.start_identity
    }
}

impl ProcessObservationPort for AttachedProcessObservation {
    fn is_alive(&mut self) -> Result<bool, HarnessError> {
        attached_process_is_alive(&self.child)
            .map_err(|_| HarnessError::new("release HTTP process liveness failed"))
    }

    fn identity_matches(&mut self) -> Result<bool, HarnessError> {
        attached_process_identity_matches(&self.child)
            .map_err(|_| HarnessError::new("release HTTP process identity failed"))
    }

    fn sample_rss_bytes(&mut self) -> Result<u64, HarnessError> {
        self.sampler
            .sample_rss_bytes(&self.child)
            .map_err(|_| HarnessError::new("release HTTP RSS sample failed"))
    }
}

pub struct ThreadDelay {
    started_at: Instant,
}

impl ThreadDelay {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }
}

impl Default for ThreadDelay {
    fn default() -> Self {
        Self::new()
    }
}

impl DelayPort for ThreadDelay {
    fn wait(&mut self, interval_ms: u64) {
        thread::sleep(Duration::from_millis(interval_ms));
    }

    fn elapsed_ms(&mut self) -> u64 {
        self.started_at
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

pub struct AdminStatusHttpProbe {
    address: SocketAddr,
    timeout: Duration,
    max_body_bytes: usize,
}

impl AdminStatusHttpProbe {
    pub fn new(
        address: SocketAddr,
        timeout: Duration,
        max_body_bytes: usize,
    ) -> Result<Self, HarnessError> {
        if timeout.is_zero() || max_body_bytes == 0 {
            return Err(HarnessError::new(
                "Admin status probe specification is invalid",
            ));
        }
        Ok(Self {
            address,
            timeout,
            max_body_bytes,
        })
    }
}

impl RuntimeStatusPort for AdminStatusHttpProbe {
    fn observe(
        &mut self,
        expected_revision: &str,
    ) -> Result<RuntimeResourceObservation, HarnessError> {
        let mut stream =
            connect_with_deadline(self.address, self.timeout, "Admin status connection failed")?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|_| HarnessError::new("Admin status timeout setup failed"))?;
        stream
            .write_all(
                b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .map_err(|_| HarnessError::new("Admin status request failed"))?;
        let response = read_bounded_response(&mut stream, self.max_body_bytes)?;
        let body = response_body(&response, self.max_body_bytes)?;
        parse_runtime_resource_status(body, expected_revision)
    }
}

fn read_bounded_response(
    stream: &mut TcpStream,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HarnessError> {
    let maximum = MAX_HTTP_HEADER_BYTES
        .checked_add(max_body_bytes)
        .ok_or_else(|| HarnessError::new("Admin status response bound overflows"))?;
    let mut response = Vec::with_capacity(maximum.min(16 * 1024));
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|_| HarnessError::new("Admin status response read failed"))?;
        if read == 0 {
            break;
        }
        let next = response
            .len()
            .checked_add(read)
            .ok_or_else(|| HarnessError::new("Admin status response size overflows"))?;
        if next > maximum {
            return Err(HarnessError::new("Admin status response exceeds bound"));
        }
        response.extend_from_slice(&chunk[..read]);
    }
    Ok(response)
}

fn response_body(response: &[u8], max_body_bytes: usize) -> Result<&[u8], HarnessError> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or_else(|| HarnessError::new("Admin status headers are incomplete"))?;
    if header_end > MAX_HTTP_HEADER_BYTES {
        return Err(HarnessError::new("Admin status headers exceed bound"));
    }
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| HarnessError::new("Admin status headers are invalid"))?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| HarnessError::new("Admin status code is invalid"))?;
    if status != 200 {
        return Err(HarnessError::new("Admin status response is not successful"));
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
            "Admin status Content-Length is missing or duplicated",
        ));
    }
    let expected = lengths[0]
        .parse::<usize>()
        .map_err(|_| HarnessError::new("Admin status Content-Length is invalid"))?;
    let body = &response[header_end..];
    if expected > max_body_bytes || body.len() != expected {
        return Err(HarnessError::new("Admin status body length is invalid"));
    }
    Ok(body)
}
