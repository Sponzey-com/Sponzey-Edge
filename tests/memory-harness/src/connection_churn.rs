use std::net::SocketAddr;
use std::time::Duration;

use crate::evaluator::{
    evaluate_scenario, AcceptanceEvaluation, AcceptancePolicy, AcceptanceResult,
    ScenarioObservation,
};
use crate::http_driver::{
    HttpLoadCounters, HttpLoadDriver, HttpLoadSpec, RuntimePressure, RuntimeResourceObservation,
};
use crate::release_http_scenario::{DelayPort, ProcessObservationPort, RuntimeStatusPort};
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChurnScenarioSpec {
    expected_revision: String,
    cycles: usize,
    requests_per_cycle: u64,
    absolute_ceiling_bytes: u64,
    cooldown_interval_ms: u64,
}

impl ChurnScenarioSpec {
    pub fn new(
        expected_revision: impl Into<String>,
        cycles: usize,
        requests_per_cycle: u64,
        absolute_ceiling_bytes: u64,
        cooldown_interval_ms: u64,
    ) -> Result<Self, HarnessError> {
        let expected_revision = expected_revision.into();
        if expected_revision.is_empty()
            || cycles < 5
            || requests_per_cycle == 0
            || absolute_ceiling_bytes == 0
            || cooldown_interval_ms == 0
        {
            return Err(HarnessError::new(
                "connection churn specification is invalid",
            ));
        }
        requests_per_cycle
            .checked_mul(cycles as u64)
            .ok_or_else(|| HarnessError::new("connection churn request total overflows"))?;
        Ok(Self {
            expected_revision,
            cycles,
            requests_per_cycle,
            absolute_ceiling_bytes,
            cooldown_interval_ms,
        })
    }

    pub fn expected_requests(&self) -> u64 {
        self.requests_per_cycle * self.cycles as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChurnScenarioState {
    Created,
    Baseline,
    Cycling,
    Analyzing,
    Passed,
    Failed,
    InvalidEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChurnScenarioOutcome {
    Passed,
    Failed,
    InvalidEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChurnCycleRecord {
    pub cycle: usize,
    pub counters: HttpLoadCounters,
    pub runtime: RuntimeResourceObservation,
    pub cooldown_rss_bytes: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChurnScenarioRecord {
    pub state: ChurnScenarioState,
    pub outcome: ChurnScenarioOutcome,
    pub baseline_rss_bytes: u64,
    pub peak_rss_bytes: u64,
    pub expected_requests: u64,
    pub succeeded_requests: u64,
    pub failed_requests: u64,
    pub cycles: Vec<ChurnCycleRecord>,
    pub evaluation: Option<AcceptanceEvaluation>,
}

pub trait ChurnCycleLoadPort {
    fn run_cycle(&mut self, cycle: usize) -> Result<HttpLoadCounters, HarnessError>;
}

pub struct CyclingHttpLoad {
    address: SocketAddr,
    host: String,
    requests_per_cycle: usize,
    timeout: Duration,
    max_response_bytes: usize,
}

impl CyclingHttpLoad {
    pub fn new(
        address: SocketAddr,
        host: impl Into<String>,
        requests_per_cycle: usize,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, HarnessError> {
        let host = host.into();
        HttpLoadSpec::new(
            address,
            host.clone(),
            requests_per_cycle,
            timeout,
            max_response_bytes,
        )?;
        Ok(Self {
            address,
            host,
            requests_per_cycle,
            timeout,
            max_response_bytes,
        })
    }
}

impl ChurnCycleLoadPort for CyclingHttpLoad {
    fn run_cycle(&mut self, _cycle: usize) -> Result<HttpLoadCounters, HarnessError> {
        let spec = HttpLoadSpec::new(
            self.address,
            self.host.clone(),
            self.requests_per_cycle,
            self.timeout,
            self.max_response_bytes,
        )?;
        let mut driver = HttpLoadDriver::new(spec);
        driver.warm()?;
        let counters = driver.load()?;
        driver.cool()?;
        Ok(counters)
    }
}

pub struct ChurnScenarioRunner<P, L, R, D> {
    process: P,
    load: L,
    status: R,
    delay: D,
    state: ChurnScenarioState,
}

impl<P, L, R, D> ChurnScenarioRunner<P, L, R, D>
where
    P: ProcessObservationPort,
    L: ChurnCycleLoadPort,
    R: RuntimeStatusPort,
    D: DelayPort,
{
    pub fn new(process: P, load: L, status: R, delay: D) -> Self {
        Self {
            process,
            load,
            status,
            delay,
            state: ChurnScenarioState::Created,
        }
    }

    pub fn run(&mut self, spec: &ChurnScenarioSpec) -> ChurnScenarioRecord {
        if self.state != ChurnScenarioState::Created {
            return self.invalid(Vec::new(), 0, 0, 0);
        }
        self.state = ChurnScenarioState::Baseline;
        let baseline = match self.sample_checked() {
            Ok(value) => value,
            Err(()) => return self.invalid(Vec::new(), 0, 0, 0),
        };
        self.state = ChurnScenarioState::Cycling;
        let mut cycles = Vec::with_capacity(spec.cycles);
        let mut succeeded = 0_u64;
        let mut failed = 0_u64;
        let mut peak = baseline;

        for cycle in 1..=spec.cycles {
            let counters = match self.load.run_cycle(cycle) {
                Ok(value) => value,
                Err(_) => return self.failed(cycles, baseline, peak, succeeded, failed, None),
            };
            succeeded = match succeeded.checked_add(counters.succeeded) {
                Some(value) => value,
                None => return self.invalid(cycles, baseline, peak, failed),
            };
            failed = match failed.checked_add(counters.failed) {
                Some(value) => value,
                None => return self.invalid(cycles, baseline, peak, succeeded),
            };
            self.delay.wait(spec.cooldown_interval_ms);
            let runtime = match self.status.observe(&spec.expected_revision) {
                Ok(value) => value,
                Err(_) => return self.failed(cycles, baseline, peak, succeeded, failed, None),
            };
            let rss = match self.sample_checked() {
                Ok(value) => value,
                Err(()) => return self.invalid(cycles, baseline, peak, failed),
            };
            peak = peak.max(rss);
            cycles.push(ChurnCycleRecord {
                cycle,
                counters,
                runtime: runtime.clone(),
                cooldown_rss_bytes: rss,
                elapsed_ms: self.delay.elapsed_ms(),
            });
            let clean = counters.expected == spec.requests_per_cycle
                && counters.succeeded == spec.requests_per_cycle
                && counters.failed == 0
                && runtime.active_connections == 0
                && runtime.used_payload_bytes == 0
                && runtime.pressure == RuntimePressure::Normal;
            if !clean {
                return self.failed(cycles, baseline, peak, succeeded, failed, None);
            }
        }

        self.state = ChurnScenarioState::Analyzing;
        let observation = ScenarioObservation {
            peak_rss_bytes: peak,
            cooldown_cycle_medians: cycles
                .iter()
                .map(|cycle| cycle.cooldown_rss_bytes)
                .collect(),
            process_alive: true,
            successful_requests: succeeded,
            failed_requests: failed,
            active_connections_after_cooldown: 0,
            charged_payload_bytes_after_cooldown: 0,
        };
        let policy =
            match AcceptancePolicy::new(spec.absolute_ceiling_bytes, spec.expected_requests()) {
                Ok(value) => value,
                Err(_) => return self.invalid(cycles, baseline, peak, failed),
            };
        let evaluation = evaluate_scenario(&policy, &observation);
        let passed = matches!(evaluation.result, AcceptanceResult::Passed);
        self.state = if passed {
            ChurnScenarioState::Passed
        } else {
            ChurnScenarioState::Failed
        };
        ChurnScenarioRecord {
            state: self.state,
            outcome: if passed {
                ChurnScenarioOutcome::Passed
            } else {
                ChurnScenarioOutcome::Failed
            },
            baseline_rss_bytes: baseline,
            peak_rss_bytes: peak,
            expected_requests: spec.expected_requests(),
            succeeded_requests: succeeded,
            failed_requests: failed,
            cycles,
            evaluation: Some(evaluation),
        }
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

    fn invalid(
        &mut self,
        cycles: Vec<ChurnCycleRecord>,
        baseline: u64,
        peak: u64,
        failed: u64,
    ) -> ChurnScenarioRecord {
        self.state = ChurnScenarioState::InvalidEvidence;
        let succeeded = cycles.iter().map(|cycle| cycle.counters.succeeded).sum();
        ChurnScenarioRecord {
            state: self.state,
            outcome: ChurnScenarioOutcome::InvalidEvidence,
            baseline_rss_bytes: baseline,
            peak_rss_bytes: peak,
            expected_requests: 0,
            succeeded_requests: succeeded,
            failed_requests: failed,
            cycles,
            evaluation: None,
        }
    }

    fn failed(
        &mut self,
        cycles: Vec<ChurnCycleRecord>,
        baseline: u64,
        peak: u64,
        succeeded: u64,
        failed: u64,
        evaluation: Option<AcceptanceEvaluation>,
    ) -> ChurnScenarioRecord {
        self.state = ChurnScenarioState::Failed;
        ChurnScenarioRecord {
            state: self.state,
            outcome: ChurnScenarioOutcome::Failed,
            baseline_rss_bytes: baseline,
            peak_rss_bytes: peak,
            expected_requests: 0,
            succeeded_requests: succeeded,
            failed_requests: failed,
            cycles,
            evaluation,
        }
    }
}
