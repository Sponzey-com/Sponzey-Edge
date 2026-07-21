use std::collections::VecDeque;

use edge_memory_harness::connection_churn::{
    ChurnCycleLoadPort, ChurnScenarioOutcome, ChurnScenarioRunner, ChurnScenarioSpec,
};
use edge_memory_harness::http_driver::{
    HttpLoadCounters, RuntimePressure, RuntimeResourceObservation,
};
use edge_memory_harness::release_http_scenario::{
    DelayPort, ProcessObservationPort, RuntimeStatusPort,
};
use edge_memory_harness::HarnessError;

#[test]
fn five_clean_load_and_cooldown_cycles_pass_plateau() {
    let process = FakeProcess::new(vec![100, 101, 102, 103, 104, 105]);
    let load = FakeLoad::clean(5, 10);
    let status = FakeStatus::clean(5);
    let spec = ChurnScenarioSpec::new("rev-1", 5, 10, 384 * 1024 * 1024, 1).unwrap();
    let mut runner = ChurnScenarioRunner::new(process, load, status, FakeDelay::default());

    let record = runner.run(&spec);

    assert_eq!(record.outcome, ChurnScenarioOutcome::Passed);
    assert_eq!(record.cycles.len(), 5);
    assert_eq!(record.expected_requests, 50);
    assert_eq!(record.succeeded_requests, 50);
    assert_eq!(record.failed_requests, 0);
    assert_eq!(record.cycles[4].runtime.active_connections, 0);
    assert_eq!(record.cycles[4].runtime.used_payload_bytes, 0);
}

#[test]
fn dirty_cycle_stops_before_the_next_load() {
    let process = FakeProcess::new(vec![100, 101, 102]);
    let load = FakeLoad::clean(5, 10);
    let mut statuses = VecDeque::from(vec![clean_status(), clean_status()]);
    statuses[1].used_payload_bytes = 1;
    let status = FakeStatus { statuses };
    let spec = ChurnScenarioSpec::new("rev-1", 5, 10, 384 * 1024 * 1024, 1).unwrap();
    let mut runner = ChurnScenarioRunner::new(process, load, status, FakeDelay::default());

    let record = runner.run(&spec);

    assert_eq!(record.outcome, ChurnScenarioOutcome::Failed);
    assert_eq!(record.cycles.len(), 2);
    assert_eq!(record.succeeded_requests, 20);
}

#[test]
fn invalid_count_identity_and_plateau_are_rejected() {
    assert!(ChurnScenarioSpec::new("rev-1", 4, 10, 1, 1).is_err());

    let spec = ChurnScenarioSpec::new("rev-1", 5, 10, 384 * 1024 * 1024, 1).unwrap();
    let mut failed_count = ChurnScenarioRunner::new(
        FakeProcess::new(vec![100, 101]),
        FakeLoad::with_first(HttpLoadCounters {
            expected: 10,
            succeeded: 9,
            failed: 1,
        }),
        FakeStatus::clean(5),
        FakeDelay::default(),
    );
    assert_eq!(
        failed_count.run(&spec).outcome,
        ChurnScenarioOutcome::Failed
    );

    let mut changed_identity = FakeProcess::new(vec![100]);
    changed_identity.identity_matches = false;
    let mut invalid = ChurnScenarioRunner::new(
        changed_identity,
        FakeLoad::clean(5, 10),
        FakeStatus::clean(5),
        FakeDelay::default(),
    );
    assert_eq!(
        invalid.run(&spec).outcome,
        ChurnScenarioOutcome::InvalidEvidence
    );

    let mut plateau = ChurnScenarioRunner::new(
        FakeProcess::new(vec![100, 100, 100, 100, 20_000_000, 20_000_000]),
        FakeLoad::clean(5, 10),
        FakeStatus::clean(5),
        FakeDelay::default(),
    );
    assert_eq!(plateau.run(&spec).outcome, ChurnScenarioOutcome::Failed);
}

struct FakeProcess {
    rss: VecDeque<u64>,
    identity_matches: bool,
}

impl FakeProcess {
    fn new(values: Vec<u64>) -> Self {
        Self {
            rss: values.into(),
            identity_matches: true,
        }
    }
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
    counters: VecDeque<HttpLoadCounters>,
}

impl FakeLoad {
    fn clean(cycles: usize, requests: u64) -> Self {
        Self {
            counters: (0..cycles)
                .map(|_| HttpLoadCounters {
                    expected: requests,
                    succeeded: requests,
                    failed: 0,
                })
                .collect(),
        }
    }

    fn with_first(counters: HttpLoadCounters) -> Self {
        Self {
            counters: VecDeque::from(vec![counters]),
        }
    }
}

impl ChurnCycleLoadPort for FakeLoad {
    fn run_cycle(&mut self, _cycle: usize) -> Result<HttpLoadCounters, HarnessError> {
        self.counters
            .pop_front()
            .ok_or_else(|| HarnessError::new("fake load exhausted"))
    }
}

struct FakeStatus {
    statuses: VecDeque<RuntimeResourceObservation>,
}

impl FakeStatus {
    fn clean(cycles: usize) -> Self {
        Self {
            statuses: (0..cycles).map(|_| clean_status()).collect(),
        }
    }
}

impl RuntimeStatusPort for FakeStatus {
    fn observe(
        &mut self,
        _expected_revision: &str,
    ) -> Result<RuntimeResourceObservation, HarnessError> {
        self.statuses
            .pop_front()
            .ok_or_else(|| HarnessError::new("fake status exhausted"))
    }
}

#[derive(Default)]
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
