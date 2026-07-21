use std::collections::VecDeque;

use edge_memory_harness::connection_churn::{
    ChurnCycleLoadPort, ChurnScenarioRunner, ChurnScenarioSpec,
};
use edge_memory_harness::connection_churn_evidence::{
    ChurnEvidenceExpectations, ChurnEvidenceValidator, ChurnMemoryEvidenceReport,
};
use edge_memory_harness::http_driver::{
    HttpLoadCounters, RuntimePressure, RuntimeResourceObservation,
};
use edge_memory_harness::release_http_scenario::{
    DelayPort, ProcessObservationPort, RuntimeStatusPort,
};
use edge_memory_harness::report::EvidenceIdentity;
use edge_memory_harness::report_io::sha256_hex;
use edge_memory_harness::HarnessError;

#[test]
fn churn_report_roundtrips_and_rejects_unknown_or_tampered_bytes() {
    let report = passed_report();
    let encoded = report.to_canonical_json().unwrap();
    let validator = ChurnEvidenceValidator::new(expectations());

    let validated = validator
        .validate(encoded.as_bytes(), &sha256_hex(encoded.as_bytes()))
        .unwrap();
    assert_eq!(validated.requests.expected, 50);
    assert_eq!(validated.cycles.len(), 5);

    let unknown = encoded.replacen("{\n", "{\n  \"unknown\": true,\n", 1);
    assert!(validator
        .validate(unknown.as_bytes(), &sha256_hex(unknown.as_bytes()))
        .is_err());
    assert!(validator
        .validate(encoded.as_bytes(), &"0".repeat(64))
        .is_err());
}

fn passed_report() -> ChurnMemoryEvidenceReport {
    let spec = ChurnScenarioSpec::new("rev-1", 5, 10, 384 * 1024 * 1024, 1).unwrap();
    let process = FakeProcess {
        rss: VecDeque::from(vec![100, 101, 102, 103, 104, 105]),
    };
    let load = FakeLoad {
        left: 5,
        requests: 10,
    };
    let status = FakeStatus { left: 5 };
    let mut runner = ChurnScenarioRunner::new(process, load, status, FakeDelay::default());
    ChurnMemoryEvidenceReport::new(identity(), 384 * 1024 * 1024, 5, 10, runner.run(&spec)).unwrap()
}

fn identity() -> EvidenceIdentity {
    EvidenceIdentity {
        scenario_id: "connection-churn-50k".to_string(),
        scenario_version: "phase011-v1".to_string(),
        platform: "macos".to_string(),
        architecture: "aarch64".to_string(),
        build_identity: format!("source-tree-sha256:{}", "a".repeat(64)),
        config_sha256: "b".repeat(64),
        process_start_identity: "fixture-start".to_string(),
    }
}

fn expectations() -> ChurnEvidenceExpectations {
    ChurnEvidenceExpectations {
        scenario_id: "connection-churn-50k".to_string(),
        scenario_version: "phase011-v1".to_string(),
        build_identity: format!("source-tree-sha256:{}", "a".repeat(64)),
        config_sha256: "b".repeat(64),
    }
}

struct FakeProcess {
    rss: VecDeque<u64>,
}

impl ProcessObservationPort for FakeProcess {
    fn is_alive(&mut self) -> Result<bool, HarnessError> {
        Ok(true)
    }
    fn identity_matches(&mut self) -> Result<bool, HarnessError> {
        Ok(true)
    }
    fn sample_rss_bytes(&mut self) -> Result<u64, HarnessError> {
        self.rss
            .pop_front()
            .ok_or_else(|| HarnessError::new("RSS exhausted"))
    }
}

struct FakeLoad {
    left: usize,
    requests: u64,
}

impl ChurnCycleLoadPort for FakeLoad {
    fn run_cycle(&mut self, _cycle: usize) -> Result<HttpLoadCounters, HarnessError> {
        if self.left == 0 {
            return Err(HarnessError::new("load exhausted"));
        }
        self.left -= 1;
        Ok(HttpLoadCounters {
            expected: self.requests,
            succeeded: self.requests,
            failed: 0,
        })
    }
}

struct FakeStatus {
    left: usize,
}

impl RuntimeStatusPort for FakeStatus {
    fn observe(&mut self, _revision: &str) -> Result<RuntimeResourceObservation, HarnessError> {
        if self.left == 0 {
            return Err(HarnessError::new("status exhausted"));
        }
        self.left -= 1;
        Ok(RuntimeResourceObservation {
            revision_id: "rev-1".to_string(),
            generation: 1,
            used_payload_bytes: 0,
            payload_limit_bytes: 128 * 1024 * 1024,
            active_connections: 0,
            pressure: RuntimePressure::Normal,
        })
    }
}

#[derive(Default)]
struct FakeDelay(u64);

impl DelayPort for FakeDelay {
    fn wait(&mut self, interval_ms: u64) {
        self.0 += interval_ms;
    }
    fn elapsed_ms(&mut self) -> u64 {
        self.0
    }
}
