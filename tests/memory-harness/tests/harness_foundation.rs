use std::collections::VecDeque;

use edge_memory_harness::orchestrator::{HarnessOrchestrator, ScenarioOutcome, ScenarioSpec};
use edge_memory_harness::ports::{
    ChildProcess, LoadDriver, MonotonicClock, ProcessSupervisor, RssSampler,
};
use edge_memory_harness::scenario::{
    EvidenceFailure, ScenarioEvent, ScenarioFailure, ScenarioLifecycle, ScenarioState,
};
use edge_memory_harness::{HarnessError, MemorySample};

#[test]
fn full_scenario_lifecycle_is_explicit_and_terminal() {
    let mut lifecycle = ScenarioLifecycle::new();
    for (event, expected) in [
        (ScenarioEvent::PreflightPassed, ScenarioState::Preflight),
        (
            ScenarioEvent::StartRequested,
            ScenarioState::StartingProcesses,
        ),
        (ScenarioEvent::ChildReady, ScenarioState::Warming),
        (ScenarioEvent::WarmupCompleted, ScenarioState::Loading),
        (ScenarioEvent::LoadCompleted, ScenarioState::Cooling),
        (ScenarioEvent::CooldownCompleted, ScenarioState::Analyzing),
        (ScenarioEvent::AnalysisPassed, ScenarioState::Passed),
    ] {
        lifecycle.transition(event).unwrap();
        assert_eq!(lifecycle.state(), expected);
    }
    assert!(lifecycle.transition(ScenarioEvent::AnalysisPassed).is_err());
    assert_eq!(lifecycle.state(), ScenarioState::InvalidEvidence);
}

#[derive(Default)]
struct FakeSupervisor {
    calls: Vec<&'static str>,
    identities: VecDeque<String>,
    alive: bool,
    exit_after_start: bool,
}

impl ProcessSupervisor for FakeSupervisor {
    fn start(&mut self) -> Result<ChildProcess, ScenarioFailure> {
        self.calls.push("start");
        self.alive = !self.exit_after_start;
        Ok(ChildProcess::new(42, "start-a"))
    }

    fn identity(&mut self, _child: &ChildProcess) -> Result<String, ScenarioFailure> {
        self.calls.push("identity");
        Ok(self
            .identities
            .pop_front()
            .unwrap_or_else(|| "start-a".to_string()))
    }

    fn is_alive(&mut self, _child: &ChildProcess) -> Result<bool, ScenarioFailure> {
        self.calls.push("alive");
        Ok(self.alive)
    }

    fn stop(&mut self, _child: &ChildProcess) -> Result<(), ScenarioFailure> {
        self.calls.push("stop");
        self.alive = false;
        Ok(())
    }
}

struct FakeSampler {
    results: VecDeque<Result<u64, ScenarioFailure>>,
}

impl RssSampler for FakeSampler {
    fn sample_rss_bytes(&mut self, _child: &ChildProcess) -> Result<u64, ScenarioFailure> {
        self.results
            .pop_front()
            .unwrap_or(Err(ScenarioFailure::SamplerFailed))
    }
}

#[derive(Default)]
struct FakeDriver {
    calls: Vec<&'static str>,
}

impl LoadDriver for FakeDriver {
    fn warm(&mut self, _child: &ChildProcess) -> Result<(), ScenarioFailure> {
        self.calls.push("warm");
        Ok(())
    }

    fn load(&mut self, _child: &ChildProcess) -> Result<(), ScenarioFailure> {
        self.calls.push("load");
        Ok(())
    }

    fn cool(&mut self, _child: &ChildProcess) -> Result<(), ScenarioFailure> {
        self.calls.push("cool");
        Ok(())
    }
}

#[derive(Default)]
struct FakeClock(u64);

impl MonotonicClock for FakeClock {
    fn now_ms(&mut self) -> u64 {
        self.0 += 1_000;
        self.0
    }
}

#[test]
fn orchestrator_success_uses_ports_and_stops_child_once() {
    let supervisor = FakeSupervisor::default();
    let sampler = FakeSampler {
        results: VecDeque::from([Ok(10), Ok(12), Ok(11)]),
    };
    let driver = FakeDriver::default();
    let clock = FakeClock::default();
    let mut orchestrator = HarnessOrchestrator::new(supervisor, sampler, driver, clock);

    let record = orchestrator.run(ScenarioSpec::new("idle", 3).unwrap());

    assert_eq!(record.outcome, ScenarioOutcome::Passed);
    assert_eq!(record.samples.len(), 3);
    assert_eq!(
        record.samples[0],
        MemorySample {
            elapsed_ms: 0,
            rss_bytes: 10
        }
    );
    assert_eq!(orchestrator.supervisor().calls.last(), Some(&"stop"));
    assert_eq!(
        orchestrator
            .supervisor()
            .calls
            .iter()
            .filter(|call| **call == "stop")
            .count(),
        1
    );
    assert_eq!(orchestrator.driver().calls, vec!["warm", "load", "cool"]);
}

#[test]
fn early_exit_and_sampler_failure_are_terminal_and_cleanup_once() {
    let supervisor = FakeSupervisor {
        exit_after_start: true,
        ..FakeSupervisor::default()
    };
    let sampler = FakeSampler {
        results: VecDeque::from([Err(ScenarioFailure::SamplerFailed)]),
    };
    let mut orchestrator = HarnessOrchestrator::new(
        supervisor,
        sampler,
        FakeDriver::default(),
        FakeClock::default(),
    );

    let record = orchestrator.run(ScenarioSpec::new("idle", 1).unwrap());

    assert_eq!(
        record.outcome,
        ScenarioOutcome::Failed(ScenarioFailure::ProcessExitedEarly)
    );
    assert_eq!(
        orchestrator
            .supervisor()
            .calls
            .iter()
            .filter(|call| **call == "stop")
            .count(),
        1
    );

    let mut sampler_orchestrator = HarnessOrchestrator::new(
        FakeSupervisor::default(),
        FakeSampler {
            results: VecDeque::from([Err(ScenarioFailure::SamplerFailed)]),
        },
        FakeDriver::default(),
        FakeClock::default(),
    );
    let sampler_record = sampler_orchestrator.run(ScenarioSpec::new("idle", 1).unwrap());
    assert_eq!(
        sampler_record.outcome,
        ScenarioOutcome::InvalidEvidence(EvidenceFailure::TooManyMissingSamples {
            expected: 1,
            missing: 1,
        })
    );
    assert_eq!(
        sampler_orchestrator
            .supervisor()
            .calls
            .iter()
            .filter(|call| **call == "stop")
            .count(),
        1
    );
}

#[test]
fn missing_samples_and_identity_change_are_invalid_evidence() {
    let supervisor = FakeSupervisor {
        identities: VecDeque::from(["start-a".to_string(), "start-b".to_string()]),
        ..FakeSupervisor::default()
    };
    let sampler = FakeSampler {
        results: VecDeque::from([Ok(10), Ok(11)]),
    };
    let mut identity_orchestrator = HarnessOrchestrator::new(
        supervisor,
        sampler,
        FakeDriver::default(),
        FakeClock::default(),
    );
    let identity_record = identity_orchestrator.run(ScenarioSpec::new("idle", 2).unwrap());
    assert_eq!(
        identity_record.outcome,
        ScenarioOutcome::InvalidEvidence(EvidenceFailure::ProcessIdentityChanged)
    );

    let missing_results = (0..100)
        .map(|index| {
            if index < 2 {
                Err(ScenarioFailure::SamplerFailed)
            } else {
                Ok(10)
            }
        })
        .collect();
    let mut missing_orchestrator = HarnessOrchestrator::new(
        FakeSupervisor::default(),
        FakeSampler {
            results: missing_results,
        },
        FakeDriver::default(),
        FakeClock::default(),
    );
    let missing_record = missing_orchestrator.run(ScenarioSpec::new("idle", 100).unwrap());
    assert_eq!(
        missing_record.outcome,
        ScenarioOutcome::InvalidEvidence(EvidenceFailure::TooManyMissingSamples {
            expected: 100,
            missing: 2,
        })
    );
    assert!(ScenarioSpec::new("", 1).is_err());
    assert!(ScenarioSpec::new("idle", 0).is_err());
}

#[test]
fn public_error_type_remains_compatible() {
    let error = HarnessError::new("compatibility");
    assert_eq!(error.to_string(), "compatibility");
}
