use crate::ports::{LoadDriver, MonotonicClock, ProcessSupervisor, RssSampler};
use crate::scenario::{
    EvidenceFailure, ScenarioEvent, ScenarioFailure, ScenarioLifecycle, ScenarioState,
};
use crate::{HarnessError, MemorySample};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioSpec {
    pub id: String,
    pub expected_samples: usize,
}

impl ScenarioSpec {
    pub fn new(id: impl Into<String>, expected_samples: usize) -> Result<Self, HarnessError> {
        let id = id.into();
        if id.is_empty() {
            return Err(HarnessError::new("memory scenario id must not be empty"));
        }
        if expected_samples == 0 {
            return Err(HarnessError::new(
                "memory scenario expected samples must be positive",
            ));
        }
        Ok(Self {
            id,
            expected_samples,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScenarioOutcome {
    Passed,
    Failed(ScenarioFailure),
    InvalidEvidence(EvidenceFailure),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioRunRecord {
    pub state: ScenarioState,
    pub outcome: ScenarioOutcome,
    pub samples: Vec<MemorySample>,
    pub missing_samples: usize,
}

pub struct HarnessOrchestrator<P, S, D, C> {
    supervisor: P,
    sampler: S,
    driver: D,
    clock: C,
}

impl<P, S, D, C> HarnessOrchestrator<P, S, D, C>
where
    P: ProcessSupervisor,
    S: RssSampler,
    D: LoadDriver,
    C: MonotonicClock,
{
    pub fn new(supervisor: P, sampler: S, driver: D, clock: C) -> Self {
        Self {
            supervisor,
            sampler,
            driver,
            clock,
        }
    }

    pub fn supervisor(&self) -> &P {
        &self.supervisor
    }

    pub fn driver(&self) -> &D {
        &self.driver
    }

    pub fn run(&mut self, spec: ScenarioSpec) -> ScenarioRunRecord {
        let mut lifecycle = ScenarioLifecycle::new();
        let mut samples = Vec::with_capacity(spec.expected_samples);
        let mut missing_samples = 0;
        if lifecycle
            .transition(ScenarioEvent::PreflightPassed)
            .is_err()
            || lifecycle.transition(ScenarioEvent::StartRequested).is_err()
        {
            return invalid_record(
                lifecycle,
                samples,
                missing_samples,
                EvidenceFailure::InvalidTransition,
            );
        }
        let child = match self.supervisor.start() {
            Ok(child) => child,
            Err(error) => {
                let _ = lifecycle.transition(ScenarioEvent::OperationalFailed);
                return failed_record(lifecycle, samples, missing_samples, error);
            }
        };
        let outcome = self.run_started(
            &spec,
            &child,
            &mut lifecycle,
            &mut samples,
            &mut missing_samples,
        );
        let cleanup = self.supervisor.stop(&child);
        let outcome = match (outcome, cleanup) {
            (ScenarioOutcome::Passed, Err(error)) => ScenarioOutcome::Failed(error),
            (outcome, _) => outcome,
        };
        let state = match outcome {
            ScenarioOutcome::Passed => ScenarioState::Passed,
            ScenarioOutcome::Failed(_) => ScenarioState::Failed,
            ScenarioOutcome::InvalidEvidence(_) => ScenarioState::InvalidEvidence,
        };
        ScenarioRunRecord {
            state,
            outcome,
            samples,
            missing_samples,
        }
    }

    fn run_started(
        &mut self,
        spec: &ScenarioSpec,
        child: &crate::ports::ChildProcess,
        lifecycle: &mut ScenarioLifecycle,
        samples: &mut Vec<MemorySample>,
        missing_samples: &mut usize,
    ) -> ScenarioOutcome {
        if lifecycle.transition(ScenarioEvent::ChildReady).is_err() {
            return ScenarioOutcome::InvalidEvidence(EvidenceFailure::InvalidTransition);
        }
        for (operation, event) in [
            (
                LoadDriver::warm as fn(&mut D, &crate::ports::ChildProcess) -> _,
                ScenarioEvent::WarmupCompleted,
            ),
            (LoadDriver::load, ScenarioEvent::LoadCompleted),
            (LoadDriver::cool, ScenarioEvent::CooldownCompleted),
        ] {
            if let Err(error) = operation(&mut self.driver, child) {
                let _ = lifecycle.transition(ScenarioEvent::OperationalFailed);
                return ScenarioOutcome::Failed(error);
            }
            if lifecycle.transition(event).is_err() {
                return ScenarioOutcome::InvalidEvidence(EvidenceFailure::InvalidTransition);
            }
        }

        let started_at = self.clock.now_ms();
        for index in 0..spec.expected_samples {
            match self.supervisor.is_alive(child) {
                Ok(true) => {}
                Ok(false) => {
                    let _ = lifecycle.transition(ScenarioEvent::OperationalFailed);
                    return ScenarioOutcome::Failed(ScenarioFailure::ProcessExitedEarly);
                }
                Err(error) => {
                    let _ = lifecycle.transition(ScenarioEvent::OperationalFailed);
                    return ScenarioOutcome::Failed(error);
                }
            }
            match self.supervisor.identity(child) {
                Ok(identity) if identity == child.start_identity => {}
                Ok(_) => {
                    let _ = lifecycle.transition(ScenarioEvent::EvidenceRejected);
                    return ScenarioOutcome::InvalidEvidence(
                        EvidenceFailure::ProcessIdentityChanged,
                    );
                }
                Err(error) => {
                    let _ = lifecycle.transition(ScenarioEvent::OperationalFailed);
                    return ScenarioOutcome::Failed(error);
                }
            }
            match self.sampler.sample_rss_bytes(child) {
                Ok(rss_bytes) if rss_bytes > 0 => samples.push(MemorySample {
                    elapsed_ms: if index == 0 {
                        0
                    } else {
                        self.clock.now_ms().saturating_sub(started_at)
                    },
                    rss_bytes,
                }),
                Ok(_) | Err(ScenarioFailure::SamplerFailed) => *missing_samples += 1,
                Err(error) => {
                    let _ = lifecycle.transition(ScenarioEvent::OperationalFailed);
                    return ScenarioOutcome::Failed(error);
                }
            }
        }
        let allowed_missing = spec.expected_samples / 100;
        if *missing_samples > allowed_missing {
            let _ = lifecycle.transition(ScenarioEvent::EvidenceRejected);
            return ScenarioOutcome::InvalidEvidence(EvidenceFailure::TooManyMissingSamples {
                expected: spec.expected_samples,
                missing: *missing_samples,
            });
        }
        if samples.is_empty() {
            let _ = lifecycle.transition(ScenarioEvent::EvidenceRejected);
            return ScenarioOutcome::InvalidEvidence(EvidenceFailure::EmptySamples);
        }
        if lifecycle.transition(ScenarioEvent::AnalysisPassed).is_err() {
            return ScenarioOutcome::InvalidEvidence(EvidenceFailure::InvalidTransition);
        }
        ScenarioOutcome::Passed
    }
}

fn invalid_record(
    lifecycle: ScenarioLifecycle,
    samples: Vec<MemorySample>,
    missing_samples: usize,
    reason: EvidenceFailure,
) -> ScenarioRunRecord {
    ScenarioRunRecord {
        state: lifecycle.state(),
        outcome: ScenarioOutcome::InvalidEvidence(reason),
        samples,
        missing_samples,
    }
}

fn failed_record(
    lifecycle: ScenarioLifecycle,
    samples: Vec<MemorySample>,
    missing_samples: usize,
    reason: ScenarioFailure,
) -> ScenarioRunRecord {
    ScenarioRunRecord {
        state: lifecycle.state(),
        outcome: ScenarioOutcome::Failed(reason),
        samples,
        missing_samples,
    }
}
