use crate::HarnessError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScenarioState {
    Created,
    Preflight,
    StartingProcesses,
    Warming,
    Loading,
    Cooling,
    Analyzing,
    Passed,
    Failed,
    InvalidEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioEvent {
    PreflightPassed,
    StartRequested,
    ChildReady,
    WarmupCompleted,
    LoadCompleted,
    CooldownCompleted,
    AnalysisPassed,
    OperationalFailed,
    EvidenceRejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScenarioFailure {
    UnsupportedPlatform,
    ProcessStartFailed,
    ProcessExitedEarly,
    SamplerFailed,
    LoadFailed,
    CleanupFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceFailure {
    EmptySamples,
    ProcessIdentityChanged,
    TooManyMissingSamples { expected: usize, missing: usize },
    InvalidTransition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioLifecycle {
    state: ScenarioState,
}

impl ScenarioLifecycle {
    pub fn new() -> Self {
        Self {
            state: ScenarioState::Created,
        }
    }

    pub fn state(&self) -> ScenarioState {
        self.state
    }

    pub fn transition(&mut self, event: ScenarioEvent) -> Result<(), HarnessError> {
        let next = match (self.state, event) {
            (ScenarioState::Created, ScenarioEvent::PreflightPassed) => ScenarioState::Preflight,
            (ScenarioState::Preflight, ScenarioEvent::StartRequested) => {
                ScenarioState::StartingProcesses
            }
            (ScenarioState::StartingProcesses, ScenarioEvent::ChildReady) => ScenarioState::Warming,
            (ScenarioState::Warming, ScenarioEvent::WarmupCompleted) => ScenarioState::Loading,
            (ScenarioState::Loading, ScenarioEvent::LoadCompleted) => ScenarioState::Cooling,
            (ScenarioState::Cooling, ScenarioEvent::CooldownCompleted) => ScenarioState::Analyzing,
            (ScenarioState::Analyzing, ScenarioEvent::AnalysisPassed) => ScenarioState::Passed,
            (
                ScenarioState::Created
                | ScenarioState::Preflight
                | ScenarioState::StartingProcesses
                | ScenarioState::Warming
                | ScenarioState::Loading
                | ScenarioState::Cooling
                | ScenarioState::Analyzing,
                ScenarioEvent::OperationalFailed,
            ) => ScenarioState::Failed,
            (
                ScenarioState::Created
                | ScenarioState::Preflight
                | ScenarioState::StartingProcesses
                | ScenarioState::Warming
                | ScenarioState::Loading
                | ScenarioState::Cooling
                | ScenarioState::Analyzing,
                ScenarioEvent::EvidenceRejected,
            ) => ScenarioState::InvalidEvidence,
            _ => {
                self.state = ScenarioState::InvalidEvidence;
                return Err(HarnessError::new("memory scenario transition is invalid"));
            }
        };
        self.state = next;
        Ok(())
    }
}

impl Default for ScenarioLifecycle {
    fn default() -> Self {
        Self::new()
    }
}
