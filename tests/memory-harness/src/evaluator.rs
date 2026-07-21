use crate::HarnessError;

const PLATEAU_MINIMUM_TOLERANCE_BYTES: u64 = 16 * 1024 * 1024;
const MINIMUM_COOLDOWN_CYCLES: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptancePolicy {
    absolute_ceiling_bytes: u64,
    expected_requests: u64,
}

impl AcceptancePolicy {
    pub fn new(absolute_ceiling_bytes: u64, expected_requests: u64) -> Result<Self, HarnessError> {
        if absolute_ceiling_bytes == 0 {
            return Err(HarnessError::new(
                "memory acceptance ceiling must be positive",
            ));
        }
        Ok(Self {
            absolute_ceiling_bytes,
            expected_requests,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioObservation {
    pub peak_rss_bytes: u64,
    pub cooldown_cycle_medians: Vec<u64>,
    pub process_alive: bool,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub active_connections_after_cooldown: u64,
    pub charged_payload_bytes_after_cooldown: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptanceFailure {
    AbsoluteCeilingExceeded,
    InsufficientCooldownCycles,
    CooldownPlateauExceeded,
    ArithmeticOverflow,
    ProcessNotAlive,
    RequestCountMismatch,
    RequestsFailed,
    ActiveConnectionsRemain,
    PayloadChargesRemain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptanceResult {
    Passed,
    Failed(Vec<AcceptanceFailure>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceEvaluation {
    pub result: AcceptanceResult,
    pub first_cooldown_median_bytes: u64,
    pub last_cooldown_median_bytes: u64,
    pub plateau_tolerance_bytes: u64,
}

pub fn evaluate_scenario(
    policy: &AcceptancePolicy,
    observation: &ScenarioObservation,
) -> AcceptanceEvaluation {
    let mut failures = Vec::new();
    if observation.peak_rss_bytes > policy.absolute_ceiling_bytes {
        failures.push(AcceptanceFailure::AbsoluteCeilingExceeded);
    }

    let plateau = evaluate_plateau(&observation.cooldown_cycle_medians);
    let (first, last, tolerance) = match plateau {
        Ok(values) => values,
        Err(reason) => {
            failures.push(reason);
            (0, 0, 0)
        }
    };

    if !observation.process_alive {
        failures.push(AcceptanceFailure::ProcessNotAlive);
    }
    match observation
        .successful_requests
        .checked_add(observation.failed_requests)
    {
        Some(total) if total == policy.expected_requests => {}
        Some(_) => failures.push(AcceptanceFailure::RequestCountMismatch),
        None => failures.push(AcceptanceFailure::ArithmeticOverflow),
    }
    if observation.failed_requests != 0 {
        failures.push(AcceptanceFailure::RequestsFailed);
    }
    if observation.active_connections_after_cooldown != 0 {
        failures.push(AcceptanceFailure::ActiveConnectionsRemain);
    }
    if observation.charged_payload_bytes_after_cooldown != 0 {
        failures.push(AcceptanceFailure::PayloadChargesRemain);
    }

    AcceptanceEvaluation {
        result: if failures.is_empty() {
            AcceptanceResult::Passed
        } else {
            AcceptanceResult::Failed(failures)
        },
        first_cooldown_median_bytes: first,
        last_cooldown_median_bytes: last,
        plateau_tolerance_bytes: tolerance,
    }
}

fn evaluate_plateau(cycles: &[u64]) -> Result<(u64, u64, u64), AcceptanceFailure> {
    if cycles.len() < MINIMUM_COOLDOWN_CYCLES {
        return Err(AcceptanceFailure::InsufficientCooldownCycles);
    }
    let first = pair_median(cycles[0], cycles[1])?;
    let last = pair_median(cycles[cycles.len() - 2], cycles[cycles.len() - 1])?;
    let tolerance = PLATEAU_MINIMUM_TOLERANCE_BYTES.max(first / 10);
    let maximum = first
        .checked_add(tolerance)
        .ok_or(AcceptanceFailure::ArithmeticOverflow)?;
    if last > maximum {
        return Err(AcceptanceFailure::CooldownPlateauExceeded);
    }
    Ok((first, last, tolerance))
}

fn pair_median(left: u64, right: u64) -> Result<u64, AcceptanceFailure> {
    left.checked_add(right)
        .map(|sum| sum / 2)
        .ok_or(AcceptanceFailure::ArithmeticOverflow)
}
