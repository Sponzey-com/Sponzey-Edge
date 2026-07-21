use serde::{Deserialize, Serialize};

use crate::report_io::sha256_hex;
use crate::HarnessError;

pub const SLOW_HEADER_CYCLE_COUNT: u32 = 5;
pub const SLOW_HEADER_CONNECTIONS: u64 = 256;
pub const SLOW_HEADER_MINIMUM_PAYLOAD_BYTES: u64 = 256 * 41;
pub const SLOW_HEADER_RSS_CEILING_BYTES: u64 = 384 * 1024 * 1024;
pub const SLOW_HEADER_PLATEAU_FLOOR_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlowHeaderCycleObservation {
    pub cycle_index: u32,
    pub build_identity: String,
    pub config_sha256: String,
    pub process_start_identity: String,
    pub expected: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub held_payload_bytes: u64,
    pub peak_rss_bytes: u64,
    pub cooldown_rss_bytes: u64,
    pub cleanup_connections: u64,
    pub cleanup_payload_bytes: u64,
    pub cleanup_pressure: String,
    pub recovery_status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlowHeaderCycleInput {
    pub observations: Vec<SlowHeaderCycleObservation>,
}

impl SlowHeaderCycleInput {
    pub fn from_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("slow header cycle input is invalid"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlowHeaderCycleResult {
    pub cycle_index: u32,
    pub peak_rss_bytes: u64,
    pub cooldown_rss_bytes: u64,
    pub held_payload_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlowHeaderCycleReport {
    pub schema_version: u32,
    pub profile_id: String,
    pub scenario_version: String,
    pub build_identity: String,
    pub config_sha256: String,
    pub process_identity_sha256: String,
    pub cycle_count: u32,
    pub expected_per_cycle: u64,
    pub first_cooldown_median_rss_bytes: u64,
    pub last_cooldown_median_rss_bytes: u64,
    pub plateau_tolerance_bytes: u64,
    pub plateau_passed: bool,
    pub correctness_failures: u32,
    pub cleanup_failures: u32,
    pub rss_ceiling_bytes: u64,
    pub cycles: Vec<SlowHeaderCycleResult>,
}

impl SlowHeaderCycleReport {
    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.schema_version != 1
            || self.profile_id != "phase011-slow-header-5cycle-v1"
            || self.scenario_version != "phase011-v1"
            || !valid_build_identity(&self.build_identity)
            || !valid_digest(&self.config_sha256)
            || !valid_digest(&self.process_identity_sha256)
            || self.cycle_count != SLOW_HEADER_CYCLE_COUNT
            || self.expected_per_cycle != SLOW_HEADER_CONNECTIONS
            || self.cycles.len() != SLOW_HEADER_CYCLE_COUNT as usize
            || !self.plateau_passed
            || self.correctness_failures != 0
            || self.cleanup_failures != 0
            || self.rss_ceiling_bytes != SLOW_HEADER_RSS_CEILING_BYTES
        {
            return Err(HarnessError::new(
                "slow header cycle report header is invalid",
            ));
        }
        let expected_tolerance = plateau_tolerance(self.first_cooldown_median_rss_bytes)?;
        if self.plateau_tolerance_bytes != expected_tolerance
            || self.last_cooldown_median_rss_bytes
                > self
                    .first_cooldown_median_rss_bytes
                    .checked_add(expected_tolerance)
                    .ok_or_else(|| HarnessError::new("slow header plateau overflows"))?
        {
            return Err(HarnessError::new("slow header cycle plateau is invalid"));
        }
        for (position, cycle) in self.cycles.iter().enumerate() {
            if cycle.cycle_index != position as u32 + 1
                || cycle.peak_rss_bytes == 0
                || cycle.peak_rss_bytes > SLOW_HEADER_RSS_CEILING_BYTES
                || cycle.cooldown_rss_bytes == 0
                || cycle.cooldown_rss_bytes > cycle.peak_rss_bytes
                || cycle.held_payload_bytes < SLOW_HEADER_MINIMUM_PAYLOAD_BYTES
            {
                return Err(HarnessError::new("slow header cycle result is invalid"));
            }
        }
        if self.first_cooldown_median_rss_bytes
            != median_of_pair(
                self.cycles[0].cooldown_rss_bytes,
                self.cycles[1].cooldown_rss_bytes,
            )?
            || self.last_cooldown_median_rss_bytes
                != median_of_pair(
                    self.cycles[3].cooldown_rss_bytes,
                    self.cycles[4].cooldown_rss_bytes,
                )?
        {
            return Err(HarnessError::new(
                "slow header cycle cooldown summary is invalid",
            ));
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, HarnessError> {
        self.validate()?;
        let mut encoded = serde_json::to_string_pretty(self)
            .map_err(|_| HarnessError::new("slow header cycle encoding failed"))?;
        encoded.push('\n');
        Ok(encoded)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        let report: Self = serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("slow header cycle decoding failed"))?;
        report.validate()?;
        if report.to_canonical_json()?.as_bytes() != bytes {
            return Err(HarnessError::new(
                "slow header cycle report is not canonical",
            ));
        }
        Ok(report)
    }
}

pub fn evaluate_slow_header_cycles(
    observations: Vec<SlowHeaderCycleObservation>,
) -> Result<SlowHeaderCycleReport, HarnessError> {
    if observations.len() != SLOW_HEADER_CYCLE_COUNT as usize {
        return Err(HarnessError::new(
            "slow header profile requires exactly five cycles",
        ));
    }
    let first = &observations[0];
    let mut cycles = Vec::with_capacity(observations.len());
    for (position, observation) in observations.iter().enumerate() {
        if observation.cycle_index != position as u32 + 1
            || observation.build_identity != first.build_identity
            || observation.config_sha256 != first.config_sha256
            || observation.process_start_identity != first.process_start_identity
            || observation.expected != SLOW_HEADER_CONNECTIONS
            || observation.succeeded != SLOW_HEADER_CONNECTIONS
            || observation.failed != 0
            || observation.held_payload_bytes < SLOW_HEADER_MINIMUM_PAYLOAD_BYTES
            || observation.peak_rss_bytes == 0
            || observation.peak_rss_bytes > SLOW_HEADER_RSS_CEILING_BYTES
            || observation.cooldown_rss_bytes == 0
            || observation.cooldown_rss_bytes > observation.peak_rss_bytes
            || observation.cleanup_connections != 0
            || observation.cleanup_payload_bytes != 0
            || observation.cleanup_pressure != "normal"
            || observation.recovery_status != 200
        {
            return Err(HarnessError::new(
                "slow header cycle observation is invalid",
            ));
        }
        cycles.push(SlowHeaderCycleResult {
            cycle_index: observation.cycle_index,
            peak_rss_bytes: observation.peak_rss_bytes,
            cooldown_rss_bytes: observation.cooldown_rss_bytes,
            held_payload_bytes: observation.held_payload_bytes,
        });
    }
    let first_cooldown_median =
        median_of_pair(cycles[0].cooldown_rss_bytes, cycles[1].cooldown_rss_bytes)?;
    let last_cooldown_median =
        median_of_pair(cycles[3].cooldown_rss_bytes, cycles[4].cooldown_rss_bytes)?;
    let tolerance = plateau_tolerance(first_cooldown_median)?;
    if last_cooldown_median
        > first_cooldown_median
            .checked_add(tolerance)
            .ok_or_else(|| HarnessError::new("slow header plateau overflows"))?
    {
        return Err(HarnessError::new(
            "slow header cooldown plateau threshold exceeded",
        ));
    }
    let report = SlowHeaderCycleReport {
        schema_version: 1,
        profile_id: "phase011-slow-header-5cycle-v1".to_string(),
        scenario_version: "phase011-v1".to_string(),
        build_identity: first.build_identity.clone(),
        config_sha256: first.config_sha256.clone(),
        process_identity_sha256: sha256_hex(first.process_start_identity.as_bytes()),
        cycle_count: SLOW_HEADER_CYCLE_COUNT,
        expected_per_cycle: SLOW_HEADER_CONNECTIONS,
        first_cooldown_median_rss_bytes: first_cooldown_median,
        last_cooldown_median_rss_bytes: last_cooldown_median,
        plateau_tolerance_bytes: tolerance,
        plateau_passed: true,
        correctness_failures: 0,
        cleanup_failures: 0,
        rss_ceiling_bytes: SLOW_HEADER_RSS_CEILING_BYTES,
        cycles,
    };
    report.validate()?;
    Ok(report)
}

fn plateau_tolerance(first: u64) -> Result<u64, HarnessError> {
    if first == 0 {
        return Err(HarnessError::new("slow header plateau baseline is invalid"));
    }
    Ok(SLOW_HEADER_PLATEAU_FLOOR_BYTES.max(first / 10))
}

fn median_of_pair(left: u64, right: u64) -> Result<u64, HarnessError> {
    left.checked_add(right)
        .map(|sum| sum / 2)
        .ok_or_else(|| HarnessError::new("slow header cooldown median overflows"))
}

fn valid_build_identity(value: &str) -> bool {
    value
        .strip_prefix("source-tree-sha256:")
        .is_some_and(valid_digest)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
