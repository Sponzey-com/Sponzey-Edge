use serde::{Deserialize, Serialize};

use crate::report_io::sha256_hex;
use crate::HarnessError;

pub const WEBSOCKET_CYCLE_COUNT: u32 = 5;
pub const WEBSOCKET_CONNECTIONS: u64 = 128;
pub const WEBSOCKET_MINIMUM_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024;
pub const WEBSOCKET_RSS_CEILING_BYTES: u64 = 384 * 1024 * 1024;
pub const WEBSOCKET_PLATEAU_FLOOR_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketCycleObservation {
    pub cycle_index: u32,
    pub build_identity: String,
    pub config_sha256: String,
    pub process_start_identity: String,
    pub expected: u64,
    pub upgraded: u64,
    pub echoed: u64,
    pub held: u64,
    pub released: u64,
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
pub struct WebSocketCycleInput {
    pub observations: Vec<WebSocketCycleObservation>,
}

impl WebSocketCycleInput {
    pub fn from_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("WebSocket cycle input is invalid"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketCycleResult {
    pub cycle_index: u32,
    pub held_payload_bytes: u64,
    pub peak_rss_bytes: u64,
    pub cooldown_rss_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketCycleReport {
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
    pub cycles: Vec<WebSocketCycleResult>,
}

impl WebSocketCycleReport {
    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.schema_version != 1
            || self.profile_id != "phase011-websocket-5cycle-v1"
            || self.scenario_version != "phase011-v1"
            || !valid_build_identity(&self.build_identity)
            || !valid_digest(&self.config_sha256)
            || !valid_digest(&self.process_identity_sha256)
            || self.cycle_count != WEBSOCKET_CYCLE_COUNT
            || self.expected_per_cycle != WEBSOCKET_CONNECTIONS
            || self.cycles.len() != WEBSOCKET_CYCLE_COUNT as usize
            || !self.plateau_passed
            || self.correctness_failures != 0
            || self.cleanup_failures != 0
            || self.rss_ceiling_bytes != WEBSOCKET_RSS_CEILING_BYTES
        {
            return Err(HarnessError::new(
                "WebSocket cycle report header is invalid",
            ));
        }
        for (position, cycle) in self.cycles.iter().enumerate() {
            if cycle.cycle_index != position as u32 + 1
                || cycle.held_payload_bytes < WEBSOCKET_MINIMUM_PAYLOAD_BYTES
                || cycle.peak_rss_bytes == 0
                || cycle.peak_rss_bytes > WEBSOCKET_RSS_CEILING_BYTES
                || cycle.cooldown_rss_bytes == 0
                || cycle.cooldown_rss_bytes > cycle.peak_rss_bytes
            {
                return Err(HarnessError::new("WebSocket cycle result is invalid"));
            }
        }
        let first = median_of_pair(
            self.cycles[0].cooldown_rss_bytes,
            self.cycles[1].cooldown_rss_bytes,
        )?;
        let last = median_of_pair(
            self.cycles[3].cooldown_rss_bytes,
            self.cycles[4].cooldown_rss_bytes,
        )?;
        let tolerance = plateau_tolerance(first)?;
        if self.first_cooldown_median_rss_bytes != first
            || self.last_cooldown_median_rss_bytes != last
            || self.plateau_tolerance_bytes != tolerance
            || last
                > first
                    .checked_add(tolerance)
                    .ok_or_else(|| HarnessError::new("WebSocket plateau overflows"))?
        {
            return Err(HarnessError::new("WebSocket cycle plateau is invalid"));
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, HarnessError> {
        self.validate()?;
        let mut encoded = serde_json::to_string_pretty(self)
            .map_err(|_| HarnessError::new("WebSocket cycle encoding failed"))?;
        encoded.push('\n');
        Ok(encoded)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, HarnessError> {
        let report: Self = serde_json::from_slice(bytes)
            .map_err(|_| HarnessError::new("WebSocket cycle decoding failed"))?;
        report.validate()?;
        if report.to_canonical_json()?.as_bytes() != bytes {
            return Err(HarnessError::new("WebSocket cycle report is not canonical"));
        }
        Ok(report)
    }
}

pub fn evaluate_websocket_cycles(
    observations: Vec<WebSocketCycleObservation>,
) -> Result<WebSocketCycleReport, HarnessError> {
    if observations.len() != WEBSOCKET_CYCLE_COUNT as usize {
        return Err(HarnessError::new(
            "WebSocket profile requires exactly five cycles",
        ));
    }
    let first_observation = &observations[0];
    let mut cycles = Vec::with_capacity(observations.len());
    for (position, observation) in observations.iter().enumerate() {
        if observation.cycle_index != position as u32 + 1
            || observation.build_identity != first_observation.build_identity
            || observation.config_sha256 != first_observation.config_sha256
            || observation.process_start_identity != first_observation.process_start_identity
            || observation.expected != WEBSOCKET_CONNECTIONS
            || observation.upgraded != WEBSOCKET_CONNECTIONS
            || observation.echoed != WEBSOCKET_CONNECTIONS
            || observation.held != WEBSOCKET_CONNECTIONS
            || observation.released != WEBSOCKET_CONNECTIONS
            || observation.failed != 0
            || observation.held_payload_bytes < WEBSOCKET_MINIMUM_PAYLOAD_BYTES
            || observation.peak_rss_bytes == 0
            || observation.peak_rss_bytes > WEBSOCKET_RSS_CEILING_BYTES
            || observation.cooldown_rss_bytes == 0
            || observation.cooldown_rss_bytes > observation.peak_rss_bytes
            || observation.cleanup_connections != 0
            || observation.cleanup_payload_bytes != 0
            || observation.cleanup_pressure != "normal"
            || observation.recovery_status != 200
        {
            return Err(HarnessError::new("WebSocket cycle observation is invalid"));
        }
        cycles.push(WebSocketCycleResult {
            cycle_index: observation.cycle_index,
            held_payload_bytes: observation.held_payload_bytes,
            peak_rss_bytes: observation.peak_rss_bytes,
            cooldown_rss_bytes: observation.cooldown_rss_bytes,
        });
    }

    let first = median_of_pair(cycles[0].cooldown_rss_bytes, cycles[1].cooldown_rss_bytes)?;
    let last = median_of_pair(cycles[3].cooldown_rss_bytes, cycles[4].cooldown_rss_bytes)?;
    let tolerance = plateau_tolerance(first)?;
    if last
        > first
            .checked_add(tolerance)
            .ok_or_else(|| HarnessError::new("WebSocket plateau overflows"))?
    {
        return Err(HarnessError::new(
            "WebSocket cooldown plateau threshold exceeded",
        ));
    }

    let report = WebSocketCycleReport {
        schema_version: 1,
        profile_id: "phase011-websocket-5cycle-v1".to_string(),
        scenario_version: "phase011-v1".to_string(),
        build_identity: first_observation.build_identity.clone(),
        config_sha256: first_observation.config_sha256.clone(),
        process_identity_sha256: sha256_hex(first_observation.process_start_identity.as_bytes()),
        cycle_count: WEBSOCKET_CYCLE_COUNT,
        expected_per_cycle: WEBSOCKET_CONNECTIONS,
        first_cooldown_median_rss_bytes: first,
        last_cooldown_median_rss_bytes: last,
        plateau_tolerance_bytes: tolerance,
        plateau_passed: true,
        correctness_failures: 0,
        cleanup_failures: 0,
        rss_ceiling_bytes: WEBSOCKET_RSS_CEILING_BYTES,
        cycles,
    };
    report.validate()?;
    Ok(report)
}

fn plateau_tolerance(first: u64) -> Result<u64, HarnessError> {
    if first == 0 {
        return Err(HarnessError::new("WebSocket plateau baseline is invalid"));
    }
    Ok(WEBSOCKET_PLATEAU_FLOOR_BYTES.max(first / 10))
}

fn median_of_pair(left: u64, right: u64) -> Result<u64, HarnessError> {
    left.checked_add(right)
        .map(|sum| sum / 2)
        .ok_or_else(|| HarnessError::new("WebSocket cooldown median overflows"))
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
