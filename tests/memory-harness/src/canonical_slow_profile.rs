use crate::HarnessError;

pub const CANONICAL_SLOW_HEADER_CONNECTIONS: u64 = 256;
pub const CANONICAL_SLOW_BODY_CONNECTIONS: u64 = 128;
pub const CANONICAL_DECLARED_BODY_BYTES: u64 = 65_536;
pub const CANONICAL_SENT_BODY_BYTES: u64 = 32_768;
pub const CANONICAL_SLOW_HEADER_RSS_CEILING_BYTES: u64 = 384 * 1024 * 1024;
pub const CANONICAL_SLOW_BODY_RSS_CEILING_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalSlowRequestProfile {
    pub profile_id: &'static str,
    pub scenario_version: &'static str,
    pub slow_header_connections: u64,
    pub slow_body_connections: u64,
    pub declared_body_bytes: u64,
    pub sent_body_bytes: u64,
    pub slow_header_rss_ceiling_bytes: u64,
    pub slow_body_rss_ceiling_bytes: u64,
}

impl CanonicalSlowRequestProfile {
    pub fn phase011() -> Result<Self, HarnessError> {
        let profile = Self {
            profile_id: "phase011-slow-request-capacity-v1",
            scenario_version: "phase011-v1",
            slow_header_connections: CANONICAL_SLOW_HEADER_CONNECTIONS,
            slow_body_connections: CANONICAL_SLOW_BODY_CONNECTIONS,
            declared_body_bytes: CANONICAL_DECLARED_BODY_BYTES,
            sent_body_bytes: CANONICAL_SENT_BODY_BYTES,
            slow_header_rss_ceiling_bytes: CANONICAL_SLOW_HEADER_RSS_CEILING_BYTES,
            slow_body_rss_ceiling_bytes: CANONICAL_SLOW_BODY_RSS_CEILING_BYTES,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.profile_id != "phase011-slow-request-capacity-v1"
            || self.scenario_version != "phase011-v1"
            || self.slow_header_connections != CANONICAL_SLOW_HEADER_CONNECTIONS
            || self.slow_body_connections != CANONICAL_SLOW_BODY_CONNECTIONS
            || self.declared_body_bytes != CANONICAL_DECLARED_BODY_BYTES
            || self.sent_body_bytes != CANONICAL_SENT_BODY_BYTES
            || self.sent_body_bytes >= self.declared_body_bytes
            || self.slow_header_rss_ceiling_bytes != CANONICAL_SLOW_HEADER_RSS_CEILING_BYTES
            || self.slow_body_rss_ceiling_bytes != CANONICAL_SLOW_BODY_RSS_CEILING_BYTES
        {
            return Err(HarnessError::new(
                "canonical slow request profile is invalid",
            ));
        }
        self.minimum_slow_body_payload_bytes()?;
        Ok(())
    }

    pub fn minimum_slow_body_payload_bytes(&self) -> Result<u64, HarnessError> {
        self.slow_body_connections
            .checked_mul(self.sent_body_bytes)
            .ok_or_else(|| HarnessError::new("canonical slow body payload overflows"))
    }
}
