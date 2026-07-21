use std::collections::{BTreeMap, VecDeque};

use edge_domain::{ConfigRevisionId, LogMode, RuntimeResourcePolicy};
use edge_ports::{ResourceMetricKind, ResourceRejectionReason, StructuredLogEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLogContext {
    pub revision_id: ConfigRevisionId,
    pub policy: RuntimeResourcePolicy,
    pub used_bytes: usize,
}

impl ResourceLogContext {
    pub fn new(
        revision_id: ConfigRevisionId,
        policy: RuntimeResourcePolicy,
        used_bytes: usize,
    ) -> Self {
        Self {
            revision_id,
            policy,
            used_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePressureLevel {
    Pressured,
    Exhausted,
    FailedClosed,
}

impl ResourcePressureLevel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pressured => "pressured",
            Self::Exhausted => "exhausted",
            Self::FailedClosed => "failed_closed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePressureTransition {
    Entered(ResourcePressureLevel),
    Recovered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestedBytesBucket {
    NotApplicable,
    UpTo4KiB,
    KiB4To64,
    KiB64To1024,
    Over1MiB,
}

impl RequestedBytesBucket {
    pub fn from_bytes(bytes: Option<usize>) -> Self {
        match bytes {
            None => Self::NotApplicable,
            Some(0..=4_096) => Self::UpTo4KiB,
            Some(4_097..=65_536) => Self::KiB4To64,
            Some(65_537..=1_048_576) => Self::KiB64To1024,
            Some(_) => Self::Over1MiB,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::UpTo4KiB => "up_to_4_kib",
            Self::KiB4To64 => "4_64_kib",
            Self::KiB64To1024 => "64_1024_kib",
            Self::Over1MiB => "over_1_mib",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourceAdmissionLogKey {
    pub resource_kind: ResourceMetricKind,
    pub reason: ResourceRejectionReason,
    pub requested_bytes_bucket: RequestedBytesBucket,
}

impl ResourceAdmissionLogKey {
    pub const fn new(
        resource_kind: ResourceMetricKind,
        reason: ResourceRejectionReason,
        requested_bytes_bucket: RequestedBytesBucket,
    ) -> Self {
        Self {
            resource_kind,
            reason,
            requested_bytes_bucket,
        }
    }
}

pub struct ResourceAdmissionLogSampler {
    ttl_seconds: u64,
    capacity: usize,
    emitted_at: BTreeMap<ResourceAdmissionLogKey, u64>,
    insertion_order: VecDeque<ResourceAdmissionLogKey>,
}

impl ResourceAdmissionLogSampler {
    pub fn new(ttl_seconds: u64, capacity: usize) -> Self {
        Self {
            ttl_seconds,
            capacity: capacity.max(1),
            emitted_at: BTreeMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    pub fn should_emit(&mut self, key: ResourceAdmissionLogKey, now_seconds: u64) -> bool {
        if self
            .emitted_at
            .get(&key)
            .is_some_and(|emitted_at| now_seconds.saturating_sub(*emitted_at) < self.ttl_seconds)
        {
            return false;
        }
        if self.emitted_at.remove(&key).is_some() {
            self.insertion_order.retain(|candidate| candidate != &key);
        }
        while self.emitted_at.len() >= self.capacity {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.emitted_at.remove(&oldest);
            }
        }
        self.emitted_at.insert(key, now_seconds);
        self.insertion_order.push_back(key);
        true
    }

    pub fn key_count(&self) -> usize {
        self.emitted_at.len()
    }
}

pub fn structured_resource_policy_active_log(context: &ResourceLogContext) -> StructuredLogEvent {
    StructuredLogEvent {
        component: "edge-core".to_string(),
        event: "resource.policy.active".to_string(),
        fields: vec![
            (
                "revision_id".to_string(),
                context.revision_id.as_str().to_string(),
            ),
            (
                "max_connections".to_string(),
                context.policy.max_connections().to_string(),
            ),
            (
                "max_inflight_payload_bytes".to_string(),
                context.policy.max_inflight_payload_bytes().to_string(),
            ),
        ],
    }
}

pub fn structured_resource_pressure_log(
    transition: ResourcePressureTransition,
    context: &ResourceLogContext,
) -> StructuredLogEvent {
    let (event, state, error_code) = match transition {
        ResourcePressureTransition::Entered(level) => (
            "resource.pressure.entered",
            level.as_str(),
            (level == ResourcePressureLevel::FailedClosed)
                .then_some("RESOURCE_ACCOUNTING_INVARIANT_FAILED"),
        ),
        ResourcePressureTransition::Recovered => ("resource.pressure.recovered", "normal", None),
    };
    let mut fields = resource_status_fields(context);
    fields.insert(1, ("state".to_string(), state.to_string()));
    if let Some(error_code) = error_code {
        fields.push(("error_code".to_string(), error_code.to_string()));
    }
    StructuredLogEvent {
        component: "edge-core".to_string(),
        event: event.to_string(),
        fields,
    }
}

pub fn structured_resource_admission_log(
    mode: &LogMode,
    context: &ResourceLogContext,
    key: ResourceAdmissionLogKey,
) -> StructuredLogEvent {
    let mut fields = resource_status_fields(context);
    fields.insert(
        1,
        (
            "resource_kind".to_string(),
            key.resource_kind.as_str().to_string(),
        ),
    );
    fields.insert(2, ("reason".to_string(), key.reason.as_str().to_string()));
    if matches!(mode, LogMode::FieldDebug | LogMode::Dev) {
        fields.push((
            "requested_bytes_bucket".to_string(),
            key.requested_bytes_bucket.as_str().to_string(),
        ));
    }
    StructuredLogEvent {
        component: "edge-core".to_string(),
        event: "resource.admission.rejected".to_string(),
        fields,
    }
}

fn resource_status_fields(context: &ResourceLogContext) -> Vec<(String, String)> {
    vec![
        (
            "revision_id".to_string(),
            context.revision_id.as_str().to_string(),
        ),
        (
            "limit_bucket".to_string(),
            limit_bucket(context.policy.max_inflight_payload_bytes()).to_string(),
        ),
        (
            "used_percent_bucket".to_string(),
            used_percent_bucket(
                context.used_bytes,
                context.policy.max_inflight_payload_bytes(),
            )
            .to_string(),
        ),
    ]
}

fn limit_bucket(limit_bytes: usize) -> &'static str {
    match limit_bytes / (1_024 * 1_024) {
        0..=63 => "16_63_mib",
        64..=127 => "64_127_mib",
        128..=255 => "128_255_mib",
        _ => "256_512_mib",
    }
}

fn used_percent_bucket(used_bytes: usize, limit_bytes: usize) -> &'static str {
    let percent = used_bytes.saturating_mul(100) / limit_bytes.max(1);
    match percent {
        0..=59 => "0_59",
        60..=79 => "60_79",
        80..=99 => "80_99",
        _ => "100_plus",
    }
}

#[cfg(test)]
mod tests {
    use edge_domain::{ConfigRevisionId, LogMode, RuntimeResourcePolicy};
    use edge_ports::{ResourceMetricKind, ResourceRejectionReason};

    use super::*;

    fn context(used_bytes: usize) -> ResourceLogContext {
        ResourceLogContext::new(
            ConfigRevisionId::new("rev-active"),
            RuntimeResourcePolicy::default(),
            used_bytes,
        )
    }

    #[test]
    fn product_policy_and_pressure_logs_have_exact_safe_fields() {
        let policy = structured_resource_policy_active_log(&context(0));
        let entered = structured_resource_pressure_log(
            ResourcePressureTransition::Entered(ResourcePressureLevel::Pressured),
            &context(108 * 1_024 * 1_024),
        );
        let recovered = structured_resource_pressure_log(
            ResourcePressureTransition::Recovered,
            &context(64 * 1_024 * 1_024),
        );

        assert_eq!(policy.event, "resource.policy.active");
        assert_eq!(
            policy
                .fields
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec![
                "revision_id",
                "max_connections",
                "max_inflight_payload_bytes"
            ]
        );
        assert_eq!(entered.event, "resource.pressure.entered");
        assert_eq!(
            entered.fields,
            vec![
                ("revision_id".to_string(), "rev-active".to_string()),
                ("state".to_string(), "pressured".to_string()),
                ("limit_bucket".to_string(), "128_255_mib".to_string()),
                ("used_percent_bucket".to_string(), "80_99".to_string()),
            ]
        );
        assert_eq!(recovered.event, "resource.pressure.recovered");
        assert!(![policy, entered, recovered].iter().any(|event| {
            event.fields.iter().any(|(key, value)| {
                key.contains("path")
                    || key.contains("client")
                    || key.contains("body")
                    || value.contains("secret")
            })
        }));
    }

    #[test]
    fn field_rejection_adds_only_bounded_buckets_to_product_contract() {
        let key = ResourceAdmissionLogKey::new(
            ResourceMetricKind::Payload,
            ResourceRejectionReason::PayloadPressure,
            RequestedBytesBucket::KiB4To64,
        );
        let product =
            structured_resource_admission_log(&LogMode::Product, &context(120 << 20), key);
        let field =
            structured_resource_admission_log(&LogMode::FieldDebug, &context(120 << 20), key);

        assert_eq!(product.event, "resource.admission.rejected");
        assert!(!product
            .fields
            .iter()
            .any(|(name, _)| name == "requested_bytes_bucket"));
        assert!(field
            .fields
            .contains(&("requested_bytes_bucket".to_string(), "4_64_kib".to_string(),)));
        assert!(field
            .fields
            .iter()
            .all(|(_, value)| !value.contains('/') && !value.contains("127.0.0.1")));
    }

    #[test]
    fn rejection_sampler_enforces_sixty_second_ttl_and_capacity() {
        let mut sampler = ResourceAdmissionLogSampler::new(60, 2);
        let connection = ResourceAdmissionLogKey::new(
            ResourceMetricKind::Connection,
            ResourceRejectionReason::ConnectionLimit,
            RequestedBytesBucket::NotApplicable,
        );
        let payload = ResourceAdmissionLogKey::new(
            ResourceMetricKind::Payload,
            ResourceRejectionReason::PayloadPressure,
            RequestedBytesBucket::KiB4To64,
        );
        let failed = ResourceAdmissionLogKey::new(
            ResourceMetricKind::Payload,
            ResourceRejectionReason::FailedClosed,
            RequestedBytesBucket::NotApplicable,
        );

        assert!(sampler.should_emit(connection, 100));
        assert!(!sampler.should_emit(connection, 159));
        assert!(sampler.should_emit(connection, 160));
        assert!(sampler.should_emit(payload, 161));
        assert!(sampler.should_emit(failed, 162));
        assert_eq!(sampler.key_count(), 2);
        assert!(sampler.should_emit(connection, 163));
        assert_eq!(sampler.key_count(), 2);
        assert!(!sampler.should_emit(connection, 99));
    }
}
