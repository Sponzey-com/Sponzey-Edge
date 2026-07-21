use std::collections::{BTreeMap, VecDeque};

use edge_domain::{ConfigRevisionId, HealthGeneration, UpstreamHealthKey};
use edge_ports::{MetricDescriptor, MetricEvent, StructuredLogEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsFailureComponent {
    Listener,
    Upstream,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TlsFailureObservation {
    pub component: TlsFailureComponent,
    pub resource_id: String,
    pub error_code: String,
}

impl TlsFailureObservation {
    pub fn new(
        component: TlsFailureComponent,
        resource_id: impl Into<String>,
        error_code: impl Into<String>,
    ) -> Self {
        Self {
            component,
            resource_id: resource_id.into(),
            error_code: error_code.into(),
        }
    }
}

pub struct TlsFailureProductSampler {
    ttl_seconds: u64,
    capacity: usize,
    emitted_at: BTreeMap<TlsFailureObservation, u64>,
    insertion_order: VecDeque<TlsFailureObservation>,
}

impl TlsFailureProductSampler {
    pub fn new(ttl_seconds: u64, capacity: usize) -> Self {
        Self {
            ttl_seconds,
            capacity: capacity.max(1),
            emitted_at: BTreeMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    pub fn observe(
        &mut self,
        observation: TlsFailureObservation,
        now_epoch_seconds: u64,
    ) -> Option<StructuredLogEvent> {
        if self.emitted_at.get(&observation).is_some_and(|emitted_at| {
            now_epoch_seconds.saturating_sub(*emitted_at) < self.ttl_seconds
        }) {
            return None;
        }
        if self.emitted_at.remove(&observation).is_some() {
            self.insertion_order.retain(|key| key != &observation);
        }
        while self.emitted_at.len() >= self.capacity {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.emitted_at.remove(&oldest);
            }
        }
        self.emitted_at
            .insert(observation.clone(), now_epoch_seconds);
        self.insertion_order.push_back(observation.clone());
        Some(structured_tls_failure_log(&observation))
    }

    pub fn key_count(&self) -> usize {
        self.emitted_at.len()
    }
}

pub fn structured_tls_failure_log(observation: &TlsFailureObservation) -> StructuredLogEvent {
    let (event, resource_field) = match observation.component {
        TlsFailureComponent::Listener => ("client_auth.handshake.failure", "listener_id"),
        TlsFailureComponent::Upstream => ("upstream_tls.handshake.failure", "upstream_id"),
    };
    StructuredLogEvent {
        component: "edge-application".to_string(),
        event: event.to_string(),
        fields: vec![
            (resource_field.to_string(), observation.resource_id.clone()),
            ("error_code".to_string(), observation.error_code.clone()),
        ],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureAwareTransition {
    PassiveEjected,
    PassiveRecovered,
    DrainStarted,
    DrainCompleted,
    RetryExhausted,
    ObservationDegraded,
    ObservationRecovered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureAwareEvent {
    pub transition: FailureAwareTransition,
    pub revision_id: ConfigRevisionId,
    pub generation: HealthGeneration,
    pub key: Option<UpstreamHealthKey>,
    pub reason: Option<&'static str>,
    pub connection_count: Option<u64>,
}

pub fn structured_failure_aware_log(event: &FailureAwareEvent) -> StructuredLogEvent {
    let mut fields = vec![
        (
            "revision_id".to_string(),
            event.revision_id.as_str().to_string(),
        ),
        ("generation".to_string(), event.generation.0.to_string()),
    ];
    if let Some(key) = &event.key {
        fields.push((
            "service_id".to_string(),
            key.service_id.as_str().to_string(),
        ));
        fields.push((
            "upstream_id".to_string(),
            key.upstream_id.as_str().to_string(),
        ));
    }
    if let Some(reason) = event.reason {
        fields.push(("reason".to_string(), reason.to_string()));
    }
    if let Some(count) = event.connection_count {
        fields.push(("connection_count".to_string(), count.to_string()));
    }
    StructuredLogEvent {
        component: "edge-application".to_string(),
        event: transition_name(event.transition).to_string(),
        fields,
    }
}

pub fn failure_aware_metric(event: &FailureAwareEvent) -> MetricEvent {
    let labels = vec![
        (
            "event".to_string(),
            transition_label(event.transition).to_string(),
        ),
        (
            "reason".to_string(),
            event.reason.unwrap_or("none").to_string(),
        ),
    ];
    MetricEvent::counter_add(MetricDescriptor::FailureAwareTransitionsTotal, 1, labels)
        .expect("failure-aware metric contract")
}

fn transition_name(transition: FailureAwareTransition) -> &'static str {
    match transition {
        FailureAwareTransition::PassiveEjected => "upstream.passive_ejected",
        FailureAwareTransition::PassiveRecovered => "upstream.passive_recovered",
        FailureAwareTransition::DrainStarted => "upstream.drain_started",
        FailureAwareTransition::DrainCompleted => "upstream.drain_completed",
        FailureAwareTransition::RetryExhausted => "proxy.retry_exhausted",
        FailureAwareTransition::ObservationDegraded => "passive_observation.degraded",
        FailureAwareTransition::ObservationRecovered => "passive_observation.recovered",
    }
}

fn transition_label(transition: FailureAwareTransition) -> &'static str {
    transition_name(transition)
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::{ServiceId, UpstreamId};

    #[test]
    fn product_transition_log_has_exact_safe_bounded_fields() {
        let log = structured_failure_aware_log(&FailureAwareEvent {
            transition: FailureAwareTransition::PassiveEjected,
            revision_id: ConfigRevisionId::new("rev-1"),
            generation: HealthGeneration(3),
            key: Some(UpstreamHealthKey {
                service_id: ServiceId::new("app"),
                upstream_id: UpstreamId::new("a"),
            }),
            reason: Some("connect"),
            connection_count: None,
        });
        assert_eq!(log.event, "upstream.passive_ejected");
        assert_eq!(
            log.fields
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec![
                "revision_id",
                "generation",
                "service_id",
                "upstream_id",
                "reason"
            ]
        );
        let rendered = format!("{log:?}");
        for forbidden in ["endpoint", "authorization", "cookie", "body", "private_key"] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn metric_uses_fixed_name_and_bounded_transition_labels() {
        for transition in [
            FailureAwareTransition::PassiveEjected,
            FailureAwareTransition::PassiveRecovered,
            FailureAwareTransition::DrainStarted,
            FailureAwareTransition::DrainCompleted,
            FailureAwareTransition::RetryExhausted,
            FailureAwareTransition::ObservationDegraded,
            FailureAwareTransition::ObservationRecovered,
        ] {
            let metric = failure_aware_metric(&FailureAwareEvent {
                transition,
                revision_id: ConfigRevisionId::new("rev"),
                generation: HealthGeneration(1),
                key: None,
                reason: None,
                connection_count: None,
            });
            assert_eq!(
                metric.descriptor,
                MetricDescriptor::FailureAwareTransitionsTotal
            );
            assert_eq!(metric.labels.len(), 2);
        }
    }

    #[test]
    fn tls_failure_sampler_suppresses_same_key_until_ttl_expires() {
        let mut sampler = TlsFailureProductSampler::new(60, 8);
        let observation = TlsFailureObservation::new(
            TlsFailureComponent::Upstream,
            "backend-a",
            "TLS_HANDSHAKE_FAILED",
        );

        assert!(sampler.observe(observation.clone(), 100).is_some());
        assert!(sampler.observe(observation.clone(), 159).is_none());
        assert!(sampler.observe(observation, 160).is_some());
    }

    #[test]
    fn tls_failure_sampler_evicts_oldest_key_at_capacity() {
        let mut sampler = TlsFailureProductSampler::new(60, 2);
        let observation = |resource| {
            TlsFailureObservation::new(
                TlsFailureComponent::Listener,
                resource,
                "TLS_HANDSHAKE_FAILED",
            )
        };

        assert!(sampler.observe(observation("listener-a"), 100).is_some());
        assert!(sampler.observe(observation("listener-b"), 101).is_some());
        assert!(sampler.observe(observation("listener-c"), 102).is_some());
        assert_eq!(sampler.key_count(), 2);
        assert!(sampler.observe(observation("listener-a"), 103).is_some());
    }

    #[test]
    fn tls_failure_product_log_has_only_safe_bounded_fields() {
        let event = structured_tls_failure_log(&TlsFailureObservation::new(
            TlsFailureComponent::Listener,
            "public-https",
            "TLS_HANDSHAKE_TIMEOUT",
        ));

        assert_eq!(event.event, "client_auth.handshake.failure");
        assert_eq!(
            event.fields,
            vec![
                ("listener_id".to_string(), "public-https".to_string()),
                (
                    "error_code".to_string(),
                    "TLS_HANDSHAKE_TIMEOUT".to_string()
                )
            ]
        );
    }
}
