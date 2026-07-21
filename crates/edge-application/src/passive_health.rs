use std::collections::BTreeMap;

use edge_domain::{
    effective_eligibility, transition_passive_health, ConfigRevisionId, ConfigSnapshot,
    EffectiveEligibility, EffectiveUpstreamState, PassiveHealthEvent, PassiveHealthPolicy,
    PassiveHealthState, UpstreamAvailability, UpstreamHealthKey, UpstreamMembership,
};
use edge_ports::PassiveObservationSubmit;
use edge_ports::{
    HealthAvailabilitySnapshot, HealthGeneration, PassiveObservation, PassiveObservationOutcome,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PassiveObservationDeliveryState {
    #[default]
    Healthy,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassiveObservationDeliveryChange {
    None,
    Degraded,
    Recovered,
}

pub fn transition_passive_observation_delivery(
    state: &mut PassiveObservationDeliveryState,
    result: PassiveObservationSubmit,
) -> PassiveObservationDeliveryChange {
    match (*state, result) {
        (
            PassiveObservationDeliveryState::Healthy,
            PassiveObservationSubmit::Full | PassiveObservationSubmit::Stopped,
        ) => {
            *state = PassiveObservationDeliveryState::Degraded;
            PassiveObservationDeliveryChange::Degraded
        }
        (PassiveObservationDeliveryState::Degraded, PassiveObservationSubmit::Accepted) => {
            *state = PassiveObservationDeliveryState::Healthy;
            PassiveObservationDeliveryChange::Recovered
        }
        _ => PassiveObservationDeliveryChange::None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassiveObservationIgnored {
    StaleRevision,
    StaleGeneration,
    UnknownUpstream,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlePassiveObservation {
    Applied { state: PassiveHealthState },
    Ignored(PassiveObservationIgnored),
}

#[derive(Debug, Clone)]
struct PassiveTarget {
    policy: PassiveHealthPolicy,
    state: PassiveHealthState,
}

#[derive(Debug, Clone)]
pub struct PassiveHealthSupervisor {
    revision_id: ConfigRevisionId,
    generation: HealthGeneration,
    targets: BTreeMap<UpstreamHealthKey, PassiveTarget>,
}

impl PassiveHealthSupervisor {
    pub fn new(revision_id: ConfigRevisionId, generation: HealthGeneration) -> Self {
        Self {
            revision_id,
            generation,
            targets: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, key: UpstreamHealthKey, policy: PassiveHealthPolicy, enabled: bool) {
        self.targets.insert(
            key,
            PassiveTarget {
                policy,
                state: if enabled {
                    PassiveHealthState::observing()
                } else {
                    PassiveHealthState::Disabled
                },
            },
        );
    }

    pub fn handle(&mut self, observation: PassiveObservation) -> HandlePassiveObservation {
        if observation.revision_id != self.revision_id {
            return HandlePassiveObservation::Ignored(PassiveObservationIgnored::StaleRevision);
        }
        if observation.generation != self.generation {
            return HandlePassiveObservation::Ignored(PassiveObservationIgnored::StaleGeneration);
        }
        let Some(target) = self.targets.get_mut(&observation.key) else {
            return HandlePassiveObservation::Ignored(PassiveObservationIgnored::UnknownUpstream);
        };
        if target.state == PassiveHealthState::Disabled {
            return HandlePassiveObservation::Ignored(PassiveObservationIgnored::Disabled);
        }
        let event = match observation.outcome {
            PassiveObservationOutcome::Succeeded => PassiveHealthEvent::Succeeded,
            PassiveObservationOutcome::Failed(_) => PassiveHealthEvent::Failed {
                now_ms: observation.observed_at_ms,
            },
        };
        target.state = transition_passive_health(target.state, event, &target.policy);
        HandlePassiveObservation::Applied {
            state: target.state,
        }
    }

    pub fn state(&self, key: &UpstreamHealthKey) -> Option<PassiveHealthState> {
        self.targets.get(key).map(|target| target.state)
    }

    pub fn expire_cooldowns(&mut self, now_ms: u64) -> bool {
        let mut changed = false;
        for target in self.targets.values_mut() {
            let next = transition_passive_health(
                target.state,
                PassiveHealthEvent::CooldownElapsed { now_ms },
                &target.policy,
            );
            changed |= next != target.state;
            target.state = next;
        }
        changed
    }

    pub fn effective_availability(
        &self,
        config: &ConfigSnapshot,
        active: &HealthAvailabilitySnapshot,
    ) -> HealthAvailabilitySnapshot {
        let mut entries = active.entries.clone();
        for service in &config.services {
            for upstream in &service.upstreams {
                let key = UpstreamHealthKey {
                    service_id: service.id.clone(),
                    upstream_id: upstream.id.clone(),
                };
                let active_health = entries
                    .get(&key)
                    .copied()
                    .unwrap_or(UpstreamAvailability::Unknown);
                let effective = effective_eligibility(&EffectiveUpstreamState {
                    membership: UpstreamMembership::Present,
                    administrative: upstream.administrative_state,
                    active_health,
                    passive_health: self.state(&key).unwrap_or(PassiveHealthState::Disabled),
                });
                entries.insert(
                    key,
                    match effective {
                        EffectiveEligibility::Eligible => active_health,
                        EffectiveEligibility::Excluded(_) => UpstreamAvailability::Unhealthy,
                    },
                );
            }
        }
        HealthAvailabilitySnapshot {
            revision_id: self.revision_id.clone(),
            generation: self.generation,
            entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::{ServiceId, UpstreamId};
    use edge_ports::{PassiveFailureReason, PassiveObservationOutcome};

    fn key() -> UpstreamHealthKey {
        UpstreamHealthKey {
            service_id: ServiceId::new("app"),
            upstream_id: UpstreamId::new("a"),
        }
    }

    fn observation(
        revision: &str,
        generation: u64,
        outcome: PassiveObservationOutcome,
    ) -> PassiveObservation {
        PassiveObservation {
            revision_id: ConfigRevisionId::new(revision),
            generation: HealthGeneration(generation),
            key: key(),
            outcome,
            observed_at_ms: 10,
        }
    }

    #[test]
    fn current_transport_observations_update_passive_state() {
        let mut supervisor =
            PassiveHealthSupervisor::new(ConfigRevisionId::new("rev-1"), HealthGeneration(2));
        supervisor.register(key(), PassiveHealthPolicy::new(2, 1_000).unwrap(), true);
        assert_eq!(
            supervisor.handle(observation(
                "rev-1",
                2,
                PassiveObservationOutcome::Failed(PassiveFailureReason::Connect)
            )),
            HandlePassiveObservation::Applied {
                state: PassiveHealthState::Observing {
                    consecutive_failures: 1
                }
            }
        );
        assert_eq!(
            supervisor.handle(observation(
                "rev-1",
                2,
                PassiveObservationOutcome::Succeeded
            )),
            HandlePassiveObservation::Applied {
                state: PassiveHealthState::observing()
            }
        );
    }

    #[test]
    fn stale_unknown_and_disabled_observations_do_not_mutate_state() {
        let mut supervisor =
            PassiveHealthSupervisor::new(ConfigRevisionId::new("rev-1"), HealthGeneration(2));
        supervisor.register(key(), PassiveHealthPolicy::new(1, 1_000).unwrap(), false);
        assert_eq!(
            supervisor.handle(observation("old", 2, PassiveObservationOutcome::Succeeded)),
            HandlePassiveObservation::Ignored(PassiveObservationIgnored::StaleRevision)
        );
        assert_eq!(
            supervisor.handle(observation(
                "rev-1",
                1,
                PassiveObservationOutcome::Succeeded
            )),
            HandlePassiveObservation::Ignored(PassiveObservationIgnored::StaleGeneration)
        );
        assert_eq!(
            supervisor.handle(observation(
                "rev-1",
                2,
                PassiveObservationOutcome::Succeeded
            )),
            HandlePassiveObservation::Ignored(PassiveObservationIgnored::Disabled)
        );
        assert_eq!(supervisor.state(&key()), Some(PassiveHealthState::Disabled));
    }

    #[test]
    fn observation_delivery_reports_only_degraded_and_recovered_edges() {
        let mut state = PassiveObservationDeliveryState::Healthy;
        assert_eq!(
            transition_passive_observation_delivery(
                &mut state,
                edge_ports::PassiveObservationSubmit::Full
            ),
            PassiveObservationDeliveryChange::Degraded
        );
        assert_eq!(
            transition_passive_observation_delivery(
                &mut state,
                edge_ports::PassiveObservationSubmit::Full
            ),
            PassiveObservationDeliveryChange::None
        );
        assert_eq!(
            transition_passive_observation_delivery(
                &mut state,
                edge_ports::PassiveObservationSubmit::Accepted
            ),
            PassiveObservationDeliveryChange::Recovered
        );
        assert_eq!(state, PassiveObservationDeliveryState::Healthy);
    }

    #[test]
    fn passive_supervisor_expires_ejection_at_supplied_tick_boundary() {
        let mut supervisor =
            PassiveHealthSupervisor::new(ConfigRevisionId::new("rev-1"), HealthGeneration(2));
        supervisor.register(key(), PassiveHealthPolicy::new(1, 1_000).unwrap(), true);
        supervisor.handle(observation(
            "rev-1",
            2,
            PassiveObservationOutcome::Failed(PassiveFailureReason::Connect),
        ));

        assert!(!supervisor.expire_cooldowns(1_009));
        assert!(supervisor.expire_cooldowns(1_010));
        assert_eq!(
            supervisor.state(&key()),
            Some(PassiveHealthState::observing())
        );
    }
}
