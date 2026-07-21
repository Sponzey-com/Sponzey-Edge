use std::collections::BTreeMap;
use std::sync::Arc;

use edge_ports::{MetricDescriptor, MetricKind, MetricObservation, MetricOperation};

pub const METRIC_MAX_SERIES: usize = 16_384;
pub const METRIC_MAX_CUMULATIVE_SERIES: usize = 12_288;
pub const METRIC_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MetricDropReason {
    SeriesLimit,
    ResponseBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricReconcileOutcome {
    Applied,
    Stale,
}

#[derive(Debug, Clone, Copy)]
pub struct MetricRegistryLimits {
    max_series: usize,
    max_cumulative_series: usize,
    max_response_bytes: usize,
}

impl Default for MetricRegistryLimits {
    fn default() -> Self {
        Self {
            max_series: METRIC_MAX_SERIES,
            max_cumulative_series: METRIC_MAX_CUMULATIVE_SERIES,
            max_response_bytes: METRIC_MAX_RESPONSE_BYTES,
        }
    }
}

impl MetricRegistryLimits {
    #[cfg(test)]
    fn testing(max_series: usize, max_cumulative_series: usize, max_response_bytes: usize) -> Self {
        Self {
            max_series,
            max_cumulative_series,
            max_response_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MetricSeriesKey {
    pub descriptor: MetricDescriptor,
    pub labels: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricHistogramValue {
    pub count: u64,
    pub sum_ms: u64,
    pub cumulative_buckets: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricSeriesValue {
    Counter(u64),
    Gauge(i64),
    Histogram(MetricHistogramValue),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricSeries {
    pub key: MetricSeriesKey,
    pub value: MetricSeriesValue,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricSnapshot {
    pub series: Vec<MetricSeries>,
    pub estimated_encoded_bytes: usize,
    pub desired_generation: u64,
    pub applied_generation: u64,
    pub ready: bool,
    pub dropped: BTreeMap<MetricDropReason, u64>,
}

pub trait MetricSnapshotReaderPort: Send + Sync {
    fn read_metric_snapshot(&self) -> Result<Arc<MetricSnapshot>, edge_domain::AppError>;
}

impl MetricSnapshot {
    pub fn counter_value(&self, descriptor: MetricDescriptor) -> Option<u64> {
        self.series
            .iter()
            .find_map(|series| (series.key.descriptor == descriptor).then_some(&series.value))
            .and_then(|value| match value {
                MetricSeriesValue::Counter(value) => Some(*value),
                _ => None,
            })
    }
    pub fn gauge_value(&self, descriptor: MetricDescriptor) -> Option<i64> {
        self.series
            .iter()
            .find_map(|series| (series.key.descriptor == descriptor).then_some(&series.value))
            .and_then(|value| match value {
                MetricSeriesValue::Gauge(value) => Some(*value),
                _ => None,
            })
    }
    pub fn histogram(&self, descriptor: MetricDescriptor) -> Option<&MetricHistogramValue> {
        self.series.iter().find_map(|series| {
            if series.key.descriptor == descriptor {
                match &series.value {
                    MetricSeriesValue::Histogram(value) => Some(value),
                    _ => None,
                }
            } else {
                None
            }
        })
    }
}

pub struct MetricRegistry {
    limits: MetricRegistryLimits,
    series: BTreeMap<MetricSeriesKey, MetricSeriesValue>,
    estimated_encoded_bytes: usize,
    cumulative_series: usize,
    desired_generation: u64,
    applied_generation: u64,
    dropped: BTreeMap<MetricDropReason, u64>,
}

impl Default for MetricRegistry {
    fn default() -> Self {
        Self::with_limits(MetricRegistryLimits::default())
    }
}

impl MetricRegistry {
    pub fn with_limits(limits: MetricRegistryLimits) -> Self {
        Self {
            limits,
            series: BTreeMap::new(),
            estimated_encoded_bytes: 0,
            cumulative_series: 0,
            desired_generation: 0,
            applied_generation: 0,
            dropped: BTreeMap::new(),
        }
    }

    pub fn observe(&mut self, observation: MetricObservation) -> Result<(), MetricDropReason> {
        let key = MetricSeriesKey {
            descriptor: observation.descriptor,
            labels: observation.labels,
        };
        let is_new = !self.series.contains_key(&key);
        let cumulative = observation.descriptor.definition().kind != MetricKind::Gauge;
        let estimate = estimate_series_bytes(&key);
        if is_new
            && (self.series.len() >= self.limits.max_series
                || (cumulative && self.cumulative_series >= self.limits.max_cumulative_series))
        {
            return Err(self.reject(MetricDropReason::SeriesLimit));
        }
        if is_new
            && self.estimated_encoded_bytes.saturating_add(estimate)
                > self.limits.max_response_bytes
        {
            return Err(self.reject(MetricDropReason::ResponseBudget));
        }
        let value = self
            .series
            .entry(key)
            .or_insert_with(|| initial_value(observation.descriptor));
        apply_operation(value, observation.operation);
        if is_new {
            self.estimated_encoded_bytes += estimate;
            if cumulative {
                self.cumulative_series += 1;
            }
        }
        Ok(())
    }

    pub fn snapshot(&self) -> MetricSnapshot {
        MetricSnapshot {
            series: self
                .series
                .iter()
                .map(|(key, value)| MetricSeries {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect(),
            estimated_encoded_bytes: self.estimated_encoded_bytes,
            desired_generation: self.desired_generation,
            applied_generation: self.applied_generation,
            ready: self.desired_generation == self.applied_generation,
            dropped: self.dropped.clone(),
        }
    }

    fn reject(&mut self, reason: MetricDropReason) -> MetricDropReason {
        let count = self.dropped.entry(reason).or_default();
        *count = count.saturating_add(1);
        reason
    }

    pub fn set_desired_generation(&mut self, generation: u64) {
        self.desired_generation = generation;
    }

    pub fn mark_applied_generation(&mut self, generation: u64) -> MetricReconcileOutcome {
        if generation != self.desired_generation || generation < self.applied_generation {
            MetricReconcileOutcome::Stale
        } else {
            self.applied_generation = generation;
            MetricReconcileOutcome::Applied
        }
    }
}

fn initial_value(descriptor: MetricDescriptor) -> MetricSeriesValue {
    match descriptor.definition().kind {
        MetricKind::Counter => MetricSeriesValue::Counter(0),
        MetricKind::Gauge => MetricSeriesValue::Gauge(0),
        MetricKind::Histogram => MetricSeriesValue::Histogram(MetricHistogramValue {
            count: 0,
            sum_ms: 0,
            cumulative_buckets: vec![0; descriptor.definition().histogram_buckets_ms.len() + 1],
        }),
    }
}

fn apply_operation(value: &mut MetricSeriesValue, operation: MetricOperation) {
    match (value, operation) {
        (MetricSeriesValue::Counter(total), MetricOperation::CounterAdd(delta)) => {
            *total = total.saturating_add(delta)
        }
        (MetricSeriesValue::Gauge(current), MetricOperation::GaugeSet(next)) => *current = next,
        (MetricSeriesValue::Histogram(histogram), MetricOperation::HistogramObserve(ms)) => {
            histogram.count = histogram.count.saturating_add(1);
            histogram.sum_ms = histogram.sum_ms.saturating_add(ms);
            let finite = histogram.cumulative_buckets.len() - 1;
            for (index, boundary) in
                request_buckets_for(histogram.cumulative_buckets.len()).enumerate()
            {
                if ms <= boundary {
                    histogram.cumulative_buckets[index] =
                        histogram.cumulative_buckets[index].saturating_add(1);
                }
            }
            histogram.cumulative_buckets[finite] =
                histogram.cumulative_buckets[finite].saturating_add(1);
        }
        _ => unreachable!("validated metric operation"),
    }
}

fn request_buckets_for(len: usize) -> impl Iterator<Item = u64> {
    MetricDescriptor::RequestDuration
        .definition()
        .histogram_buckets_ms
        .iter()
        .copied()
        .take(len.saturating_sub(1))
}

fn estimate_series_bytes(key: &MetricSeriesKey) -> usize {
    let definition = key.descriptor.definition();
    128usize
        .saturating_add(definition.name.len())
        .saturating_add(definition.help.len())
        .saturating_add(
            key.labels
                .iter()
                .map(|(key, value)| key.len().saturating_add(value.len()).saturating_add(8))
                .sum::<usize>(),
        )
        .saturating_add(definition.histogram_buckets_ms.len().saturating_mul(96))
}

#[cfg(test)]
mod tests {
    use edge_ports::{MetricDescriptor, MetricObservation};

    use super::*;

    fn request(route: &str, duration_ms: u64) -> [MetricObservation; 2] {
        [
            MetricObservation::counter_add(
                MetricDescriptor::RequestsTotal,
                1,
                vec![
                    ("route_id".into(), route.into()),
                    ("status_class".into(), "2xx".into()),
                ],
            )
            .unwrap(),
            MetricObservation::histogram_observe(
                MetricDescriptor::RequestDuration,
                duration_ms,
                vec![("route_id".into(), route.into())],
            )
            .unwrap(),
        ]
    }

    #[test]
    fn registry_aggregates_counter_gauge_and_histogram_into_ordered_snapshot() {
        let mut registry = MetricRegistry::with_limits(MetricRegistryLimits::testing(16, 8, 4096));
        for observation in request("route-a", 25) {
            registry.observe(observation).unwrap();
        }
        for observation in request("route-a", 50) {
            registry.observe(observation).unwrap();
        }
        registry
            .observe(
                MetricObservation::gauge_set(MetricDescriptor::ActiveConnections, 7, Vec::new())
                    .unwrap(),
            )
            .unwrap();

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.series.len(), 3);
        assert!(snapshot
            .series
            .windows(2)
            .all(|pair| pair[0].key < pair[1].key));
        assert_eq!(
            snapshot.counter_value(MetricDescriptor::RequestsTotal),
            Some(2)
        );
        assert_eq!(
            snapshot.gauge_value(MetricDescriptor::ActiveConnections),
            Some(7)
        );
        let histogram = snapshot
            .histogram(MetricDescriptor::RequestDuration)
            .unwrap();
        assert_eq!(histogram.count, 2);
        assert_eq!(histogram.sum_ms, 75);
        assert_eq!(histogram.cumulative_buckets[2], 1);
        assert_eq!(histogram.cumulative_buckets[3], 2);
    }

    #[test]
    fn registry_rejects_new_series_at_partition_or_response_budget_without_eviction() {
        let mut registry = MetricRegistry::with_limits(MetricRegistryLimits::testing(2, 1, 4096));
        registry.observe(request("route-a", 1)[0].clone()).unwrap();
        let before = registry.snapshot();
        assert_eq!(
            registry.observe(request("route-b", 1)[0].clone()),
            Err(MetricDropReason::SeriesLimit)
        );
        assert_eq!(registry.snapshot().series, before.series);

        let mut tiny = MetricRegistry::with_limits(MetricRegistryLimits::testing(10, 10, 1));
        assert_eq!(
            tiny.observe(request("route-a", 1)[0].clone()),
            Err(MetricDropReason::ResponseBudget)
        );
        assert!(tiny.snapshot().series.is_empty());
    }

    #[test]
    fn reconciliation_generation_exposes_degraded_lag_and_rejects_stale_completion() {
        let mut registry = MetricRegistry::default();
        registry.set_desired_generation(2);
        assert!(!registry.snapshot().ready);
        assert_eq!(
            registry.mark_applied_generation(1),
            MetricReconcileOutcome::Stale
        );
        assert_eq!(registry.snapshot().applied_generation, 0);
        assert_eq!(
            registry.mark_applied_generation(2),
            MetricReconcileOutcome::Applied
        );
        assert!(registry.snapshot().ready);
    }
}
