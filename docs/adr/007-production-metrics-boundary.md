# ADR 007: Production Metrics Boundary

Status: Accepted for Phase 007 baseline

## Context

The data plane already emits bounded `MetricEvent` values through
`std::sync::mpsc::SyncSender::try_send`. The process collector currently drains and
discards them. The sender type is embedded in core and runtime adapters, so adding an
HTTP exporter directly would couple the mio hot path to transport and storage details.

## Current Inventory

| Producer | Current family | Operation intent | Labels | Target family |
| --- | --- | --- | --- | --- |
| completed request | `edge_requests_total` | counter add | `route_id`, `status_class` | `sponzey_edge_requests_total` |
| completed request | `edge_request_duration_ms` | histogram observe, milliseconds | `route_id` | `sponzey_edge_request_duration_seconds` |
| connection lifecycle | `edge_active_connections` | gauge set | none | `sponzey_edge_active_connections` |
| upstream selection | `edge_upstream_selections_total` | counter add | `service_id`, `upstream_id` | `sponzey_edge_upstream_selections_total` |
| upstream transport failure | `edge_upstream_failures_total` | counter add | `route_id`, `upstream_id`, `error_code` | `sponzey_edge_upstream_failures_total` |
| active health transition | `edge_upstream_health_transitions_total` | counter add | `service_id`, `upstream_id`, `from`, `to` | `sponzey_edge_upstream_health_transitions_total` |
| no eligible upstream | `edge_upstream_no_eligible_total` | counter add | `service_id` | `sponzey_edge_upstream_no_eligible_total` |
| failure-aware transition | `edge_failure_aware_transitions_total` | counter add | closed transition fields | `sponzey_edge_failure_aware_transitions_total` |
| TLS failure | `edge_tls_handshake_failures_total` | counter add | `error_code` | `sponzey_edge_tls_handshake_failures_total` |
| certificate startup scan | `edge_certificate_not_after_epoch_seconds` | gauge set | `certificate_ref` | `sponzey_edge_certificate_not_after_seconds` |
| health dispatch | `edge_health_probe_dispatch_dropped_total` | counter add | closed `reason` | internal drop/health family mapping |

Missing target observations are upstream availability, metric event drops, collector
readiness, build identity, and process start time. Their descriptors are added only
after the publication boundary is port-neutral.

Existing IDs come from validated configuration. Raw request paths, query strings,
hosts, endpoints, certificate domains, secrets, request IDs, and revision IDs are not
metric labels. Counter deltas are currently represented by positive `i64`; the typed
contract will replace this ambiguity with unsigned operations.

## Current Call Graph

```text
edge-application metric constructors
  -> edge-core / health runtime / admin runtime producer
  -> bounded SyncSender::try_send
  -> process Receiver
  -> RuntimeMetricDrain
  -> discard
```

Queue capacity is 1,024 in process wiring. Producers never call blocking `send`.
`Full` does not block traffic and increments the existing shared drop counter where it
is wired; `Disconnected` does not block traffic and is treated as a stopped consumer.
The counter is not yet a typed metrics drop counter, which remains Phase 3 work.

## Decision

The target flow is:

```text
producer
  -> MetricPublisher port (nonblocking Accepted | Full | Stopped)
  -> bounded channel adapter
  -> single-writer registry worker
  -> immutable MetricSnapshot reader
  -> Prometheus HTTP adapter / authenticated Admin API adapter
```

- The port and observation DTO contain no channel, thread, HTTP, mio, or encoder type.
- Registry mutation has one writer. Readers only receive immutable snapshots.
- Queue capacity remains 1,024 and publication remains nonblocking.
- The registry enforces 16,384 resident series, the reserved series partition, and the
  4 MiB encoded response estimate before accepting a new series.
- Prometheus encoding is implemented in an outer adapter against golden contract tests.
  No third-party encoder is required initially; adding one later is allowed only in the
  adapter crate and must preserve byte-level contract tests.
- Metrics are a derived operational view and never authorize or commit configuration.

## Listener And Failure Policy

- Metrics are disabled when the canonical `[metrics]` block is absent.
- Explicit enablement accepts loopback addresses only; the default is
  `127.0.0.1:9464`. Environment variables cannot toggle or reconfigure it at runtime.
- A configured listener bind failure fails process startup. A later listener failure
  transitions metrics to `Failed`/not-ready while the existing data plane continues.
- The listener has a bounded accept queue of 16, two workers, 2 second I/O timeouts,
  an 8 KiB request-header limit, and a 4 MiB response limit.
- Only `GET /metrics` is successful. Scrape requests do not produce Product logs.
- Remote exposure, authentication on the Prometheus listener, retention, and bundled
  Prometheus/Grafana are outside this phase.

## State Machines

- Collector: `Created -> Running -> Draining -> Stopped`; startup/runtime invariant
  failure may transition to `Failed`. Shutdown drains to a bounded deadline.
- Listener: `Disabled` or `Binding -> Serving -> Draining -> Stopped`; bind/runtime
  failure transitions to `Failed`.
- Reconciliation: `Idle -> Planning(generation) -> Applying(generation) -> Applied`;
  stale completion is rejected and failure preserves the previous applied generation.
- Readiness is true only when collector/listener requirements are healthy and desired
  generation equals applied generation. Boolean flag combinations are prohibited.

## Logging Decision

- Product: collector/listener lifecycle edges and actionable failure only; no scrape log.
- Field Debug: sampled/TTL-bounded saturation and validation aggregates with stable IDs.
- Development: state transitions and encoder diagnostics, disabled by default in production.
- All modes exclude secrets, request/response bodies, authorization, cookies, raw URLs,
  and unbounded label values.

## Consequences

Phase 1 can replace concrete senders without changing event order or queue behavior.
Typed descriptors and registry policy can then evolve independently of mio and HTTP.
The initial in-process snapshot resets on process restart and provides no retention.
