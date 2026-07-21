# Multi-Upstream And Active Health Architecture

Status: Phase 005 implemented runtime architecture

Date: 2026-07-13

Scope: multiple HTTP upstreams, round-robin selection, active HTTP health checks

Deferred: retry, passive health, weighted balancing, keep-alive pool, Prometheus export, external ACME

## Current Production Baseline

The config model stores stable upstream identities and an explicit round-robin policy. The production
mio runtime owns one cursor per service and dispatches new HTTP and HTTPS requests in configured
upstream order. Bounded workers perform active HTTP probes outside the event loop and publish
generation-fenced immutable availability snapshots. `Unhealthy` targets are excluded from new requests;
`Unknown`, `Healthy`, and health-disabled targets remain eligible.

~~~text
primary config / Admin apply
  -> edge-application::parse_mvp_config
       -> [[services.upstreams]].url
       -> generated id: <service-id>-<1-based-position>
  -> ConfigSnapshot
  -> edge-application::select_http_route_action
       -> service_id
  -> edge-core snapshot mio runtime::route_completed_request
       -> RuntimeUpstreamSelector::select
       -> edge-domain::select_upstream
       -> prevalidated HttpUpstreamEndpoint cache lookup
       -> typed literal-IP connect address
       -> mio upstream connect
~~~

The non-production/blocking snapshot helper still calls 'primary_upstream_for_service'. It is a
compatibility path, not a source of production load-balancing policy. Production completion is judged
by the unified mio runtime; helper compatibility is retained only where existing tests require it.

### Current endpoint contract

`HttpUpstreamEndpoint` is the single parser/value used by config validation, production mio traffic,
and the health probe port. It accepts HTTP with literal IPv4 or bracketed IPv6 addresses, validates
ports and base paths, and rejects userinfo, query, fragment, control characters, ambiguous addresses,
and hostnames before activation. Equivalent default-port forms normalize to the same value.

The production runtime builds an endpoint map when a snapshot is activated and does not parse URLs
on the request path. Hostname resolution requires a separate resolver port/worker and remains outside
Phase 005; blocking DNS in the mio event loop is prohibited.

## Logical Layers And Ownership

The 'edge-core' crate name does not make it an inner Clean Architecture layer. Its mio event loop and
socket lifecycle are outer data-plane mechanisms.

~~~text
domain
  Upstream identity
  load-balancing policy
  pure selection decision
  health states and transition rules

application
  config normalization and validation
  health supervisor use cases
  activation reconciliation
  explicit Tick and ProbeResult handling

ports
  HealthProbeTransport
  clock/tick boundary
  CoreCommandClient
  LogSink / MetricsSink

adapters
  bounded HTTP health probe
  timer and worker infrastructure
  config repository and Admin API transport
  mio runtime execution

bootstrap
  read environment once
  construct immutable limits and dependencies
  own startup/shutdown ordering
~~~

Dependencies point from mechanisms toward policy. Domain and application never import mio, socket,
filesystem, environment, concrete HTTP client, logger implementation, or worker handles.

## Accepted Decisions

### Stable upstream identity

- A configured upstream has an operator-visible stable id/name.
- A legacy single-upstream config without a name normalizes to '<service-id>-primary'.
- Two or more upstreams require explicit unique names.
- Reordering does not change identity.
- Duplicate names and duplicate normalized endpoints are validation errors.
- Health state is keyed by service id plus upstream id, not by vector position or URL string.

### Round-robin cursor

- The mio runtime owns one cursor per service; no global/static cursor is allowed.
- Selection is a pure domain decision over ordered upstreams, availability, and sequence.
- The cursor advances once when a new request receives a selected target.
- Request dispatch order, not completion order, defines fairness.
- Cursor arithmetic wraps without panic.
- Cursor is preserved only when service id, ordered upstream-id sequence, and algorithm are unchanged.
- Add, remove, reorder, or algorithm change resets the cursor to zero.
- Existing connections remain pinned to their selected target.

### Health state reconciliation

- Health policy disabled produces 'Disabled' and no probes.
- A new or materially changed upstream starts as 'Unknown' and is initially eligible.
- Health state is preserved only when upstream id, normalized endpoint, and health policy are equal.
- Endpoint or policy changes reset that upstream to 'Unknown'.
- Removed upstream state and scheduled work are discarded.
- 'Unhealthy' targets are excluded from new selection.
- If all configured targets are 'Unhealthy', the runtime returns 503 without opening a connection.
- Health operational state, counters, cursor, and in-flight work are memory-only and restart cleanly.

### Activation generation

- Every apply and rollback receives a new process-local monotonically increasing generation.
- Revision id is retained for audit but is not sufficient for stale-result fencing because rollback can
  reactivate an older revision id.
- Probe requests and results carry generation and upstream identity.
- A result with a non-active generation is discarded before any state transition or runtime publish.
- Config, TLS, and candidate availability are prepared and activated through one runtime command/ack.
- Health scheduling starts only after the runtime accepts the candidate.
- Rejection preserves previous config, TLS, availability, cursor reconciliation input, and schedule.

### Time and worker boundary

- Application use cases do not call system time or sleep.
- A scheduler adapter sends explicit 'Tick { now }' input.
- A network adapter executes 'HealthProbeRequest' with bounded timeout/header/queue limits.
- One upstream/generation has at most one in-flight probe.
- Queue saturation reschedules at the next interval plus deterministic jitter; it does not busy-retry.
- Shutdown transitions the supervisor to Draining, stops new work, cancels/drains in-flight probes, and
  returns a bounded join result.

## State Contracts

~~~text
Health:
  Disabled
  Unknown(successes, failures)
  Healthy(failures)
  Unhealthy(successes)

Probe:
  Idle -> Scheduled -> InFlight -> Completed | TimedOut | Cancelled -> Scheduled

Supervisor:
  Stopped -> Starting -> Running -> Draining -> Stopped
  Starting -> FailedStart

Activation:
  Drafted -> Parsed -> Normalized -> Validated -> Prepared(generation)
  -> RuntimeQueued -> Activated -> RevisionCommitted -> Audited -> ScheduleReconciled
~~~

Independent health booleans are not a source of truth. Transitions return typed outputs that logging,
metrics, and runtime publication consume.

## Logging Contract

- Product: one event for first Unknown determination and Healthy/Unhealthy transitions; stable ids,
  revision, state, and machine-readable error only.
- Field Debug: sampled probe classification and selected target details; no raw body, credential, auth,
  cookie, or unbounded error.
- Development: cursor, scheduling, queue bucket, and stale generation details; production default off.
- Probe success/failure without a state transition does not emit Product health logs.
- Sink failure or saturation never blocks event-loop or supervisor progress.

## Architecture Fitness Gates

`scripts/check_architecture.sh` rejects:

- concrete network, filesystem, environment, clock/sleep, HTTP client, or logger use in domain/application;
- health probe connect/read/write/sleep inside the mio event-loop module;
- direct Admin API/UI mutation of runtime health or config files;
- unbounded health worker or command queues;
- global/static mutable health maps or round-robin cursors;
- production calls to first-upstream-only selection after round-robin integration;
- probe and proxy use of different endpoint normalization paths;
- runtime environment access outside bootstrap.

Existing Phase 004 TLS/rustls boundary checks remain mandatory.

## Implemented Validation And Compatibility Contract

- A legacy service with one unnamed upstream normalizes to `<service-id>-primary`.
- Every upstream in a multi-upstream service requires an explicit unique name.
- Duplicate normalized endpoints in one service are rejected before activation.
- Config parse/render, Admin API DTOs, and runtime snapshots preserve stable upstream identities.
- The legacy `upstream_url` Admin API field remains a single-upstream compatibility input; new clients
  use `upstreams[]` and treat each `id` as stable.

## Deferred Scope

Retry, passive health, weighted balancing, upstream keep-alive pooling, hostname resolution, metrics
export, and external Let's Encrypt staging remain outside this phase. Unified mio HTTP/HTTPS state
handling, deterministic round-robin, active health filtering, and the read-only operational health API
are implemented and are not deferred items.
