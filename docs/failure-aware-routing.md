# Failure-Aware Upstream Routing ADR

Status: Phase 006 accepted design, implementation pending

Date: 2026-07-14

Scope: passive transport failure observation, replay-safe single retry, upstream administrative drain

Deferred: weighted balancing, generic circuit breaker, response retry, request-body replay, Prometheus export,
external Let's Encrypt staging

## Baseline

Phase 005 is the behavior baseline. The 2026-07-14 fresh run passed 457 workspace tests, fmt, clippy,
architecture fitness, release documentation, and the four focused multi-upstream/health tests. Current
production behavior is:

- one global-cursor advance per newly selected request;
- unhealthy targets excluded and all-unhealthy mapped to 503;
- connect/write/reset errors mapped to 502;
- connect/read timeout mapped to 504;
- no retry and no passive traffic observation;
- existing WebSocket connections remain pinned during health changes;
- HTTP and HTTPS use the same snapshot mio runtime.

The release-document ACME smoke validates local evidence only. No external Let's Encrypt request is part
of this ADR or Phase 006.

## Current Production Call Graph

```text
snapshot mio runtime
  -> route_completed_request                         edge-core:2070
       -> parse_http_request
       -> select_http_route_action
       -> RuntimeUpstreamSelector::select             edge-core:1536
            -> edge-domain::select_upstream
            -> advance service cursor once            edge-core:1549
       -> build_upstream_request                       edge-core:3459
       -> connect_upstream                             edge-core:2190
            -> pending_upstream_request                edge-core:2246
            -> register upstream WRITABLE
       -> write_upstream                               edge-core:2254
            -> take_error for connect result
            -> move request into HttpConnectionIo
            -> write remaining bytes
            -> reregister upstream READABLE
       -> read_upstream                                edge-core:2332
            -> append first/next response bytes
            -> pause read on client backpressure
            -> finish or map reset/error
       -> expire_connection                            edge-core:2903
            -> timeout_decision_for_state
            -> drop upstream
            -> queue 408/504 or terminal close
       -> drop_upstream                                edge-core:3096
            -> deregister when registered
            -> drop socket and clear registration flag
       -> cleanup_closed                               edge-core:3167
            -> final upstream cleanup
            -> access log
            -> remove connection
```

`SnapshotMioConnection` currently owns the client/upstream sockets, `HttpConnectionIo`, pending upstream
request, WebSocket buffers, registration flag, and one state-relative deadline. `HttpConnectionIo` owns a
consuming upstream `WriteBuffer` and streaming client `WriteBuffer`. The current write path calls `to_vec()`
on remaining request bytes for each readiness event. Phase 006 must remove that full-remaining copy before it
retains replay bytes; otherwise retry would increase allocation pressure.

Backpressure is not an upstream failure. `pause_upstream_read_if_needed` intentionally deregisters upstream
read interest at the response buffer limit, and `resume_upstream_read_if_needed` registers it later. A paused
read cannot produce passive timeout/failure evidence until read interest and its deadline are valid again.

The blocking snapshot helper has another `build_upstream_request`, but it is not the production data-plane
policy path. Phase 006 changes and completion evidence target the unified snapshot mio runtime. Compatibility
helpers must retain behavior unless a separately reviewed tidy removes them.

## Layer Ownership

| Concern | Owner | Must not own |
| --- | --- | --- |
| retry eligibility and denial reason | domain | socket, mio, clock, log |
| effective active/passive/membership reduction | domain | worker, config file, global state |
| observation fencing/cooldown orchestration | application | concrete channel, socket, sleep |
| drain plan and generation reconciliation | application | connection-table mutation |
| observation/clock/core/status/log interfaces | ports | concrete runtime implementation |
| bounded queue, monotonic tick, structured sinks | adapters/bootstrap | domain decisions |
| attempt execution/readiness/socket cleanup | edge-core mio adapter | health threshold/config persistence |
| config/API serialization and UI | outer adapters | core internals/config-file bypass |

Dependencies remain outer mechanism to inner policy. Environment is read once in
`apps/edge-proxy/src/bootstrap.rs`; Phase 006 adds no post-bootstrap environment access or runtime mutation.

## Fixed Retry Contract

Retry is allowed only when every condition is true:

1. service retry policy is enabled;
2. method is exactly GET or HEAD;
3. parsed request body length is zero;
4. no Upgrade and no Expect header is present;
5. serialized upstream request fits the per-request replay limit;
6. global replay reservation was acquired before attempt 1;
7. upstream bytes written is zero;
8. no upstream response byte has been appended to the client buffer;
9. attempt count is one and retry budget remains one;
10. current config/availability generation equals the captured attempt plan generation;
11. another currently eligible, not-yet-attempted upstream exists;
12. the absolute upstream deadline has remaining time.

All other cases return a typed denial. The fixed reasons are `Disabled`, `MethodNotAllowed`, `BodyPresent`,
`UpgradeRequested`, `ExpectPresent`, `RequestTooLarge`, `ReplayBudgetExhausted`, `BytesAlreadyWritten`,
`ResponseStarted`, `NoAlternative`, `GenerationChanged`, `DeadlineExhausted`, and `AttemptsExhausted`.

The first selection alone advances the service round-robin cursor. Retry chooses the next target from the
captured ordered service pool, filters with the latest effective availability of the same generation, excludes
attempted ids, and does not mutate the global cursor. Generation mismatch denies retry rather than combining an
old request with new config.

Attempts share one immutable serialized request buffer and own independent write offsets. Full buffer cloning is
forbidden. Reservation failure leaves attempt 1 available but marks retry ineligible. Reservation is returned
exactly once on terminal cleanup or when retry eligibility is abandoned.

The absolute upstream deadline is created once from connect timeout plus upstream-read timeout. A second attempt
uses the smaller of its state timeout and remaining absolute budget. Retry cannot extend the existing maximum
upstream wait.

HTTP 4xx/5xx is a backend application result. It is neither a retry trigger nor a passive transport failure.

## Passive Observation Contract

The core emits facts through a bounded nonblocking port only when passive health is enabled. Retry and passive
health are independent toggles. An envelope contains:

- attempt id;
- revision id and activation generation;
- service id and upstream id;
- typed endpoint equality fingerprint;
- transport outcome;
- upstream bytes written;
- response-started marker.

The endpoint fingerprint is the normalized service/upstream identity and typed endpoint used for equality. It is
not a cryptographic hash and is not logged as a raw endpoint.

Allowed transport failure reasons are `ConnectRefused`, `ConnectTimeout`, `ConnectError`, `WriteError`,
`ReadTimeout`, `ResetBeforeResponse`, and `ResetAfterResponse`. Client disconnect, client-write timeout,
backpressure pause, HTTP status, queue saturation, config apply, and normal drain are not passive upstream
failures.

The first response byte emits `PassiveResponseStarted` and resets pre-ejection consecutive failures. A later
reset may emit one terminal transport failure for the same attempt. An attempt emits at most one terminal outcome;
duplicate terminal events are ignored by attempt id and generation.

Queue `Full` or `Closed` never blocks or changes the client status. Sink health transitions from Healthy to
Degraded on the first failed emit and returns to Healthy on the next accepted emit. Repeated failures increment a
bounded low-cardinality counter.

## Effective Availability State Machine

```text
DesiredMembership = Active | Draining | Removed
ActiveHealth = Disabled | Unknown | Healthy | Unhealthy
PassiveHealth = Disabled | Observing(failures) | Ejected(until_ms)

EffectiveSelection precedence:
  Removed > Draining > ActiveUnhealthy > PassivelyEjected > Eligible
```

Reducer events are `ConfigActivated`, `ActiveObservation`, `PassiveTransportFailure`,
`PassiveResponseStarted`, `Tick`, `ConnectionAcquired`, and `ConnectionReleased`.

- passive transport failure increments the counter and ejects at the configured threshold;
- passive response start resets Observing failures but does not clear an existing ejection;
- current-generation active success may clear ejection before cooldown;
- supplied monotonic `Tick(now_ms >= until_ms)` clears ejection to Observing(0);
- active Unhealthy still excludes a target after passive cooldown;
- Draining and Removed always exclude new selections;
- zero eligible targets returns 503 without fail-open connect;
- stale revision/generation/fingerprint and duplicate terminal events do not mutate state.

The application receives monotonic time through a port. Domain transitions receive numeric `now_ms` and never
read system time.

## Drain State Machine

The only operator drain path is canonical config plus validate/diff/plan/apply/ack/revision/audit. No Admin
direct-memory drain endpoint is allowed.

```text
Active
  -> Draining(Administrative, pending_connections)
  -> Draining(RemovedFromConfig, pending_connections)

Draining(Administrative, 0) -> Drained
Draining(RemovedFromConfig, 0) -> Removed
Drained -> Active only after accepted newer config generation
```

Desired `administrative_state = active | draining` is persisted. Pending references, timestamps, counters, and
runtime lifecycle remain memory-only. A service must retain at least one active upstream, so an all-draining draft
is rejected before activation.

Reference acquisition occurs when an attempt target is fixed. Exactly one release occurs on HTTP terminal
cleanup, timeout/reset/error cleanup, or WebSocket tunnel termination. Administrative drain stops new selection
and new active probes but does not terminate existing HTTP responses or WebSockets. Removed targets remain in a
runtime-only drain entry until references reach zero.

## Activation And Reconciliation

- every apply/rollback allocates a non-reused process-local generation;
- unchanged service/upstream id, normalized endpoint, retry/passive/active-health policy, and administrative
  state may carry active/passive state into the new generation;
- endpoint, policy, or administrative-state change resets active state to Unknown/Disabled and passive state to
  Observing(0)/Disabled;
- remove/re-add and process restart reset transient state;
- draining/removed targets receive no new active probes;
- old-generation probe, observation, connection-release, and drain-completion events are ignored;
- retry is denied if generation changes between attempts;
- runtime activation acknowledgement precedes revision commit and worker/drain reconciliation.

## Configuration And Resource Bounds

The plan-fixed external fields are:

- `runtime.max_retry_replay_bytes_total`, default 67,108,864, range 1 MiB through 512 MiB;
- `services.retry.enabled`, default false;
- `services.retry.max_retries`, enabled value exactly 1;
- `services.retry.max_replay_bytes`, default 32,768, range 1,024 through 65,536;
- `services.passive_health.enabled`, default false;
- `services.passive_health.failure_threshold`, default 3, range 1 through 10;
- `services.passive_health.ejection_ms`, default 30,000, range 1,000 through 86,400,000;
- `services.upstreams[].administrative_state`, default active.

Internal typed runtime defaults are observation queue 1,024, processing batch 128, tick interval 100 ms, and
worker shutdown deadline 2,000 ms. They are constructor arguments from the composition root, not hidden env/file
lookups or mutable globals.

## Logging And Error Contract

Product transition events are `upstream.passive_ejected`, `upstream.passive_recovered`,
`upstream.drain_started`, `upstream.drain_completed`, `proxy.retry_exhausted`,
`passive_observation.degraded`, and `passive_observation.recovered`. Successful attempts do not create Product
events.

Field Debug contains sampled attempt/retry/classification/arbitration details keyed only by stable ids and bounded
reasons. Development contains readiness, token, buffer offset, deadline, and stale-fence details and is production
default-off. No mode records request/response body, authorization, cookie, full query, secret, key, session/CSRF,
raw endpoint, host, or IP.

Connect/write/reset maps to 502, connect/read timeout maps to 504, and no eligible target maps to 503. Observation
or log queue failure never changes client response. Admin errors retain `code`, `message`, `details`, `hint`, and
`request_id`. Recoverable paths do not panic.

## Port And Test-Double Inventory

| Port | Production adapter | Required doubles |
| --- | --- | --- |
| passive observation sink | bounded try-send channel | recording, full, closed |
| monotonic clock/tick | bootstrap worker clock | manual clock |
| core command client | bounded wakeable command channel | accepting, rejecting |
| runtime status reader | immutable application snapshot | fixed, failing |
| log/metric/audit sink | bounded structured sink | recording, full, failing |
| config/revision repositories | existing file adapters | in-memory repositories |

## Red Test Inventory

The first implementation task is behavior-preserving characterization, not retry enablement:

1. connect failure, zero-byte write failure, partial write failure, read reset, and timeout produce typed internal
   attempt outcomes while retaining current 502/504 behavior;
2. first upstream response byte marks response-started before any retry decision;
3. backpressure deregistration is not classified as upstream failure;
4. duplicate terminal outcome is rejected without state mutation.

Subsequent domain Red tests cover:

- the exact retry allow/deny matrix and reason enum;
- global cursor unchanged by retry and generation mismatch denial;
- passive threshold/success reset/cooldown boundary/active recovery;
- effective-state precedence and all-unavailable behavior;
- drain transitions and exactly-once reference accounting;
- overflow and replay reservation boundaries.

Application/adapter/core Red tests then cover queue full/closed, stale fencing, reordered events, no-blocking
publish, socket deregistration, one response, immutable buffer reuse, absolute deadline, HTTP/HTTPS parity,
WebSocket preservation, config/API compatibility, logs, and release evidence.

## First Tidy Insertion Plan

The next task must not add retry behavior. It should introduce only:

1. typed attempt progress/outcome representation around current connect/write/read/timeout branches;
2. response-started and bytes-written accounting in socket-free connection I/O;
3. characterization tests proving existing 502/504, response streaming, backpressure, and cleanup behavior remain
   unchanged.

Passive ports, retry policy, config fields, and Admin UI remain excluded until this tidy is Green.
