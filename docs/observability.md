# Observability

## Log Modes

Sponzey Edge uses three operational log modes:

- `product`: minimal production-safe logs
- `field-debug`: field diagnosis logs with route/upstream detail
- `dev`: development and test logs with state detail

Product logs must include stable `request_id` and `revision_id` fields where available,
but must not include request bodies, response bodies, secrets, authorization headers,
cookies, full query strings, or raw high-cardinality paths.
Data-plane access events include bounded `scheme=http|https`. Product mode does
not include SNI, raw TLS records, request paths, PEM, or private key material.
Field-debug adds the existing route/method/path context, while development mode
adds state markers; those enrichments are not enabled in Product mode.

Durable audit is not a fourth log level. It is a typed control-plane ledger with
intent/terminal, security-observation, reconciliation, retention and restore-provenance
records. Product logs report only bounded ledger readiness/degradation and operation
outcomes; Field Debug may sample bounded action/error context; Development may expose
state-transition fixture IDs in tests. None may emit record payload bytes, chain hashes,
filesystem paths, raw config/diffs, credentials, cookies, CSRF values, PEM or keys.

Active health follows the same three-mode policy:

- Product emits `upstream_health_changed` only when availability changes. Its
  allowlisted fields are `revision_id`, `generation`, `service_id`,
  `upstream_id`, `previous_state`, and `next_state`.
- Field Debug additionally emits sampled `upstream_health_probe_debug` events.
  The sampler emits the first event and then at most one event per 60,000 ms for
  each `(service_id, upstream_id, bounded_reason)` key. It retains at most 8,192
  keys and evicts deterministically when full.
- Development may use the same sampled probe event for test/runtime diagnosis;
  development logging remains disabled in the production default.

Probe debug events contain only revision/generation, stable identities,
`outcome`, optional bounded `status_code`, and `duration_ms`. They never contain
an endpoint URL, health path, body, header, credential, or raw transport error.
Probe success/failure without a state transition does not create Product logs.
HTTPS probe failures use only `tls_profile`, `tls_handshake`, or
`tls_handshake_timeout`. Root references, SNI values, HTTP Host values,
certificate identities, PEM, and rustls error strings are never log fields.

The concrete product log adapter is `edge-adapters::JsonLineLogSink<W>`.
`edge-proxy` wires `stdout_json_log_sink()` at the process boundary for
startup product events. Each event is one JSON object per line with:

- `component`
- `event`
- `fields`

The process-start event records `data_dir`, `config_file`, `admin_bind`,
`log_mode`, and `acme_client`. It does not record password files, secret
values, request material, private keys, cookies, authorization headers, or raw
query strings.

Outbound TLS startup preparation emits `upstream_tls.startup.prepared` only
after the active snapshot's managed trust registry is built. Its complete field
allowlist is `revision_id` and `prepared_upstream_count`. Trust references,
server names, endpoint addresses, certificate identities, PEM, paths, digests,
and raw rustls errors are prohibited. Preparation failure returns a stable
bounded error before proxy listener startup and does not emit a misleading
success event.

Offline backup creation uses fixed Product events
`backup.create.started`, `backup.create.succeeded`, and
`backup.create.failed`. Allowed fields are operation/archive IDs, artifact
count, duration, and stable error code. Paths, domains, config content, hashes,
PEM, verifier, and passphrase are prohibited. Field Debug may add only bounded
state/component and rejection codes; per-artifact payload logging is forbidden.
Development diagnostics use fake-port call-order assertions and are not enabled
in the production default.

Backup verification uses `backup.verify.started`,
`backup.verify.succeeded`, and `backup.verify.failed` with the same safe-field
policy. Wrong passphrase and ciphertext tampering are intentionally not
distinguished in Product output.

New-target restore uses `backup.restore.started`,
`backup.restore.succeeded`, and `backup.restore.failed`. Success fields are
limited to operation/archive identity, `commit_mode=new_target`, and duration;
failure adds only a stable error code. Stage/target paths and restored material
are never Product fields.

Replace and recovery use `backup.restore_replace.*` and
`backup.restore_recovery.*`. Allowed values include
`commit_mode=replace_transaction` and the bounded outcomes
`commit_completed|rollback_restored|restore_aborted`. Journal and physical path
content is prohibited in Product events.

## Metrics

The production metrics model exposes typed `sponzey_edge_*` counter, gauge,
and histogram families defined by the descriptor registry. Runtime producers
publish through a bounded nonblocking queue into a single-writer registry.

- requests and request-duration histogram per stable route
- active connections
- upstream selection, availability, failure, health transition, and no-eligible counts
- failure-aware and TLS handshake failure counts
- certificate expiry, collector drops/readiness, build identity, and process start time
- active runtime payload charge and payload limit gauges
- resource admission rejections with only `connection/connection_limit`,
  `payload/payload_pressure`, and `payload/failed_closed` label combinations

`sponzey_edge_resource_payload_bytes` is the authoritative logical byte count
owned by the mio runtime payload ledger. It is not process RSS or allocator
capacity. `sponzey_edge_resource_payload_limit_bytes` is emitted from the
immutable policy used by the running core. A desired config revision that is
pending restart must not change this gauge until a new process starts with that
revision.

Resource observations use the existing bounded nonblocking publisher. Queue
full or collector shutdown increments the bounded drop counter but cannot undo
an admission decision, charge, release, socket transition, or cleanup. Used
payload publication is deduplicated by value and cleanup attempts a final zero
gauge when the ledger returns to zero.

Resource Product events are limited to `resource.policy.active`,
`resource.pressure.entered`, `resource.pressure.recovered`, and sampled
`resource.admission.rejected`. Pressure is emitted only on normal-to-active,
active-to-normal, and failed-closed edges; `pressured`/`exhausted` oscillation
does not produce per-read logs. Rejection keys use a fixed 60-second TTL and an
8,192-key oldest-entry bound.

Product fields are restricted to active revision, bounded pressure/resource
kind/reason, numeric startup limits, and limit/usage buckets. Field Debug and
Development modes may add only the closed requested-byte bucket. Raw path,
query, headers, body, client address, PID, certificate identity, and secret
material are prohibited. Log mode and resource policy are captured at startup;
hot config commands update the active revision identity but cannot mutate the
running policy or log mode. Full or disconnected log queues increment only the
bounded drop counter and cannot alter resource progression.

Admin live resource status follows the same active-policy identity. The Core publishes
only active revision, monotonic publication generation, logical used/limit bytes,
active connection count, and the closed pressure state. Publication is deduplicated
and nonblocking; a busy or stopped mirror increments the existing drop counter without
changing socket, ledger, cleanup, or revision progression. The Admin API and UI never
hold a Core table/ledger lock and report `null`/`unavailable` before the first snapshot.
This aggregate is not process RSS and is not retained as history.

Health and resource metric labels use only bounded state/reason values and stable configured
service/upstream identities. Ignored or rejected observations converge on the
bounded `sponzey_edge_metric_events_dropped_total` reason label.

Metric labels must remain bounded. Raw paths, full query strings, user headers, request bodies, and unbounded user-provided values must not be used as labels.

## Prometheus Endpoint

Prometheus exposition is disabled when `[metrics]` is omitted. When explicitly
enabled, a separate adapter thread binds only to the configured loopback socket
(default `127.0.0.1:9464`) and serves exact `GET /metrics` requests. The listener
uses two workers, a bounded accept handoff, 5-second socket timeouts, an 8 KiB
header limit, and a 4 MiB response limit. It reads immutable snapshots and never
locks or backpressures the mio data plane. Remote exposure and retention remain
deferred.

## Recent Operational Feed

The application layer provides bounded recent buffers for:

- access logs
- error events

The Admin API exposes read-only recent feeds through:

- `GET /api/v1/logs/access`
- `GET /api/v1/logs/errors`

The Admin Web UI reads those endpoints when authenticated. Data-plane access log
events are currently produced by the snapshot mio runtime and handed to the
Admin recent access buffer through a bounded nonblocking queue. Data-plane
502/504 and TLS handshake timeout/failure errors are produced as recent error events and handed to the Admin
recent error buffer through the same nonblocking boundary. The mio event loop
uses nonblocking send and never locks UI-facing log storage.
Queue-full drops on runtime log handoff queues are counted by an injected
counter and exposed in recent error feeds only when log mode is `field-debug` or
`dev`.

Health transition and probe logs use a bounded queue with capacity 256. Runtime
metrics use a bounded queue with capacity 1,024. Producers call nonblocking
`try_send`; a full or disconnected sink increments the injected drop counter
and never blocks health reconciliation or the mio event loop. Operational health
state remains available through authenticated `GET /api/v1/upstream-health`
even when a log or metric sink is saturated.

Authenticated `GET /api/v1/metrics` exposes a bounded JSON summary of the same
immutable registry snapshot. It rejects query parameters and caps each metric
kind array at 500 entries; Prometheus scraping remains on the separate
loopback-only listener.

## Failure-Aware Routing

Product transition names are fixed to `upstream.passive_ejected`,
`upstream.passive_recovered`, `upstream.drain_started`, `upstream.drain_completed`,
`proxy.retry_exhausted`, `passive_observation.degraded`, and
`passive_observation.recovered`. Fields are limited to revision/generation,
configured IDs, bounded reasons, and optional connection count. Successful
attempts and per-connection drain reference changes do not create Product logs.

`sponzey_edge_failure_aware_transitions_total` uses closed `event` and `reason` labels.
Endpoint URLs, paths, headers, bodies, cookies, credentials, private keys, and
connection identities are prohibited. Passive transition emission uses bounded
`try_send`; sink saturation cannot roll back state or alter proxy responses.
Authenticated `GET /api/v1/upstream-health` preserves effective `status` and
additively returns nullable `drain_state` and `connection_count`.
