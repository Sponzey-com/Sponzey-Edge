# Unified TLS Runtime

This document records the implemented Phase 004 HTTP/HTTPS mio runtime. External
Let's Encrypt staging and production remain deferred.

## Current MVP Boundary

The MVP runtime supports:

- file-backed certificate store
- private key `0600` permission on Unix
- atomic certificate file write preserving the previous file on failed temp
  write
- rustls server config loading in the adapter boundary
- startup TLS preflight before runtime listener bind and before current revision
  import
- adapter-owned `TlsRuntimeSnapshot` for loaded rustls configs
- one mio poll loop with a protocol-aware HTTP/HTTPS listener registry
- byte-oriented rustls sessions driven by core readiness without socket or
  thread ownership in the adapter
- `InstallCertificate` loads and validates outside the event loop, then sends a
  prepared TLS factory through the bounded runtime command queue
- local self-signed unified mio HTTPS, hot-install, SNI, timeout, malformed
  input, close-notify, and WebSocket smoke coverage
- multi-cert SNI resolver in the adapter-owned TLS runtime snapshot
- HTTPS listener smoke proving SNI selects the non-default certificate among
  multiple loaded configs
- pure core TLS transport tests for partial ingress/egress, read/write interest,
  timeout, failure, closing, and terminal states

## Implemented Boundary

`edge-core` owns listeners, sockets, readiness, deadlines, transport buffers,
and backpressure. `edge-adapters` owns rustls, PEM/X.509 parsing, and immutable
TLS configuration. Domain/application do not import either mio or rustls.

## Phase 004 Baseline ADR

Status: implemented and verified locally.

The production path is:

```text
main
  -> startup_proxy_config_from_file
  -> preload certificate material and build rustls factory outside event loop
  -> run_snapshot_http_proxy_mio
  -> register HTTP and HTTPS listeners in one poll
  -> create Plaintext or TLS ClientTransport at accept
  -> shared snapshot route/upstream/WebSocket lifecycle
  -> bounded log/metric channels
```

The runtime has one
poll loop for HTTP and HTTPS listeners, accepts both protocols through a
protocol-aware listener registry, captures immutable config/TLS snapshots per
connection, and drives TLS handshake/application data through readiness,
deadlines, and buffers owned by `edge-core`.

The implemented TLS port contract is intentionally capability based and
supports:

- create a server session from an immutable runtime snapshot/factory
- accept encrypted bytes from core
- expose pending decrypted bytes to core after establishment
- accept plaintext response bytes from core
- expose pending encrypted bytes for core to write to the socket
- expose mutually exclusive progress state
- expose read/write interest hints derived from TLS progress and buffers
- expose normalized SNI when available
- request close-notify without blocking I/O

The contract must not expose:

- rustls concrete types
- mio types
- `TcpStream` or listener types
- filesystem paths
- PEM bytes or private key material
- environment variable access
- concrete logging sinks

Snapshot activation uses prepared immutable runtime payloads:

```text
Admin/API intent or startup config
  -> application validation
  -> certificate/config preparation outside event loop
  -> bounded runtime command/event
  -> event-loop compatibility check
  -> active pointer swap
  -> acknowledgement
```

Any failure before acknowledgement keeps previous config and TLS snapshots. A
connection accepted before activation keeps the snapshot captured at accept
time. A connection accepted after activation uses the newly active snapshot.
Partial activation where config succeeds but TLS fails, or TLS succeeds but
config fails, is not an allowed final state.

Architecture fitness invariants:

- production contains no blocking HTTPS listener or per-connection HTTPS thread
- server-side production contains no `rustls::StreamOwned` request path
- event-loop listener factories are replaced only by bounded prepared commands
- keep certificate file reads and PEM/X.509 parsing outside the event loop
- keep rustls in `edge-adapters`
- keep TLS progress in explicit state machines rather than boolean flag sets
- keep production TLS failure/access events on bounded structured queues with
  Product/FieldDebug/Dev formatting at the application boundary

Phase 004 progress:

- Task 002 extracted the legacy blocking HTTPS bridge into
  `apps/edge-proxy/src/https_blocking.rs` without behavior changes.
- Task 003 added the first byte-oriented TLS session port in `edge-ports`.
  `ServerTlsSessionFactory` creates inbound `TlsSession` objects, while
  `ClientTlsSessionFactory` requires an explicit typed server name for outbound
  sessions. `TlsSessionProgress`
  represents mutually exclusive session state, and `TlsSessionInterest`
  exposes read/write hints without rustls, mio, socket, filesystem, PEM, private
  key, environment, or logger types.
- `ScriptedServerTlsSessionFactory`, `ScriptedClientTlsSessionFactory`, and
  `ScriptedTlsSession` provide deterministic
  fake sessions for contract and core runtime tests. They cover partial
  handshake progress, pending ciphertext drain, plaintext handoff, peer close,
  and failed state representation.
- Phase 009 Task 011 added `RustlsClientTlsSessionFactory` in `edge-adapters`.
  It builds an immutable HTTP/1.1 client configuration from an explicitly
  validated managed trust bundle, uses no native/system-root fallback, and
  requires a typed server name for every independent client session. In-memory
  private-PKI tests cover trusted success, wrong Root, wrong name, missing
  Intermediate, malformed TLS records, and invalid prepared material. Client
  verification failures expose only stable bounded codes/messages; rustls error
  text, certificate identities, PEM, paths, and digests do not cross the adapter.
- Phase 009 Task 012 added the core-only prepared client factory registry keyed by
  `(ServiceId, UpstreamId)`, an outbound `UpstreamTransport` byte/interest
  boundary, and explicit `HandshakingUpstreamTls` timeout transitions. Runtime
  endpoint selection now preserves HTTP/HTTPS scheme and base path. Until the
  next task wires the prepared transport into mio socket readiness, HTTPS
  selections fail with a bounded 502 before opening an upstream socket; they
  never fall back to plaintext.
- Phase 009 Task 013 wires that registry into the Snapshot mio runtime. For an
  HTTPS upstream, TCP connect now transitions through explicit outbound TLS
  handshaking, flushes partial ciphertext according to session interest, and
  accepts the pending HTTP request only after peer verification establishes the
  session. Scripted loopback tests prove success, terminal verification failure,
  handshake timeout, configured upstream `Host`, preserved
  `X-Forwarded-Host`, and no plaintext fallback.
- Phase 009 Task 014 adds a pure application preparation plan and production
  composition-root builder. Startup traverses the active snapshot in stable
  `(ServiceId, UpstreamId)` order, verified-loads each referenced managed Root
  once, builds strict rustls client factories outside the event loop, and
  injects the immutable registry explicitly into `SnapshotProxyConfig` before
  any proxy listener starts. Missing trust fails startup with a bounded code.
  Actual loopback tests prove Root-only trust plus complete server chain and
  correct SNI forwards HTTP successfully; unrelated Root and wrong SNI return
  502 without exposing plaintext HTTP to the backend application. TLS WebSocket
  tunneling and generation-atomic registry replacement remained follow-up work
  at the end of Task 014.
- Phase 009 Task 015 extends `HealthProbeRequest` with the typed upstream endpoint
  and TLS policy. The application health supervisor rejects scheme/policy
  contradictions and includes Root/SNI/HTTP-Host policy in reconciliation
  identity, so a trust or identity change resets counters. The worker adapter
  uses a separately owned prepared client-factory registry built from the same
  startup trust material as the request path. It drives the existing
  byte-oriented TLS session on bounded worker sockets, writes no HTTP bytes
  before establishment, and maps profile, handshake, and handshake-timeout
  failures to bounded health reasons. Private-PKI adapter and controller tests
  cover trusted 204/Healthy plus wrong Root and wrong SNI with zero plaintext.
  Generation-atomic hot replacement and TLS WebSocket tunneling remained
  follow-up work at the end of Task 015.
- Phase 009 Task 016 routes the WebSocket upgrade response and both tunnel
  directions through `UpstreamTransport`. Connection-owned pending encrypted
  output survives partial socket writes, and flow control pauses client or
  upstream ingress when its plaintext plus socket-output ownership reaches the
  configured bound. Actual private-PKI WebSocket ping/pong and plaintext
  WebSocket regression tests pass. Retry replay now rebuilds the request for
  the newly selected endpoint and TLS HTTP Host while preserving the original
  forwarded authority and upgrade headers. Generation-atomic registry
  replacement remains follow-up work.
- Phase 009 Task 017 adds required inbound mTLS without exposing rustls or client
  identity to the core. `TlsRuntimeSnapshot` reuses the SNI certificate resolver
  with a `WebPkiClientVerifier` built only from an explicitly managed validated
  Root bundle. Startup preserves each HTTPS listener's `ClientAuthPolicy`, reads
  each shared trust ref once, and injects an immutable server session factory per
  bind before listeners start. In-memory tests cover trusted clientAuth chains,
  missing certificates, unrelated Roots, incomplete chains, wrong EKU,
  expired/not-yet-valid certificates, and malformed records. An actual mio E2E
  proves rejected clients create no upstream HTTP request and a trusted client
  forwards successfully. Disabled listeners retain the prior server-only TLS
  behavior. Listener policy changes remain restart-required.
- Phase 009 Task 018 adds a generation-atomic runtime payload containing the
  immutable config snapshot, health availability, bind-keyed inbound server TLS
  registry, and service/upstream-keyed outbound client TLS registry. The event
  loop validates selector reconciliation, availability, every HTTPS upstream,
  and the exact active TLS listener bind set before mutating any field. The
  composition root shares one verified trust read cache across inbound,
  outbound request, and health preparation. Successful apply and rollback tests
  replace the outbound trust behavior; rejected registries preserve old behavior
  with zero plaintext. Actual mio mTLS remains required across hot generation
  activation, and certificate install now uses the same bind-keyed server
  registry instead of a global no-client-auth factory. If post-ack health
  activation fails, a preprepared previous generation is reactivated and the
  config mirror remains unchanged.
- Task 004 extended manual certificate validation so the adapter returns leaf
  DNS SAN identities and the application rejects declared domains that are not
  covered by the validated certificate identity before store, audit, or core
  command mutation. Supported matching is exact DNS and one-label wildcard DNS.
  IP SAN, URI SAN, email SAN, and CN fallback remain unsupported.
- Task 005 added a rustls-backed byte-oriented `ServerTlsSessionFactory` and
  `TlsSession` in `edge-adapters`. The adapter completes fragmented in-memory
  handshakes, roundtrips plaintext after establishment, emits close-notify, and
  maps malformed TLS records to `TLS_HANDSHAKE_FAILED` without socket ownership
  or per-connection threads.
- Task 006 added `TlsTransport` and `TlsTransportState` in `edge-core`. The core
  now drives a `TlsSession` port through fragmented encrypted input, plaintext
  handoff, ciphertext drain, read/write interest, timeout, and peer-close
  transitions without importing rustls or owning a socket. Deterministic tests
  use `ScriptedTlsSession`; later Phase 004 tasks completed production mio wiring.
- Task 007 added the explicit `Closing` progress state. Outbound close-notify
  now retains writable interest during partial ciphertext drains and changes to
  terminal `PeerClosed` only after the queued record is fully drained.
- Task 008 added the protocol-aware `ClientTransport` boundary in `edge-core`.
  Plaintext and TLS variants now expose the same socket ingress, HTTP egress,
  socket output drain, and readiness merge operations. TLS handshake bytes are
  not handed to the HTTP parser, while established decrypted bytes use the same
  HTTP-facing contract as plaintext connections.
- Task 009 connected the production plaintext `SnapshotMioConnection` ingress
  to `ClientTransport`. Accepted HTTP connections now explicitly own a
  plaintext transport and only transport-produced plaintext reaches
  `HttpConnectionIo`; routing, timeout, WebSocket, and backpressure behavior is
  unchanged. Tasks 010 and 011 subsequently completed partial-write-safe egress.
- Tasks 010 and 011 added connection-owned pending socket output and connected
  the production plaintext mio egress to it. Transport output is retained until
  the socket acknowledges each partial write, and close plus upstream
  backpressure decisions include the unacknowledged tail.
- Task 012 added explicit `ServerTlsSessionFactory` injection to
  `SnapshotProxyConfig` and the mio accept boundary. A fake TLS end-to-end test
  proves coalesced handshake/request bytes are separated, routed through the
  shared HTTP pipeline, returned through TLS transport egress, and forwarded
  upstream with `X-Forwarded-Proto: https` without a connection thread.
- Task 013 added ingress-generated TLS ciphertext readiness. The mio runtime
  now pulls handshake output into connection-owned pending bytes, registers
  client writable interest, flushes partial output, and returns to readable
  handshake/request state instead of closing a connection with no HTTP response.
- Task 014 added the unified listener registry. Listener tokens occupy a
  dedicated namespace, each registry entry owns its optional TLS factory, and
  one mio poll loop accepts both plaintext HTTP and TLS connections. Mixed
  protocol E2E coverage verifies `X-Forwarded-Proto` remains protocol-correct.

## Tidy First Decisions

- Introduce an adapter-owned `TlsConfigRepository` or equivalent boundary for
  loaded TLS configs. Current implemented slice:
  `edge-adapters::TlsRuntimeSnapshot`.
- Keep `CertificateRef` and SNI policy in domain/application types.
- Keep rustls config, PEM parsing, and file reads in adapter/bin code.
- Define a small immutable TLS runtime snapshot type for loaded certificate
  refs without storing private key material in domain. Current implemented
  slice: `TlsRuntimeSnapshot` indexes loaded rustls configs by `CertificateRef`
  and normalized SNI hostname.
- Add tests around the boundary before changing runtime behavior.

## Behavior Work

1. Hot install command planning

- Input: `CoreCommand::InstallCertificate { certificate_ref }`
- Boundary dependency: loaded certificate lookup by `CertificateRef`
- Output on success: new immutable TLS runtime snapshot
- Output on failure: rejected ack with stable error code
- Invariant: previous TLS runtime snapshot remains active on failure
- Current implemented gates:
  `install_certificate_command_replaces_tls_runtime_snapshot_after_ack`,
  `install_certificate_missing_ref_rejects_without_core_command`,
  `install_certificate_core_rejection_preserves_tls_runtime_snapshot`,
  `unified_mio_https_hot_install_uses_new_certificate_for_new_connection`

2. Multi-cert SNI resolver

- Select certificate by normalized SNI hostname.
- Reject unknown SNI according to the explicit core policy.
- Do not default to an unrelated certificate for an unknown hostname.
- Preserve a deterministic fallback policy only if the domain policy explicitly
  allows it.
- Current implemented gates:
  `tls_runtime_snapshot_selects_certificate_ref_by_normalized_sni`,
  `tls_runtime_snapshot_rejects_duplicate_sni_hostname`,
  `tls_runtime_snapshot_replace_rejects_duplicate_sni_hostname`,
  `https_listener_selects_certificate_by_sni_among_loaded_configs`,
  `install_certificate_rejects_sni_domain_conflict_without_core_command`

3. mio TLS connection-state integration

- Represent TLS states explicitly:

```text
WaitingForClientHello
  -> SelectingCertificate
  -> Handshaking
  -> Established
  -> Failed
```

- Drive read/write interest from the TLS state.
  Current gate: `tls_handshake_interest_follows_current_state`.
- Drive TLS handshake progress from explicit events before wiring adapter
  readiness. Current gates: `tls_handshake_events_drive_state_transitions`,
  `tls_handshake_event_timeout_sets_failed_state`.
- Enforce handshake timeout.
- Never parse certificate files or perform blocking I/O on the event loop
  thread.

4. Decrypted HTTP handoff

- Reuse the snapshot HTTP stream handler after TLS establishment.
- Preserve `X-Forwarded-Proto: https`.
- Keep HTTP route selection and proxy policy unchanged.

## Required Tests

- `InstallCertificate` success replaces only the TLS runtime snapshot. Current
  gate: `install_certificate_command_replaces_tls_runtime_snapshot_after_ack`.
- `InstallCertificate` failure preserves the previous TLS runtime snapshot.
  Current gate: `install_certificate_core_rejection_preserves_tls_runtime_snapshot`.
- Missing certificate ref rejects the command without changing active TLS state.
  Current gate: `install_certificate_missing_ref_rejects_without_core_command`.
- Invalid PEM rejects the command without panic and without changing active TLS
  state.
- SNI selects the expected certificate among at least two configured certs.
  Current gate: `https_listener_selects_certificate_by_sni_among_loaded_configs`.
- Unknown SNI follows the documented rejection policy. Current gates:
  `tls_runtime_snapshot_selects_certificate_ref_by_normalized_sni`,
  `unknown_sni_has_no_certificate_selection`.
- Duplicate SNI hostname conflicts are rejected before runtime mutation.
  Current gates: `tls_runtime_snapshot_rejects_duplicate_sni_hostname`,
  `install_certificate_rejects_sni_domain_conflict_without_core_command`.
- TLS state derives client read/write interest without rustls or socket types in
  core. Current gate: `tls_handshake_interest_follows_current_state`.
- TLS handshake events drive certificate selection, establishment, and timeout
  failure without boolean flag combinations. Current gates:
  `tls_handshake_events_drive_state_transitions`,
  `tls_handshake_event_timeout_sets_failed_state`.
- TLS handshake timeout closes or fails the connection without panic.
- HTTPS request after hot install uses the new certificate. Current gate:
  `unified_mio_https_hot_install_uses_new_certificate_for_new_connection`.
- Existing HTTP runtime tests remain unchanged.
- Architecture check confirms rustls types do not enter domain/application.

## Review Checklist

- Tidy changes and behavior changes are separated.
- Tests are written before behavior changes.
- Event loop does not perform file I/O, DNS, ACME, or certificate parsing.
- TLS config replacement is atomic.
- Product logs include certificate ref and error code only.
- Field-debug logs include SNI selection result without private path or key
  material.
- Development logs may include TLS state transitions but remain disabled by
  default in production.
