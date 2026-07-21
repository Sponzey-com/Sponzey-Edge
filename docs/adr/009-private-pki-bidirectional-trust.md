# ADR 009: Private PKI Bidirectional TLS Trust

- Status: Accepted for phased implementation
- Date: 2026-07-15
- Scope: Phase 009

## Context

Phase 008 proves inbound HTTPS termination and recovery with a private server
certificate. It does not provide HTTPS connections to upstreams, active HTTPS
health probes, managed trust roots, or required client-certificate authentication.
The current implementation deliberately accepts only literal-IP `http://`
upstreams, exposes a server-only TLS session factory, builds rustls server
configurations with no client authentication, probes upstreams with plaintext
HTTP, and stores backup schema v1 artifacts without trust bundles.

The Phase 009 baseline is green: `./scripts/check.sh` passes with 551 workspace
tests and `./scripts/smoke_mvp.sh` passes all MVP, architecture, release-document,
Docker, health, recovery, and private-PKI smoke gates. Existing characterization
tests include `upstream_target_rejects_https_for_mvp`, the
`http_upstream_endpoint_*` tests, `rustls_tls_session_completes_with_fragmented_client_hello`,
`unified_mio_private_pki_requires_root_trust_and_correct_sni`, and backup schema-v1
manifest tests. This ADR changes no production behavior.

## Decision

### Managed trust bundles

Trust roots are managed, immutable, create-only artifacts addressed by a typed
`TrustBundleRef`. A bundle contains 1 through 32 unique CA certificates and at
most 256 KiB of decoded certificate data. Empty input, private keys, non-CA leaf
certificates, duplicate DER certificates, malformed material, and limit overflow
are rejected before publication.

The file adapter owns the mapping from logical refs to paths. It writes an
owner-controlled temporary file, syncs it, atomically renames it, and syncs the
directory. It must reject symlinks and platforms that cannot provide the required
no-follow, permission, and atomic-publication guarantees. Importing an existing
ref is a conflict, never an overwrite. Rotation imports a new ref, applies a new
config revision, waits for runtime acknowledgement, and only then attempts to
delete the old ref. Deletion scans every rollback-capable revision and fails if
any revision still references the bundle.

### Configuration schema

Schema v1 remains readable with its existing HTTP and no-client-auth meaning. It
is not rewritten on read. Schema v2 adds explicit upstream TLS and listener client
authentication policies. An HTTPS upstream retains a literal IPv4/IPv6 connect
address and separately requires a DNS `tls_server_name`, an HTTP
`upstream_http_host`, and a `tls_trust_bundle_ref`. These values respectively
control certificate identity/SNI, the HTTP `Host` header, and Root trust. No field
implicitly substitutes for another and no CN or IP fallback is allowed.

An HTTPS listener may use `client_auth=disabled` or `client_auth=required`.
Required mode needs an existing `client_trust_bundle_ref`; disabled mode rejects a
trust ref. HTTP listeners reject client-auth fields. HTTPS upstreams without all
required TLS fields fail validation. HTTP upstreams with any TLS field also fail.
Migration to v2 occurs only through the canonical validate, diff, apply, and
revision path.

Resource bounds are 128 managed bundles, 64 client-auth listener factories, and
1,024 HTTPS upstream factories per runtime generation. Admin import accepts at
most 384 KiB encoded input. List output is bounded to 128 refs in stable order.

### Layer and dependency boundaries

The domain owns trust refs, endpoint and TLS policies, validation rules, stable
errors, and state transitions. It imports no rustls, mio, filesystem, network,
environment, clock implementation, or logger types. Application use cases expose
typed inputs, outputs, and failures and depend only on ports such as
`TrustBundleStore`, `TrustBundleMaterialValidator`, `TlsRuntimePreparer`,
`RuntimeGenerationActivator`, `Clock`, `AuditSink`, and log sinks.

Adapters own PEM/X.509 parsing, rustls configuration, filesystem publication,
network health probes, and Admin HTTP serialization. Core receives only opaque,
immutable TLS capabilities through direction-specific server and client session
factory ports. It never reads certificates or paths and never chooses a crypto
provider. Admin UI and API cannot write files or mutate Core state directly.

The existing rustls 0.23.41 adapter dependency is sufficient. Its explicit Root
store client config supports strict upstream server authentication,
`WebPkiClientVerifier` supports required client authentication, and its
`TimeProvider` capability permits deterministic adapter tests. `rustls-pki-types`
remains the PEM boundary and `x509-parser` remains adapter-only. No new TLS runtime
is accepted by this decision.

### Atomic runtime generation

Preparation reads and validates files and builds rustls configurations outside
the mio event loop. A `PreparedRuntimeGeneration` contains the immutable config
snapshot, inbound server registry keyed by validated unique listener bind, upstream client registry
keyed by `(ServiceId, UpstreamId)`, active-health TLS policy, generation/revision
identifiers, and exact trust-ref digests. It exposes no rustls, PEM, or path type.

The bind key is deliberate: the mio runtime owns and replaces concrete listener
factories through each registered socket's `local_addr`. `ListenerId` remains the
canonical config and safe Product-log identity. Duplicate binds and missing prepared
factories fail the generation before mutation.

The bounded Core command carries only prepared capabilities. Core performs a
short compatibility check and atomically swaps the complete generation before
acknowledging it. The revision pointer is committed only after acknowledgement.
Prepare, queue, runtime, or commit failure preserves the previous revision and
runtime. Existing connections retain the generation captured at selection; new
attempts use the request's captured generation.

### TLS behavior and state

Upstream connections use explicit states:

```text
Idle -> TcpConnecting -> TlsHandshaking -> RequestWriting
     -> ResponseReading -> WebSocketTunneling | Closing -> Closed
```

Connect and handshake deadlines are distinct. HTTP bytes are never written before
TLS establishment. Partial encrypted reads/writes, readiness interest,
backpressure, close-notify, timeout, and terminal failure are explicit events.
Trust, identity, profile, and protocol failures map to a bounded `502`; connect or
handshake timeouts map to `504`. Plaintext fallback is forbidden. Retry remains
limited by the existing safe replay policy. Active health consumes the same typed
trust, SNI, HTTP Host, and generation fence as request forwarding.

Inbound required mTLS accepts HTTP plaintext only after rustls verifies a client
chain for client authentication against the configured bundle. Missing,
untrusted, incomplete, expired, not-yet-valid, wrong-EKU, and malformed client
certificates terminate TLS without an HTTP response. Phase 009 does not add
identity-based authorization or forward client certificate data.

Trust mutation, runtime activation, and HTTPS health likewise use explicit state,
event, guard, failure, and terminal values. Boolean combinations are not an
acceptable substitute for those state machines.

### Time, platform, logging, and disclosure

Certificate time decisions use an injected `Clock` in domain/application logic or
an adapter-owned injectable rustls time capability. Required filesystem and TLS
capabilities are checked during preparation/startup. Unsupported platforms fail
with a stable error rather than reducing authentication guarantees.

Product logs record only bounded outcomes for trust mutation, generation changes,
upstream TLS, and inbound client-auth failures. Handshake failures pass through a
bounded nonblocking queue and a keyed 60-second first-event sampler. Field Debug
uses bounded phase/decision categories under sampling and TTL. Development logs
may contain fixture and transition names and remain disabled by default.

No mode records PEM, keys, subject/issuer/serial/SAN, fingerprint/digest, client
identity, or raw parser/crypto errors. Metrics labels cannot contain trust refs,
SNI, HTTP Host, or certificate identity. API/UI/config diff never echoes trust
material.

### Backup compatibility

Backup schema v2 adds trust-bundle artifacts and validates that every trust ref in
every retained config revision has exactly one authenticated artifact with a
matching digest and safe logical path. Restore validates all relations and builds
the prepared runtime generation before publishing. Schema v1 verify and restore
remain supported with their original no-trust-artifact semantics. Failure leaves
the previous target intact.

## TDD and delivery order

Implementation proceeds as reviewable tasks: domain/schema, managed trust
boundary, mechanical server/client port split, strict upstream HTTPS and health,
required inbound mTLS, atomic activation/backup v2, then Admin UX and release
evidence. Each behavior starts with a failing test and receives the minimum
implementation before refactoring. Tidy First changes stay separate. Adapter
tests alone may use filesystem/network; application tests use fakes and Core uses
scripted TLS sessions.

## Rejected alternatives

- System Root trust or insecure verification: not explicit or deterministic.
- Reusing endpoint host for SNI and HTTP Host: conflates independent identities.
- In-place bundle replacement: changes historical revision meaning.
- Reading trust files in the event loop: introduces blocking I/O and partial truth.
- Optional client authentication: adds an ambiguous authorization surface.
- Runtime environment switches or file-presence policy: bypass canonical config.
- A second async/TLS runtime in Core: unnecessary and violates the mio boundary.

## Consequences

The design adds explicit schema and lifecycle work but keeps authentication
deterministic, rollback-safe, testable with an ephemeral private PKI, and isolated
from data-plane policy. Let's Encrypt, DNS-01, revocation, outbound client
certificates, wildcard selection, and TLS passthrough remain separate work.
