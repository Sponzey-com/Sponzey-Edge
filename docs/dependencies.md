# Dependency Decisions

## Phase 008 Accepted Candidates

ADR [`docs/adr/008-backup-recovery-foundation.md`](adr/008-backup-recovery-foundation.md)
selects the following versions for phased, adapter-only introduction:

- `age 0.12.1`, default features disabled, passphrase/scrypt streaming encryption only
- `tar 0.4.46`, default features disabled, uncompressed manual-entry processing only
- `fs4 1.1.0`, synchronous nonblocking advisory locks
- `zeroize 1.8.1`, pinned because workspace MSRV is Rust 1.80
- `sha2 0.10.9`, `getrandom 0.3.4`, and `rpassword 7.4.0` at adapter/bin boundaries
- existing dev-only `rcgen 0.14.8` for private PKI fixtures

Task 003 adds `fs4`, Task 004 pins `zeroize`, and Task 005 adds `age`, `sha2`,
`getrandom`, and Unix `libc` at adapter/bin boundaries. `tar` and `rpassword`
remain unselected and are not in Cargo manifests. Each owning implementation task must add only the dependency it uses, keep it out of
domain/application/core, run MSRV/advisory checks, and record the resulting dependency graph.
`tar` unpack APIs and `age` plugin features are prohibited.

Every non-standard dependency must be recorded here before or with the code change that introduces it.

## Template

```text
Date:
Crate:
Layer:
Purpose:
Alternatives considered:
Risk:
Decision:
```

```text
Phase 011 Task 048
Date: 2026-07-17
Dependency: existing serde/serde_json, sha2, and standard filesystem APIs
Layer: edge-memory-harness and release-script adapters only
Purpose: Canonical fixed-allowlist steady-profile manifest, SHA-256 binding, and atomic publication.
Alternatives considered: shell-only ad hoc JSON parsing, newest-file directory discovery, or a product runtime evidence dependency.
Decision: Reuse existing test-only serializers and digest code. Add no crate, product dependency, environment reader, or hot-path code. Release scripts invoke the test-only inspector only when both optional manifest files are explicit.
```

## Current External Runtime Dependencies

```text
Date: 2026-07-15
Crate: age 0.12.1 (default features disabled), sha2 0.10.9, getrandom 0.3.4, libc 0.2
Layer: edge-adapters encrypted archive/filesystem boundary; edge-proxy Unix passphrase-file bootstrap boundary
Purpose: Stream a passphrase-authenticated encrypted backup, compute deterministic SHA-256 manifest/artifact digests, generate opaque operation/archive IDs, and reject symlink passphrase input with O_NOFOLLOW.
Alternatives considered: plaintext tar, OpenSSL subprocess, custom AEAD/KDF envelope, path metadata followed by ordinary open, rpassword interactive input.
Risk: age expands the transitive crypto/i18n graph; passphrase mode depends on scrypt cost and archive compatibility; Unix no-follow behavior needs an explicit unsupported-platform failure; secret copies outside SensitiveString cannot be cleared.
Decision: Use age passphrase streaming only behind BackupArchiveWriter, encode bounded canonical records manually, and avoid tar/unpack and plugin features. Keep sha2/getrandom/libc out of domain/application/core. Task 005 gates this graph with workspace clippy/tests and architecture checks; advisory/license evidence remains a release gate before distribution.
```

```text
Date: 2026-07-15
Crate: zeroize 1.8.1
Layer: edge-domain sensitive value boundary
Purpose: Clear passphrase-equivalent String storage on drop while exposing it only through an explicit scoped callback.
Alternatives considered: ordinary String, manual volatile memory clearing, adapter-specific secret wrappers.
Risk: Memory copies outside the wrapper cannot be cleared; callers must not clone or format exposed values.
Decision: Pin 1.8.1 for Rust 1.80 compatibility. SensitiveString derives neither Clone nor raw Debug and uses a custom redacted Debug implementation.
```

```text
Date: 2026-07-15
Crate: fs4 1.1.0
Layer: edge-adapters filesystem boundary only
Purpose: Provide synchronous nonblocking cross-platform advisory file locks for exclusive data-directory ownership.
Alternatives considered: std File locking (workspace MSRV 1.80 predates stabilization), lock-file existence, platform-specific flock/LockFileEx, directory rename sentinels.
Risk: Advisory locks require every Sponzey process to cooperate; aliases must resolve to one canonical target identity and unsupported platforms must not silently succeed.
Decision: Use FileExt::try_lock behind DataDirectoryLockManager/Guard ports. Keep the held File handle outside the target directory for the full serve/maintenance lifetime; never infer ownership from lock-file existence.
```

```text
Date: 2026-06-04
Crate: mio
Layer: edge-core
Purpose: Core data-plane event loop, listener readiness, and future nonblocking socket state machine.
Alternatives considered: Tokio, async web framework runtime, direct blocking std::net.
Risk: mio is lower-level and requires explicit state machine tests for readiness, interest changes, timers, and backpressure.
Decision: Use mio for the Core data plane to satisfy the project requirement for an explicit, predictable reverse proxy state machine.
```

## Current Internal Boundary Decisions

```text
Date: 2026-07-18
Crate: edge-memory-harness
Layer: test/release-tool model and adapter only
Purpose: Re-evaluate and bind full-profile readiness plus the fixed two-hour soak into final Phase 011 evidence.
Alternatives considered: shell-only JSON matching, trusting prior ready booleans, or adding the checker to a product crate.
Risk: A stale or selected report could publish a false marker; adding a production dependency would contaminate the data-plane graph.
Decision: Add no dependency. Reuse serde and the existing test-only SHA-256/report adapters, keep evaluation pure, and keep filesystem/process behavior outside product crates.
```

```text
Date: 2026-07-16
Crate: edge-memory-harness
Layer: test/release-tool report adapter only
Purpose: Bind canonical Phase 011 memory report bytes to an independently verifiable SHA-256 digest.
Alternatives considered: platform sha256sum/shasum commands, non-cryptographic std hash, reuse edge-adapters backup implementation.
Risk: A crypto dependency in production would expand the hot-path graph; custom hex encoding must stay deterministic.
Decision: Use sha2 0.10.9 only in the test-tool crate. Keep report schema/evaluation free of filesystem and hashing, and keep product crates independent of edge-memory-harness.
```

```text
Date: 2026-07-16
Crate: edge-domain, edge-ports, edge-application, edge-adapters
Layer: durable audit domain/port/orchestration/filesystem adapter boundaries
Purpose: Persist typed intent/terminal and security records with bounded restart-safe query, reconciliation, retention and backup restore provenance.
Alternatives considered: Product log as audit, SQLite solely for audit, JSON lines, runtime audit-disable environment switch.
Risk: Synchronous fsync adds control-plane latency; a local privileged writer can replace the chain; bounded retention may fail closed under disk pressure.
Decision: Add no dependency. Use the existing SHA-256 adapter dependency with a canonical bounded frame, owner-only whole segments, explicit state machines and authenticated safe metadata projection. Keep core/domain free of filesystem, serde and hash implementations.
```

```text
Date: 2026-07-14
Crate: edge-application, edge-adapters, edge-admin-api
Layer: application port and outer adapters
Purpose: Aggregate typed metrics and expose immutable snapshots through Prometheus and authenticated Admin views.
Alternatives considered: Prometheus client crate, registry locks in core/Admin handlers, or a metrics sidecar protocol.
Risk: Custom exposition must preserve escaping, ordering, bounds, and HTTP resource limits.
Decision: Add no exporter dependency. Keep typed descriptors/registry policy in ports/application, use a single-writer adapter collector and immutable reader port, and bind a bounded std::net loopback adapter outside the mio data plane.
```

```text
Date: 2026-07-07
Crate: edge-ports
Layer: ports
Purpose: Own CoreCommandClient, Clock, and SecretStore boundaries so application/control-plane adapters can depend on ports rather than each other.
Alternatives considered: Keep CoreCommandClient in edge-admin-api.
Risk: Leaving command delivery in edge-admin-api would make future CLI/control-plane code depend on Admin API concepts.
Decision: CoreCommandClient, Clock, and SecretStore belong in edge-ports.
```

```text
Date: 2026-07-07
Crate: edge-admin-api
Layer: adapter contract
Purpose: Define the initial Admin API HTTP request/response contract without binding a network listener or introducing an async runtime.
Alternatives considered: Add axum, hyper, tiny_http, or a custom TcpListener directly in edge-admin-api.
Risk: Introducing a framework too early can pull runtime dependencies into the wrong layer or hide auth/CSRF behavior behind framework glue.
Decision: Keep the current status/setup/login/logout/auth preflight router framework-free. Add any future HTTP server dependency only at adapter/bin boundary with a separate decision entry.
```

```text
Date: 2026-07-07
Crate: edge-proxy
Layer: bin/adapter boundary
Purpose: Bind the initial Admin API status/setup/login/logout/auth preflight listener over local TCP while reusing the framework-free edge-admin-api contract.
Alternatives considered: Move TcpListener into edge-admin-api or add a web framework now.
Risk: Binding inside edge-admin-api would mix network adapter code into the contract crate; adding a framework now would expand the runtime surface before login/mutation endpoints are complete.
Decision: Use std::net in edge-proxy for the initial listener and keep edge-admin-api socket-free.
```

```text
Date: 2026-07-07
Crate: edge-proxy, apps/admin-web
Layer: bin/adapter boundary, optional UI client
Purpose: Extend the same socket-free Admin API contract to config lifecycle, proxy host CRUD, certificate reads, log reads, and a static Admin Web UI client.
Alternatives considered: Move HTTP routing into edge-core, let the UI write config files directly, or add a browser framework/build step for the MVP UI.
Risk: UI fallback can mask backend failures, and richer HTTP/UI dependencies can leak into the core hot path.
Decision: Keep Admin API handlers framework-free in edge-admin-api, bind TCP only in edge-proxy, keep Admin Web UI as static assets that call /api/v1, and gate the UI with smoke_admin_web plus architecture checks for no direct file writes.
```

```text
Date: 2026-07-07
Crate: rustls 0.23.41
Layer: edge-adapters TLS adapter boundary; edge-proxy dev-dependency for HTTPS smoke client
Purpose: Build server TLS configuration from persisted certificate/key material and generate a test-only rustls client for local self-signed HTTPS smoke.
Alternatives considered: OpenSSL/native-tls, tokio-rustls, hand-rolled TLS parsing.
Risk: Rustls is low-level and does not perform network I/O or file reads itself; integration must keep certificate parsing and config construction outside the mio event loop and must not leak rustls types into domain/application.
Decision: Use rustls runtime server configuration in edge-adapters, with `default-features = false` and the `ring` provider selected explicitly. Allow direct rustls use in edge-proxy tests and the edge-memory-harness test-tool only for local HTTPS client smoke and capacity measurement. Do not add Tokio or an async TLS wrapper to the core hot path.

Phase 009 capability review (2026-07-15): rustls 0.23.41 already provides the
adapter APIs required by ADR 009: an explicit Root-store client configuration for
strict upstream authentication, `WebPkiClientVerifier` for required inbound
client authentication, and `TimeProvider` for deterministic certificate-time
tests. Reuse this dependency in `edge-adapters`; do not introduce another TLS
runtime. Rustls values remain behind direction-specific ports and immutable
prepared runtime capabilities. A later API gap must be documented here before a
dependency is added.

Phase 009 Task 011 implementation (2026-07-15): the outbound client adapter now
uses an empty `RootCertStore` populated only from the selected validated managed
trust bundle, advertises only HTTP/1.1 ALPN, and receives the server name as an
explicit typed port argument. It does not consult native roots, environment, or
files. Verification failures are mapped to bounded identity-mismatch,
untrusted-peer, or invalid-profile errors before leaving `edge-adapters`.
```

```text
Date: 2026-07-07
Crate: rustls-pki-types 1.15.0
Layer: edge-adapters TLS adapter boundary; edge-proxy dev-dependency for HTTPS smoke trust root parsing
Purpose: Parse certificate and private key PEM sections for the rustls server config loader and parse the test trust root for local HTTPS smoke.
Alternatives considered: rustls-pemfile.
Risk: PEM parsing errors must become `CertificateStoreFailed`/TLS boundary errors, never panic.
Decision: Depend directly on rustls-pki-types PEM APIs because rustls-pemfile is marked unmaintained and RustSec recommends using the PEM parsing code in rustls-pki-types.

Phase 011 Task 039 (2026-07-17): `edge-memory-harness` uses these existing TLS
dependencies only to parse a temporary private Root, verify `localhost` SNI, and hold 512 complete
client handshakes. Product domain/application/core crates do not depend on the harness, Root paths
are bootstrap-only test inputs, and certificate/key material is excluded from evidence.

Phase 011 Task 040 (2026-07-17): the same test-tool boundary additionally parses a client
certificate chain and private key into an immutable rustls client-auth config for required-mTLS
capacity measurement. The key remains an owner-only temporary input; it is never returned through
product types, logs or evidence. No product dependency or runtime environment lookup was added.
```

```text
Phase 011 Task 044
Date: 2026-07-17
Crate: socket2 0.6.4
Layer: edge-memory-harness test/release adapter only
Purpose: Set a deterministic 4 KiB receive buffer on slow-response test clients.
Alternatives considered: OS-default receive buffers, unsafe platform-specific libc setsockopt.
Risk: A test helper dependency must not enter the product core or be interpreted as a production socket policy.
Decision: Declare the already locked crate directly in edge-memory-harness and use safe SockRef APIs. No edge-core, domain, application, or product hot-path dependency is added. Phase 011 Task 043 owns this decision.
```

```text
Date: 2026-07-17
Crates: edge-adapters, edge-admin-api, edge-application, edge-domain, edge-ports
Layer: edge-memory-harness test/release composition only
Purpose: Hold the production audit ledger and metric registry at their declared maximums and query their public reader/Admin contracts for Task 044 control-max RSS evidence.
Alternatives considered: hidden product fixture mode, tens of thousands of live Admin mutations, fake vectors that only approximate production types.
Risk: A test composition can be mistaken for full edge-proxy process RSS or leak fixture hooks into product layers.
Decision: Use local workspace dependencies only from edge-memory-harness. Keep preparation, digest verification, query lifecycle and RSS sampling outside the product graph; add no product endpoint, env switch or core dependency. Document fixture-process overhead and require a later full release composition profile.
```

```text
Date: 2026-07-07
Crate: rcgen 0.14.8
Layer: edge-adapters and edge-proxy dev-dependency
Purpose: Generate self-signed certificate/key fixtures for rustls loader tests and local HTTPS smoke without checking PEM secrets into the repository.
Alternatives considered: static PEM fixtures, shelling out to openssl.
Risk: Test-only crypto fixture generation must not become runtime certificate issuing behavior.
Decision: Use rcgen only as a dev-dependency in adapter/bin and memory-harness tests. Runtime ACME/manual certificate handling remains behind ports and file stores.
```

```text
Phase 011 Task 046
Date: 2026-07-17
Crate: rcgen 0.14.8
Layer: edge-memory-harness dev/test adapter only
Purpose: Generate in-memory private Root and localhost leaf material for deterministic trusted and wrong-identity HTTPS steady driver tests.
Alternatives considered: checked-in private keys, shelling out to OpenSSL from Rust tests, or exposing a product certificate fixture mode.
Risk: Test certificate generation could leak material into evidence or be mistaken for runtime certificate issuance.
Decision: Reuse the already locked rcgen version only in dev tests. The actual release smoke generates ephemeral material with OpenSSL before process start; no PEM, path, product dependency or runtime environment switch enters evidence or product layers.
```

```text
Phase 011 Task 047
Date: 2026-07-17
Crates: rustls 0.23.41, rustls-pki-types 1.15.0
Layer: edge-memory-harness test/release adapter only
Purpose: Parse one server Root and complete client-auth identity, then inject an immutable config into the shared steady driver.
Alternatives considered: curl subprocess per request, product fixture hooks, or duplicated TLS driver logic.
Risk: Client key material could leak into evidence or the adapter could be mistaken for product trust management.
Decision: Keep parsing and paths in mtls_steady, reuse locked test dependencies, and reject PEM/path/key markers from evidence. No product dependency changes.
```

```text
Date: 2026-07-08
Crate: instant-acme 0.8.5
Layer: edge-adapters ACME adapter boundary
Purpose: Implement the real Let's Encrypt HTTP-01 ACME client behind the AcmeClient port without leaking async ACME types into domain/application/core.
Alternatives considered: acme-client, shelling out to certbot, hand-rolled RFC 8555 client.
Risk: instant-acme is async and network-facing; it must remain in edge-adapters and be wrapped behind the synchronous port so the mio core hot path never depends on Tokio or Hyper.
Decision: Use instant-acme with default features disabled and explicit ring/hyper-rustls/rcgen features. Run it inside the adapter boundary only.
```

```text
Date: 2026-07-08
Crate: tokio 1.48.0
Layer: edge-adapters ACME adapter boundary
Purpose: Provide the minimal runtime needed to execute instant-acme's async client inside the adapter.
Alternatives considered: Expose async through application ports, spawn an external certbot process, or add a global runtime to edge-core.
Risk: Tokio must not enter edge-core hot path or domain/application crates.
Decision: Depend on Tokio only from edge-adapters with rt/time/net features and construct a local current-thread runtime inside the ACME adapter.
```

```text
Date: 2026-07-08
Crate: x509-parser 0.18.1
Layer: edge-adapters certificate parsing boundary
Purpose: Parse the leaf certificate not_after timestamp from ACME PEM output for CertificateStore metadata.
Alternatives considered: Store a placeholder expiry, parse with OpenSSL, or add certificate parsing to application.
Risk: Certificate parsing failures must become CertificateStoreFailed or AcmeChallengeFailed AppError values, never panics.
Decision: Use x509-parser only in edge-adapters to derive metadata from already-issued certificate material.

Phase 009 may also use x509-parser inside `edge-adapters` for bounded trust-bundle
profile checks. Domain/application expose only typed refs, counts, decisions, and
stable errors; they never expose parser types or raw certificate identity.
```

## Phase 011 macOS Diagnostic Tool Boundary

Task 069 adds no product or third-party runtime dependency. The pure report model uses the existing
test-only `edge-memory-harness` serde and SHA-256 facilities. `codesign`, `/usr/bin/leaks`, `ps`, and
standard shell utilities are macOS release-test adapter prerequisites only. They are never invoked
from product domain/application code or the mio event loop, and the temporary entitled binary is
not a build or distribution output.
