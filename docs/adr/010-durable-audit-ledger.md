# ADR 010: Durable Audit Ledger And Safe Search

- Status: Accepted for phased implementation
- Date: 2026-07-16
- Scope: Phase 010

## Context

Sponzey Edge has an `AuditSink` port, but its record is an unbounded string plus an optional
revision and production creates independent in-memory sinks for config, certificate, and trust
operations. Records disappear at restart, cannot be queried, and do not pair a durable intent with
the actual terminal effect. Setup, production login/logout, and restore have no audit integration.

The ledger is control-plane evidence, not a replacement for Product Log. It must not enter the mio
data-plane hot path, must not hold secrets or raw configuration, and must remain bounded. This ADR
fixes the contracts that later TDD tasks implement. It does not change production behavior.

## Baseline Inventory

### Production sink wiring

| Owner | Current sink | Lifetime | Result |
| --- | --- | --- | --- |
| config and Proxy Host lifecycle | `ConfigLifecycle<FileRevisionRepository, MemoryAuditSink>` | Admin process memory | lost on restart |
| certificate issue/renew/import | `Arc<Mutex<MemoryAuditSink>>` | Admin process memory | separate history, lost on restart |
| trust import/delete | `TrustBundleRuntimeEvents { audit: MemoryAuditSink }` | Admin process memory | errors ignored, lost on restart |

The three constructors are independent. There is no process-wide ordering, reader, verifier,
admission state, or durable head.

### Call-site and side-effect ordering

| Family | Current source behavior | Audit ordering | Compensation/result | Classification |
| --- | --- | --- | --- | --- |
| config apply without Core | validate, save revision, set current | terminal string after current changes | audit failure leaves committed current revision | covered but unsafe ordering |
| config apply with Core | validate, save inactive revision, Core ack, set current | failure string after Core reject; success after current change | terminal audit failure can mask actual effect | covered but unsafe ordering |
| config rollback | find/validate, optional Core ack, set current | terminal string after effect or Core rejection | no durable intent; audit failure leaves effect ambiguous | covered but unsafe ordering |
| Proxy Host CRUD | translate request to full config apply | inherits config lifecycle record | action is only `config.apply`, target CRUD identity is lost | indirectly covered |
| certificate issue/renew | ACME operation, save certificate | terminal string after store save | audit failure leaves saved certificate | covered but unsafe ordering |
| manual certificate import | validate, save certificate, audit, send install command | terminal string before Core outcome | audit failure restores store; Core rejection can leave false success record | covered but misleading |
| trust import/delete | validate/store operation, emit product and audit event | result observation after effect | production ignores audit append failure | covered best-effort |
| setup | save password verifier | none | persistent security mutation has no audit | missing |
| login/logout/lockout | session mutation | helper exists only in application tests | production has no bounded observation | helper-only/missing |
| backup create/verify | read-only maintenance | none | intentionally no ledger mutation | intentionally excluded |
| restore/new target/replace/recover | restore journal and Product Log | none | journal is current authority | missing post-publication provenance |

### Characterized gap

`MemoryAuditSink` retains a record in one instance and a newly constructed instance has zero
records. The desired durable-restart assertion fails before implementation. The executable
baseline checker also fixes the current three-constructor split and call-site counts so later tasks
must update the inventory deliberately rather than silently changing it.

## Architecture Decision

Layer responsibilities are fixed as follows.

```text
domain
  closed audit enums and bounded value objects
  operation/admission/reconciliation reducers
  query and cursor invariants

application
  BeginAuditOperation, CompleteAuditOperation
  RecordSecurityObservation, ReconcileIncompleteAudit, QueryAudit
  persistent mutation orchestration

ports
  AuditLedgerWriter, AuditLedgerReader, AuditLedgerVerifier
  Clock, OperationIdGenerator, AuthoritativeStateInspector

adapters
  canonical codec, SHA-256 frame chain, file segments/index
  certificate/config/trust/restore inspectors

admin/bin
  authenticated request context, bootstrap path and dependency wiring
  startup verification/reconciliation and maintenance CLI
```

Dependencies point inward. Domain and application import no filesystem, JSON codec, SHA, logger,
system clock, environment, mio, rustls, HTTP, or database implementation. Core receives no audit
dependency. All blocking ledger I/O executes on the Admin/maintenance boundary, never the mio event
loop. Reader and writer ports are separate even if one synchronized adapter implements both.

No audit-specific environment variable or external policy file is added. Bootstrap receives the
canonical data directory once and passes an immutable `AuditLedgerOptions` containing the fixed
bounds to the adapter. Runtime environment reread, signal reload, request-level bypass, and global
mutable configuration are forbidden.

## Typed Record Decision

The domain uses closed enums for action, outcome, record kind, target kind, and actor kind. Free
text event names and arbitrary detail maps are not accepted. IDs and error codes are bounded ASCII
value objects. The allowed actor kinds in Phase 010 are `bootstrap_setup`, `bootstrap_admin`,
`maintenance_cli`, and `system_recovery`.

Persistent online mutations use an intent and exactly one terminal record with one server-generated
operation ID. The request ID is bounded correlation only and is never an authorization or
idempotency key. Login success, logout, lockout transition, and sampled authentication failure are
standalone security observations. Observation append failure does not reverse authentication or
session decisions. Setup is a persistent mutation.

The payload allowlist is:

```text
record_version
record_kind
operation_id
request_id
actor_kind
action
target_kind
target_id
before_revision
after_revision
outcome
error_code
timestamp_epoch_seconds
```

Optional fields serialize as JSON `null`, not omission. Passwords, cookies, CSRF and authorization
values, request/response bodies, raw config/diff, filesystem paths, PEM/private keys, certificate
identity/fingerprint/digest, trust digest, IP, User-Agent, username, and raw OS/parser errors are
forbidden.

## Ledger Format Decision

The adapter stores segments under `data/logs/audit/`. `ledger.meta` is an atomic, disposable cache;
verified segment content is the only authority. Missing, stale, or malformed meta is rebuilt after
segment verification.

Each frame is:

```text
magic[8] = "SPAUDIT\0"
frame_version: u16 big endian = 1
flags: u16 big endian = 0
payload_length: u32 big endian
sequence: u64 big endian
previous_hash[32]
payload[payload_length]
frame_hash[32]
```

`frame_hash = SHA-256(frame_version || sequence || previous_hash || payload)`. Header magic,
version, zero flags, exact length, sequence continuity, previous hash, payload schema, and frame
hash are all mandatory verification gates. SHA detects accidental corruption and missing/reordered
local records; it is not hostile-host tamper proof or non-repudiation.

The payload is compact UTF-8 JSON encoded by an adapter DTO with the field order above. No
whitespace is emitted. Domain constructors reject invalid ASCII identifiers before serialization;
the codec performs no Unicode normalization. Golden byte fixtures fix optional-null behavior,
integer representation, enum spelling, and field order. Unknown frame or record versions fail
closed.

Fixed Phase 010 bounds are: payload 8 KiB, ID/filter 128 bytes, startup records 100,000,
incomplete operations 1,024, segment 4 MiB, retained segments 32, retained total 128 MiB, query
default 50 and maximum 100. Acknowledgement is returned only after file sync. Once synced, a frame
is never rewritten in place.

## Startup And Recovery Decision

Startup holds the existing exclusive data-directory lock and performs:

```text
lock -> discover bounded segments -> verify frames/chain/sequence
     -> rebuild immutable index/head -> recover trailing residue if any
     -> find bounded incomplete operations -> reconcile authoritative facts
     -> publish shared reader/writer/admission -> enable persistent mutations
```

Only an incomplete final frame at EOF may be recovered. Under the exclusive lock, the adapter
verifies the complete prefix, truncates only the incomplete suffix, syncs the file and directory,
then appends a `system_recovery` record. Interior malformed data, sequence gaps, hash mismatch,
unsupported versions, excess bounds, or conflicting authoritative facts are never truncated or
skipped and enter failed-closed admission.

Ledger failure does not stop a previously validated data-plane configuration. It blocks persistent
Admin mutations while login/session decisions and authenticated read-only status, query, and verify
remain available. No production file-ledger wiring is activated until verification and incomplete
operation reconciliation pass as one composition-root cutover.

## Rotation And Retention Decision

A segment rotates before a frame would exceed 4 MiB. The new segment links to the predecessor
terminal hash and preserves the monotonic sequence. New file publication and parent directory sync
complete before the head is exposed.

At 32 segments or 128 MiB, retention may delete whole oldest segments only. Before deletion, a new
retained segment receives a first, synced checkpoint record containing the pruned sequence range
and terminal hash. The checkpoint file and directory are synced before old segment deletion;
deletion and its directory sync must succeed before capacity is considered available. No frame or
partial segment is rewritten. Failure keeps the old segments and moves admission to degraded.

The query reader uses a verified immutable index snapshot and does not hold the append lock while
formatting results. The newest-first cursor is a URL-safe opaque encoding of
`(ledger_generation, before_sequence)`. It contains no path, offset, or hash. A generation/range
mismatch after retention returns stable `AUDIT_CURSOR_INVALID` rather than silently changing pages.

## Restore And Backup V3 Decision

Backup creation and verification are read-only and do not append an audit record, because changing
the ledger after inventory capture would make the archive self-inconsistent. Schema v3 adds one
authenticated manifest relation for the verified audit head and an `audit_segment` artifact for
every retained segment. The disposable `ledger.meta` cache is not archived. Segment count, size,
frame chain, sequence, checkpoint, and manifest completeness are verified before encryption output
is accepted.

Restore preflight authenticates and verifies every segment before target publication. Schema v1/v2
remain readable with no audit artifacts. During restore/replace/recover, the existing durable
restore transaction journal is authoritative; writing restore intent into the ledger that is about
to be replaced is forbidden. Publication failure leaves the prior target unchanged or follows the
existing journaled rollback contract. After successful publication and target preflight, one
`maintenance.restore_imported` provenance reconciliation record is appended to the restored ledger
with the restore journal operation ID and source manifest ID. Failure of this append is reported as
audit degraded without claiming that publication did not occur.

## State Machine Decision

Persistent operation states are:

```text
Received -> IntentPersisting -> IntentPersisted -> EffectRunning
         -> EffectCommitted | EffectRejected -> TerminalPersisting -> Completed

IntentPersisting -> RejectedNoEffect
TerminalPersisting -> AuditDegradedCommitted | AuditDegradedRejected
```

Admission states are:

```text
Starting -> Verifying -> Reconciling -> Healthy
Verifying | Reconciling -> FailedClosed
Healthy -> Degraded -> Reconciling | FailedClosed
```

Append states are:

```text
Ready -> Encoding -> Appending -> Syncing -> PublishedHead
Ready -> RotationRequired -> SegmentPreparing -> SegmentPublished -> Ready
Ready -> RetentionRequired -> CheckpointPersisted -> OldSegmentRemoved -> Ready
Appending | Syncing -> Degraded
```

Guards require Healthy admission before persistent intent, durable intent before effect port calls,
an explicit actual effect state before terminal append, one terminal per operation, verified valid
prefix before trailing recovery, and durable checkpoint before deletion. Unknown reconciliation is
a terminal mutation block, not a guessed success/failure. These are enums and pure reducers, never
boolean-flag combinations.

## Logging Decision

Product Log permits bounded `audit.ledger.ready`, `audit.ledger.degraded`,
`audit.ledger.recovered`, `audit.retention.checkpointed`, and
`audit.reconciliation.completed` outcomes. Field Debug may include bounded operation ID, action,
transition, sequence, and segment number under a 60-second bounded-key sampler. Development/Test may
include fixture IDs, transition names, and injected failure points and is disabled in production by
default. No mode logs payload, path, frame hash, config, secret, certificate identity, or raw error.
Log mode is read once at bootstrap and passed as an immutable dependency.

## TDD And Delivery Consequences

Delivery order is domain/value/state contracts, ports/application use cases, file codec/startup,
rotation/retention, candidate mutation integration, reconciliation and atomic production cutover,
query API/UI, backup v3/restore provenance, then release evidence. Each behavior starts with a
failing test. Application tests use fake ledger/clock/ID/inspectors; only adapter tests use files;
integration tests use a real data directory and restart/restore. Tidy changes remain separate from
behavior changes.

## Rejected Alternatives

- Product Log or best-effort text file as audit: no durable intent/terminal contract.
- SQLite solely for audit: adds an unnecessary database boundary and operational dependency.
- One mutable JSON file: unbounded rewrite and crash ambiguity.
- `ledger.meta` as authority: stale cache can publish a false head.
- Skipping corrupt frames: presents incomplete history as valid.
- Rewriting partial segments for retention: violates synced-record immutability.
- Runtime environment switch to disable audit: bypasses canonical admission policy.
- Blocking login when audit is degraded: prevents operator read-only recovery access.
- Restore intent in the target ledger: successful replacement deletes its own intent.
- Hash-chain non-repudiation claim: local host write access can replace chain and metadata.
- File I/O in mio event loop: violates the data-plane boundary and latency requirements.

## Consequences

Phase 010 adds durable synchronous work to persistent Admin mutations but not proxy traffic. Disk
failure intentionally blocks new persistent control-plane changes. The fixed retention loses old
detail by design but leaves a checkpoint. Multi-user identity, remote anchoring/export, legal hold,
and hostile-admin tamper resistance remain explicit future work.
