# ADR 011: Quantitative Memory And Resource Safety

- Status: Accepted for Phase 011 implementation, numeric RSS ceilings provisional until reference profiles
- Date: 2026-07-16
- Scope: runtime resource policy, logical payload accounting, memory evidence

## Context

The proxy already limits connections, request headers/bodies, response buffering, channels, metrics,
and audit storage. These independent limits do not prove a process-wide memory envelope. Request
completion, parsing, upstream formatting, retry, TLS, response, and WebSocket paths may retain
multiple allocations at the same time.

The source inventory is `docs/memory-resource-baseline.md`. Phase 010 release evidence proves the
existing functional baseline but contains no quantitative idle/peak/cooldown memory profile.

## Decision

### Product Resource Policy

The product will use one immutable `RuntimeResourcePolicy` injected at bootstrap.

| Field | Initial default | Allowed range | Activation |
| --- | ---: | ---: | --- |
| `max_connections` | 1,024 | 1..=4,096 | restart required |
| `max_inflight_payload_bytes` | 134,217,728 (128 MiB) | 16..=512 MiB | restart required |

The values are first implementation candidates, not a claim that RSS is 128 MiB. Increasing the hard
maximum requires new reference evidence and an ADR revision.

### Accounting Unit

The central ledger charges proxy-owned **logical payload bytes**. A charge remains owned until its
backing payload is dropped or ownership is explicitly transferred. Partial socket writes do not imply
that allocator capacity was returned.

Direct charges include request, upstream wire/replay, pending client response, WebSocket directions,
and adapter/core TLS pending bytes. rustls internals, allocator metadata/free arenas, shared libraries,
and kernel socket buffers are outside the direct ledger and are constrained through connection limits
and measured RSS profiles.

### Failure Semantics

- New connection capacity failure rejects only the new admission.
- Request capacity failure returns 503 only when valid framing can still be produced; otherwise it closes.
- Per-request body overflow remains 413.
- Response pressure pauses upstream reads and preserves existing client drain/timeout progression.
- WebSocket pressure pauses the corresponding source read.
- Managed buffer allocation failure becomes a typed error; this does not promise recovery from every
  allocator or dependency OOM.
- Accounting invariant failure enters failed-closed admission without panicking the data plane.

### Desired And Active Policy

Resource policy revisions are restart-required. Admin API/UI and metrics must distinguish desired and
active revision/policy identity. Committing a revision does not mutate the running ledger. A successful
restart and startup validation make desired policy active; failed startup never publishes false activation.

### Evidence Contract

The Task 001 mini baseline establishes tooling, not the final release gate. Full completion requires:

- macOS arm64 and Linux x86_64 release profiles;
- HTTP, HTTPS, required mTLS, WebSocket, churn, slow-path, audit, and metric scenarios;
- correctness counters, active connections zero, and logical charge zero after cooldown;
- absolute profile ceilings plus relative plateau checks over three runs;
- at least one actual deep diagnostic artifact and no definite leak in any supplied artifact.

Provisional absolute ceilings are the Phase 011 plan candidates. They may be amended once, before
resource behavior implementation, based on Task 001 baseline and deployment capacity review. After
behavior work begins, relaxing a threshold requires failure analysis, reviewer approval, and fresh
cross-platform evidence.

## Task 001 Baseline Record

The source-bound Task 001 reports are written below after the release mini-run:

| Scenario | Connections | Baseline RSS | Peak RSS | Report |
| --- | ---: | ---: | ---: | --- |
| idle | 0 | observed 9-10 MiB | observed 9-10 MiB | `artifacts/memory-baseline/task001/idle.json` |
| idle connections | 100 | observed 9-10 MiB | observed 9-10 MiB | `artifacts/memory-baseline/task001/idle-100-connections.json` |

Two Task 001 runs kept the observed 100-connection increase below 1 MiB. The short sample does not
include a full HTTP request, upstream connection, TLS, response payload, or allocator cooldown. These
measurements characterize one macOS arm64 host/build only and cannot be reused as Linux or final
release evidence. The source-bound JSON contains the exact values and is authoritative; the table is
an initial human-readable characterization and must not be used as a release ceiling.

## Architecture Consequences

- Product domain/application/core do not depend on the memory harness.
- Product core does not execute `ps`, `/proc`, filesystem reports, or allocator diagnostics.
- The harness has its own model/application/port/adapter boundary.
- Environment is read only at product bootstrap. Harness inputs are explicit CLI values; child process
  bootstrap values are set once before spawn and never mutated afterward.
- Existing metrics and observation ports are extended instead of introducing a parallel logging system.

## Rejected Alternatives

- Treating `max_connections * max_request_body_bytes` as RSS: ignores copies, TLS, allocator, and control plane.
- Using RSS alone as a leak proof: allocator retention and shared pages make the conclusion invalid.
- Reading RSS in the mio event loop: introduces blocking OS/process work into the data plane.
- Runtime environment overrides for limits/thresholds: violates immutable configuration lifecycle rules.
- One global mutable counter accessed by every layer: creates hidden state and cross-thread coupling.

## Verification

- `cargo test -p edge-memory-harness`
- `./scripts/collect_memory_baseline.sh`
- `./scripts/check_architecture.sh`
- `./scripts/check_release_docs.sh`

## Task 048 Manifest Decision

The first aggregate contract is `phase011-steady-v1`, containing exactly HTTP steady 100,000,
private-PKI HTTPS steady 50,000, and required-mTLS steady 25,000. It binds canonical report,
digest, driver and terminal summaries, source identity, correctness, cleanup, recovery, and the
existing 384 MiB candidate ceiling. Collection and full validation are separate process operations.

This contract is always `partial` with one repetition. `Approved` is rejected until a later reviewed
schema proves Linux x86_64, three independent repetitions, and long-soak/deep-diagnostic evidence.

## Task 049 Repeatability Decision

Exactly three independently collected `phase011-steady-v1` manifests form
`phase011-steady-3run-v1`. The aggregate requires identical source, platform, architecture, and
typed scenario contracts, but distinct hashes of each run's process-start identity set. Raw config
digests differ because each independent run uses fresh ports and temporary paths; each digest stays
bound and validated inside its child manifest. The aggregate revalidates every child against its
original report files rather than trusting selected fields.

For each scenario, both peak and cooldown RSS ranges must fit
`max(16 MiB, minimum peak RSS / 10)`. The fixed 384 MiB ceiling and all correctness, negative TLS,
forwarding, recovery, and zero-cleanup contracts remain unchanged. Checked arithmetic rejects
overflow. This threshold is provisional but source-controlled; changing it requires a reviewed
behavior change and fresh evidence.

The aggregate remains `partial`. It removes the three-independent-repetitions blocker only for the
three covered steady scenarios and does not substitute for Linux x86_64, full-scenario, long-soak,
or deep diagnostic evidence.
