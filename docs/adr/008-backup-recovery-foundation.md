# ADR 008: Backup Recovery Foundation

- Status: Accepted for phased implementation
- Date: 2026-07-15
- Scope: Phase 008 encrypted offline backup, crash-recoverable restore, private PKI recovery
- External/operational exclusions: Let's Encrypt, online restore, remote storage
- Follow-up TLS scope: mTLS and other private-PKI-testable TLS capabilities are
  outside Phase 008 delivery but are not excluded from the product roadmap

## Context

The current process reads a bootstrap config file, imports it into
`FileRevisionRepository`, and later Admin apply/rollback changes the repository current pointer.
The current physical stores are useful but are not yet one recoverable transaction:

| Logical state | Current physical layout | Baseline evidence |
| --- | --- | --- |
| bootstrap seed | `config/current.toml` by default | `bootstrap_config_from_env` |
| revision pointer | `config/current` | `FileRevisionRepository::current_path` |
| revisions | `config/revisions/<hex-id>.toml` | `revision_path` and repository tests |
| certificate chain | `certs/<encoded-ref>/fullchain.pem` | certificate store tests |
| certificate key | `certs/<encoded-ref>/privkey.pem` | owner-only permission test |
| certificate metadata | `certs/<encoded-ref>/metadata.toml` | certificate store roundtrip test |
| Admin verifier | `secrets/admin-password-hash.secret` | secret store and Admin setup tests |

The bootstrap seed and revision pointer could diverge after an Admin apply. Task
002 replaced seed-first startup with repository-first resolution before backup
format work. It also established an adapter test proving owner-only secret-file
permissions, keeping both changes outside the future backup adapter.

## Decisions

### 1. Config authority

- The revision repository current pointer is the authoritative startup state.
- The bootstrap file is a seed only when the repository is empty.
- A missing/dangling pointer in a non-empty repository fails closed.
- A completely empty repository with no seed remains explicitly `Unconfigured`;
  this preserves headless first-start behavior and is not a valid backup source.
- Startup validates config and TLS material before committing an imported seed.
- Schema v1 backs up revision payloads and the current pointer, not `current.toml`.
- Startup and restore preflight use the same application use case.

### 2. Schema v1 assets

Exact allowlist:

- current revision pointer
- all valid revision payloads
- all certificate chain/key/metadata triples
- `admin-password-hash` only when Admin setup is complete

Excluded:

- bootstrap seed, logs, backup recursion, temp files, lock/journal files
- sessions, CSRF, runtime health/drain/metrics, in-memory audit events
- unknown plugin files and unknown secrets
- Root/Intermediate CA private keys

Unknown or malformed entries inside managed config/cert/secret directories fail backup. They are
not silently skipped. Schema v1 uses the limits in `.tasks/plan.md` and does not compress data.

### 3. Encryption envelope

Select `age 0.12.1` with default features disabled and passphrase encryption only.

Reasons:

- standard age file format instead of a custom cryptographic protocol
- scrypt passphrase recipient/identity with a configurable maximum work factor
- streaming authenticated payload and truncated-stream rejection
- Rust 1.74 MSRV, compatible with workspace Rust 1.80
- MIT OR Apache-2.0

Constraints:

- no plugin, SSH, armor, async, or CLI-common features
- no custom KDF, nonce, MAC, or AEAD implementation
- decryption identity must set the ADR-approved maximum work factor before decrypting
- wrong passphrase and tamper map to one external authentication error
- `age` is marked beta/experimental; the adapter and contract fixtures isolate replacement risk
- RustSec `RUSTSEC-2024-0433` affects old plugin APIs; version 0.12.1 is outside the listed affected
  versions and plugin support remains disabled

The exact maximum work factor and passphrase length bounds must be measured and fixed in the first
encryption-adapter task. No production archive is emitted before those tests exist.

### 4. Archive container

Select `tar 0.4.46` with default features disabled, nested inside the age stream.

Reasons:

- streaming reader/writer without whole-archive memory residency
- no compression in the crate or schema v1
- Rust 1.63 MSRV and MIT OR Apache-2.0

Constraints:

- never call `Archive::unpack`, `unpack_in`, `Entry::unpack`, or `Entry::unpack_in`
- inspect every entry header and stream accepted regular-file payloads into bounded staging files
- reject links, devices, FIFOs, unknown types, absolute/parent/platform-prefixed paths,
  duplicate paths, PAX/sparse surprises, trailing data, count/size overflow
- write deterministic ustar-compatible regular entries with normalized metadata
- RustSec advisories `RUSTSEC-2018-0002`, `RUSTSEC-2021-0080`,
  `RUSTSEC-2026-0067`, and `RUSTSEC-2026-0068` are patched by 0.4.46; the affected unpack APIs
  remain prohibited as defense in depth

### 5. Data-directory lock

Select `fs4 1.1.0` with sync support only.

- advisory cross-platform file locks
- nonblocking `try_lock` behavior for typed busy errors
- Rust 1.75 MSRV and MIT OR Apache-2.0
- lock file lives in the canonical target parent, not inside the renamed data directory
- lock ownership is represented by a held file handle, never file existence
- unsupported alias/durability semantics fail closed

### 6. Supporting dependencies

- `zeroize = 1.8.1` pinned for Rust 1.80 compatibility; 1.9.0 requires Rust 1.85
- `sha2 = 0.10.9` for artifact SHA-256 in the adapter/codec boundary
- `getrandom = 0.3.4` for archive/operation identifiers in an adapter
- `rpassword = 7.4.0` for no-echo terminal input in the bin boundary
- existing `serde_json` may encode adapter-owned manifest DTOs; domain types do not derive archive DTOs
- `tempfile` is dev-only for adapter/integration tests
- existing `rcgen 0.14.8` remains dev-only for private PKI fixtures

No dependency is added to production manifests by this ADR task. Exact additions occur only in the
task that owns the corresponding adapter and tests.

### 7. Private PKI fixture

Each test run creates Root CA, pathLen=0 issuing Intermediate CA, and server leaf in memory. The
Intermediate signs the leaf; the client trusts Root only; the server fullchain contains leaf then
Intermediate and excludes Root. The leaf uses SAN `app.private.test`, serverAuth EKU, and explicit
not-before/not-after values. Root/Intermediate private keys never enter product stores, archives,
logs, or release evidence.

Server-side material validation proves parse/key/SAN/profile/time/chain-signature properties.
Client-side rustls handshake separately proves Root trust, complete chain, and SNI authentication.

## State And Durability Decisions

- Config authority, backup, restore, lock, and certificate preflight use explicit enums/events.
- New-target publish is one same-filesystem rename after file/directory sync.
- Replace mode uses a synced transaction journal, rollback sibling, target publish, re-preflight,
  parent sync, and explicit interrupted-transaction recovery.
- Serve detects an unresolved journal and fails closed before listener startup.
- No boolean combination or mtime-based recovery chooses a winner.

## Logging And Secret Decisions

- Product: operation start/result, operation/archive id, counts, duration, stable error only.
- Field Debug: bounded state/component/rejection reason; enabled only by bootstrap log mode.
- Development/Test: state transition and fake call order; production default disabled.
- Never log full paths, config body, domain lists, PEM, verifier, passphrase, cookie, or CSRF.
- The current Admin verifier is password-equivalent and must be encrypted and redacted.

## Baseline And Security Evidence

- Workspace MSRV: Rust 1.80; local verification compiler: Rust 1.94.0.
- `cargo test --workspace -- --test-threads=1`: 508 passed.
- `cargo fmt --all -- --check`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `./scripts/check_architecture.sh`: passed.
- `./scripts/check_release_docs.sh`: passed.
- RustSec advisory database snapshot:
  `9f3e138091487e69144f536d36976e427a7a3307`.

The local environment has no Rust 1.80 toolchain manager and no `cargo-audit` command. Each task
that adds a selected dependency must still compile against the declared workspace MSRV in CI or a
dedicated toolchain and run an advisory scan before Phase 008 completion.

## Consequences

- Backup implementation cannot begin by recursively copying the data directory.
- Task 002 must repair config authority and secret permissions first.
- Security-sensitive dependencies stay in adapter/bin crates and out of core/domain/application.
- Replace restore is more work than two renames, but it has a defined crash-recovery contract.
- The beta status of the age library remains a tracked replacement/compatibility risk.
