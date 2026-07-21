# Encrypted Backup And Offline Restore

Sponzey Edge supports local, encrypted, offline backup and restore of the
canonical config revision store, referenced certificate material, and the
initialized Admin password verifier. Schema v2 includes every managed trust
bundle and trust reference used by retained config revisions. Schema v3 also
includes the verified durable audit ledger segments. Runtime sessions, CSRF tokens, health,
drain, metrics, and in-flight connections are not backup artifacts.

## Safety Model

- Stop the serving process before `backup create`, `backup restore --replace`,
  or `backup restore-recover` so the exclusive data-directory lock can be held.
- Supply the passphrase through an owner-only regular file. Do not pass it in
  argv or an environment variable.
- Copy the encrypted archive off-host, then run `backup verify` on the copied
  bytes before declaring the backup usable.
- New-target restore publishes only after archive authentication, bounded
  extraction, artifact digest checks, config/certificate/secret validation,
  audit chain verification, runtime/trust preflight, and filesystem sync.
- New archives use schema v3. Verification and restore accept legacy schema v1
  and v2. Schema v1 has no trust-bundle artifacts; schema v1/v2 have no audit
  segment artifacts.
- Audit artifacts are an ordered contiguous set of at most 32 private segment
  files. Each segment is at most 4 MiB and the set is at most 128 MiB. Unknown,
  symlinked, hard-linked, non-private, corrupt, incomplete, or unresolved ledger
  state fails before target publication.
- `backup create` and `backup verify` are read-only for the audit ledger. They do
  not append an audit event, so the inventory and ledger head remain stable while
  the exclusive data-directory lock is held.
- Successful publication appends one `maintenance.restore_imported` provenance
  record to the restored ledger. The record links the restore operation ID and
  archive ID without exposing archive paths, hashes, or secrets. Recovery appends
  it only when an interrupted stage publication is completed, not when a restore
  is aborted or the old target is rolled back.
- A provenance append failure never rolls back an already verified published
  target. The operation reports an audit error as committed-but-audit-degraded;
  replace recovery keeps its transaction journal until provenance succeeds.
- Existing-target replace uses an owner-only durable journal and sibling
  rollback directory. Never remove those paths manually after an interruption.

The command syntax and replace/recovery examples are in `docs/deployment.md`.

## Recovery Decision Table

| Observation | Action | Do not do |
| --- | --- | --- |
| Data-directory lock is busy | Stop the serving owner and retry | Delete the lock file to bypass ownership |
| No journal, target startup succeeds | Continue normal startup | Re-import a stale seed config |
| Journal exists | Run `backup restore-recover` with its exact operation id | Delete stage or rollback manually |
| Recovery reports ambiguous state | Preserve target, stage, rollback, and journal for analysis | Pick the newest path by mtime |
| Wrong passphrase or tamper error | Check archive custody and passphrase source | Request raw cryptographic details |
| Audit chain or reconciliation error | Preserve source/archive/stage and run `audit verify` against the authoritative data directory | Delete a segment or force restore publication |
| Restored TLS trust/SNI fails | Check fullchain order, Root trust, SAN, and clock | Disable certificate validation |

## Private PKI Drill

The automated drills create private server and client PKIs, then perform:

```text
canonical revision + certificate + Admin verifier
  -> trusted source HTTPS
  -> encrypted backup
  -> authenticated verify
  -> wrong-passphrase target-preservation check
  -> fresh-target restore
  -> authoritative repository startup
  -> old-session rejection and new Admin login
  -> untrusted-client rejection
  -> trusted-SNI HTTPS forwarding

schema v2 canonical revision + server/client Root bundles
  -> encrypted backup and authenticated verify
  -> fresh-target restore and authoritative startup
  -> unauthenticated client rejection at inbound mTLS
  -> trusted client acceptance
  -> restored Root/SNI authenticated upstream HTTPS forwarding

schema v3 durable audit ledger
  -> source mutation and verified ledger head
  -> encrypted offline backup without changing that head
  -> fresh-target restore with pre-publication chain verification
  -> journal-linked restore provenance append
  -> old record query and next-sequence append
```

Run the focused drill with:

```bash
cargo test -p edge-proxy private_pki_backup_restore_restarts_admin_and_trusted_https \
  -- --test-threads=1
cargo test -p edge-proxy phase009_backup_v2_restores_bidirectional_private_tls_trust \
  -- --test-threads=1
cargo test -p edge-adapters phase010_backup_v3_restores_audit_history_and_continues_sequence
```

The server store and archive contain the leaf-first fullchain and leaf private
key only. Test CA private keys are not product artifacts. See
`docs/private-pki-testing.md` for the authentication matrix.

## Limitations

The current implementation is local and offline. It does not provide an Admin
backup endpoint, online/hot restore, remote object storage, scheduling, public
CA issuance, optional/client-identity authorization mTLS, or automatic session
recovery. Required inbound mTLS is supported. Replace durability depends on same-filesystem atomic rename and
directory fsync semantics.
