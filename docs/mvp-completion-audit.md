# MVP Completion Audit

Audit date: 2026-07-21  
Status: Phase 011 implementation and its 2026-07-20 cross-platform checkpoint are complete. External Let's Encrypt remains explicitly deferred.

This document records completion evidence for archived Phase plans through
Phase 009 and the completed Phase 010/011 task loops.
Phase 010 adds durable typed audit persistence/search and schema v3 recovery;
its accepted release evidence must be generated from the current source identity.
MVP release approval is based on the automatic evidence collector and
`scripts/check_release_evidence.sh`. External Let's Encrypt staging is no
longer part of the MVP completion rule; it remains documented for Post-MVP
implementation and validation.

Historical checkpoint: Phase 008 implementation and automatic release gates verified.

## Phase 011 Completion Audit

Phase 011 adds a typed process-wide connection/payload resource policy, exact owner accounting,
restart-required desired/active separation, bounded resource observability, cross-platform RSS
measurement, fixed workload profiles, a two-hour soak, and one authorized macOS deep diagnostic.
The measurement harness remains outside product domain/application/core dependencies.

| Area | Accepted evidence | Result |
| --- | --- | --- |
| architecture | layered dependency checks, boundary-only process/filesystem/network access, bootstrap-only environment | passed |
| resource policy | bounded `max_connections`, process-wide payload ledger, exact reserve/transfer/release and typed failures | passed |
| protocol cleanup | HTTP/HTTPS/mTLS/WebSocket close, timeout, reset and pressure paths end at connection/payload 0 | passed |
| macOS arm64 | full profile 12/12, 7,200-second soak, zero correctness/cleanup failures | passed |
| native Linux x86_64 | full profile jobs 10/10, scenarios 12/12, ready=true, blocker 0 | passed |
| deep diagnostic | macOS `/usr/bin/leaks`, 1,000 successful requests, definite leak 0/0 | passed |
| final binding | exact nine files, current checkpoint source/digests and independent marker validation | passed |
| quality and docs | `./scripts/check.sh` and `./scripts/check_release_docs.sh` exit 0 | passed |

The accepted checkpoint source identity is
`source-tree-sha256:2c2bcbf580ed60fe18c330340236ecccf0936d7e5a2d18822e1c36f0fb970862`.
The final binding digest is
`78d453e0568c069e68c5e563535f2f2497ab42b80d765845a5568bacb7cbcf09`.
This proves the declared resource envelope for the exact reference workloads and platforms. It is
not a mathematical proof of zero leaks for every allocator, kernel-memory accounting, or arbitrary
production traffic. Later tracked changes require fresh source-bound evidence before release.

## Phase 010 Completion Audit

Phase 010 implements one verified process-wide file ledger, durable intent/effect
ordering, restart reconciliation, bounded security observations, authenticated
query/Admin UI, and backup schema v3 restore provenance. The data plane remains
independent and read-only recovery remains available while persistent mutation
admission is degraded.

| Area | Automatic evidence | Result |
| --- | --- | --- |
| architecture | domain/application/core isolation, bootstrap-only env, no production memory sink | passed |
| durability | sync-before-ack, reopen, corruption/trailing recovery, rotation/retention bounds | passed |
| mutation safety | intent before effect, exact terminal, degraded fail-closed and restart reconciliation | passed |
| API/UI | authenticated max-100 exact filters, opaque cursor, safe projection, responsive API-only viewer | passed |
| recovery | schema v1/v2 compatibility, schema v3 preflight, publication provenance and next append | passed |
| security | owner-only/no-follow/hard-link checks and no secret/raw config/path/hash projection | passed |
| quality | fmt, clippy warnings-as-errors, full workspace and focused phase tests | passed |
| evidence | Phase 010 marker and focused snippets required by collector/validator | passed |

The local chain provides corruption and local integrity detection, not hostile-admin
tamper proofing or non-repudiation. Export, remote signing/attestation, RBAC and
long-term external retention remain deferred.

Accepted evidence is `artifacts/release-evidence/phase010-20260716-final-r2`.
Its build identity is recorded in `environment.txt`; the documentation, check
and smoke gate exit codes are all `0`, and an independent
`scripts/check_release_evidence.sh` run accepts the directory.

## Phase 009 Completion Audit

Phase 009 adds immutable managed Root bundles, schema v2 TLS policy, strict
private upstream HTTPS, required inbound mTLS, generation-atomic activation,
trust-aware schema v2 backup/restore, and Admin UI trust management.

| Area | Automatic evidence | Result |
| --- | --- | --- |
| architecture/config | domain/application isolation, bootstrap-only env, schema v1/v2 tests | passed |
| managed trust | CA-only validator, create-only file store, API/TCP/UI metadata-only CRUD | passed |
| upstream TLS | explicit Root/SNI/HTTP Host, health/WebSocket/backpressure/private-PKI E2E | passed |
| inbound mTLS | trusted client success and no-cert/wrong-root/EKU/validity rejection before HTTP | passed |
| atomic runtime | snapshot/server/client/health generation success, rejection, compensation | passed |
| recovery | schema v1 compatibility and schema v2 fresh restore bidirectional TLS E2E | passed |
| UI safety | API-only workflow, transient PEM clear, no browser storage/material rendering | passed |
| observability | 60-second bounded-key TLS Product sampler and full-queue nonblocking core path | passed |
| deterministic time | injected rustls time rejects pre-validity and accepts in-validity handshake | passed |
| registry identity | unique bind server registry and `(ServiceId, UpstreamId)` client registry reject collisions | passed |
| evidence | Phase 009 marker and nine focused snippets required by collector/validator | passed |

Explicit exclusions are external Let's Encrypt, optional identity-based access,
outbound client-certificate mTLS, revocation, TLS passthrough, remote backup, and
ephemeral session/health restoration. These exclusions are not represented as
implemented capabilities.

The accepted Phase 009 evidence is
`artifacts/release-evidence/phase009-20260715-final-r2`: all three gate exit
codes are `0`, and `scripts/check_release_evidence.sh` independently passed.
The earlier `phase009-20260715-final` directory predates Task 021 and remains a
historical diagnostic rather than current-source release evidence.

## Phase 008 Completion Audit

Phase 008 adds encrypted allowlisted backup, authenticated bounded verify,
fresh-target restore, durable existing-target replace/rollback/recovery, and a
private Root→Intermediate→leaf disaster-recovery E2E. Runtime session, CSRF,
health, drain, metrics, and connection state remain memory-only and are not
restored.

| Area | Automatic evidence | Result |
| --- | --- | --- |
| architecture/config authority | architecture gate; repository-current startup and bootstrap-only env/config tests | passed |
| encrypted create/verify | backup reducer, authenticated age archive, bounds/tamper/wrong-passphrase tests | passed |
| restore/replace/recovery | preflight ordering, durable journal, crash-state rollback, ambiguous non-destructive recovery tests | passed |
| private PKI authentication | Root-only trust, complete chain, SNI, validity, key/order negative matrix | passed |
| recovery E2E | source/restored revision and certificate identity, old-session rejection, new login, trusted HTTPS test | passed |
| secret and permission safety | `0600` key/verifier, structured-log negative assertions, evidence scanner | passed |
| quality gates | fmt, clippy `-D warnings`, 551 serial workspace tests, architecture/docs checks | passed |
| release evidence contract | Phase 008 marker and four focused snippets required by collector/validator | passed |

Explicit exclusions are external Let's Encrypt, DNS-01 provider integration,
online/hot restore, remote storage/scheduling, and automatic restoration of
ephemeral runtime state. mTLS, upstream TLS, wildcard/SNI selection, and TLS
passthrough remain unimplemented, but are planned TLS work because private PKI
fixtures can verify them without public infrastructure. Same-filesystem atomic
rename and directory fsync are required for replace durability; unsupported
platforms must fail closed.

The accepted final evidence is
`artifacts/release-evidence/phase008-20260715-final-r6`: all three gate exit
codes are `0`, and `scripts/check_release_evidence.sh` independently passed.
The earlier `final`, `final-r2`, `final-r3`, and `final-r4` directories are
failed diagnostics and are not release evidence.

## Phase 007 Completion Audit

Phase 007 adds a typed 15-family metric contract, nonblocking publisher port,
bounded single-writer registry, immutable snapshots, loopback-only Prometheus
exposition, authenticated Admin JSON summary, and compact Admin UI status.
Metrics remain memory-only and cannot mutate or block the mio data plane.

| Area | Automatic evidence | Result |
| --- | --- | --- |
| architecture and publication | publisher/reader ports, architecture environment/dependency scan | passed |
| typed aggregation and bounds | descriptor contract, registry partition/4 MiB, histogram and generation tests | passed |
| listener security and lifecycle | exact GET, loopback, oversized, concurrent, disabled, shutdown tests | passed |
| Admin API and UI | auth/query/500-bound summary tests and `smoke_admin_web.sh` | passed |
| producer completeness | core request/connection/failure tests, health availability/transition tests, startup identity/certificate tests | passed |
| quality gates | fmt, clippy `-D warnings`, 508 serial workspace tests, architecture/docs checks | passed |

Explicit exclusions are remote metrics exposure, retention/history/charts,
Prometheus/Grafana bundling, and cross-container sidecar scraping of a loopback
listener. The runtime 16,384-series and 4 MiB admission limits are enforced;
pre-apply config cardinality estimation remains a documented follow-up because
the accepted config may not be the only source of cumulative metric series.

## Phase 006 Completion Audit

Phase 006 adds conservative one-shot retry, passive transport-failure ejection,
effective active/passive/administrative eligibility, generation-fenced graceful
drain, additive Admin API/Web policy controls, and bounded transition
observability. Runtime health, attempt, and drain state remains memory-only and
is exposed through typed ports. Force drain and remote/retained telemetry
external Let's Encrypt validation are not part of this phase.

| DoD | Automatic evidence | Result |
| --- | --- | --- |
| 1-5 failure taxonomy, bounded observations, stale fencing, threshold/recovery | domain passive tests; `current_transport_observations_update_passive_state`; health controller tests | passed |
| 6-10 disabled default and safe one-shot retry guards | retry decision tests; safe GET integration; POST denial integration; parser/protocol regressions | passed |
| 11-17 attempt accounting, replay limits, timeout/cleanup/cursor/generation rules | domain policy bounds; core attempt-state and retry-selector tests; workspace regressions | passed |
| 18-24 drain, desired/runtime separation, connection preservation, fencing/reset | drain lifecycle tests; generation selector tests; WebSocket regression; runtime status port tests | passed |
| 25-28 config/Admin/UI/headless contracts | config round-trip/diff/apply tests; canonical/legacy Admin tests; static Admin smoke; headless smoke | passed |
| 29 logging modes and secret safety | failure observability exact-field tests; evidence secret scanner; observability docs gate | passed |
| 30-33 boundaries, test doubles, non-panic errors | architecture fitness gate; application fake-port tests; typed error regressions | passed |
| 34-36 HTTP/HTTPS, Phase 005, parser/security regression | self-signed HTTPS, round-robin/health/WebSocket, CL/TE/header/limit tests | passed |
| 37 quality gates | fmt, clippy warnings-as-errors, workspace tests, architecture/docs checks | passed |
| 38 deployment smoke | headless, static Admin TCP, and Docker smoke passed; live browser is explicitly excluded and opt-in via `SPONZEY_REQUIRE_LIVE_BROWSER=true` | passed with documented exclusion |
| 39 Phase 006 evidence contract | collector and validator require the `phase 006 failure-aware routing smoke passed` marker and focused snippets | passed |
| 40 Let's Encrypt exclusion | collector summary and this audit identify it as deferred Post-MVP work | passed |

The focused Phase 006 evidence names are fixed in `scripts/smoke_mvp.sh`,
`scripts/collect_release_evidence.sh`, and `scripts/check_release_evidence.sh`.
The checker rejects a missing focused snippet, a missing Phase 006 marker,
unknown paths, symlinks, command overrides, and PEM/Authorization/Cookie/CSRF
material. The accepted evidence directory is
`artifacts/release-evidence/phase006-20260714-final-r3`; it was collected with
no command overrides and independently passed `scripts/check_release_evidence.sh`.
The three recorded gate exit codes are all `0`. The earlier `final` and
`final-r2` directories are rejected diagnostics and are not release evidence.

## Phase 005 Completion Audit

The accepted final evidence directory for the current source is
`artifacts/release-evidence/phase005-20260713-final`. It is collected without
test command overrides after this document is finalized and must pass
`scripts/check_release_evidence.sh`. Earlier `phase005-20260713` evidence is a
rejected diagnostic run; `phase005-20260713-r2` is a successful pre-final run
whose source identity predates this audit update.

Phase 005 adds deterministic round-robin, active HTTP health checks, generation-
fenced availability activation, Admin pool/status controls, bounded health
observability, and operations documentation. External Let's Encrypt staging and
production are not part of this completion claim.

| Plan DoD | Evidence | Status |
| --- | --- | --- |
| 1. Legacy single upstream | `legacy_single_upstream_normalizes_to_stable_primary_id`, legacy Admin JSON test | passed |
| 2. Stable multi-upstream config | `service_policy_config_parses_and_renders_losslessly`, duplicate/name validation tests | passed |
| 3. HTTP/HTTPS round-robin | `snapshot_mio_runtime_round_robins_new_requests_across_service_upstreams`, HTTPS equivalent | passed |
| 4. WebSocket selects eligible target | `snapshot_mio_runtime_keeps_selected_websocket_during_health_change` | passed |
| 5. Probe outside event loop | bounded adapter worker tests and `scripts/check_architecture.sh` | passed |
| 6. Health states/thresholds | domain transition and boundary tests | passed |
| 7. Exclusion and recovery | runtime selector generation test and health 503/recovery integration | passed |
| 8. All unhealthy returns 503 | `snapshot_mio_runtime_publishes_health_503_and_recovery_through_command_queue` | passed |
| 9. Existing connection retained | WebSocket health-change integration keeps ping/pong while new request gets 503 | passed |
| 10. Old completion rejected | stale result, reconciliation, and monotonic activation tests | passed |
| 11. Atomic config/TLS/health failure | unified activation and rejected activation preservation tests | passed |
| 12. Bounded resources | worker capacity, response limit, one-in-flight, and queue saturation tests | passed |
| 13. Three-mode logs/metrics | exact Product fields, bounded metrics, 60-second/8,192 Field sampler tests | passed |
| 14. Legacy/canonical Admin API | legacy JSON and canonical pool/health lifecycle tests | passed |
| 15. Admin UI pool/health | static contract and live browser two-upstream operational-health smoke | passed |
| 16. Inner layers have no external I/O | architecture fitness gate | passed |
| 17. fmt/clippy/workspace/architecture | `scripts/check.sh` | passed |
| 18. protocol/Admin/headless/Docker | `scripts/smoke_mvp.sh` | passed |
| 19. Fresh evidence | final collector plus `scripts/check_release_evidence.sh` | passed after final collection |
| 20. Current docs/deferred scope | release docs checker and stale phrase scan | passed |
| 21. Let's Encrypt deferred | collector summary and ACME documentation | passed |
| 22. Explicit use-case contracts/test doubles | application tests use port fakes; architecture gate rejects concrete I/O | passed |
| 23. Boundary-only external access | dependency/source architecture scans | passed |
| 24. No health/cursor files | runtime state is in memory; data-layout and source inventory checks | passed |
| 25. Bootstrap-only environment | architecture environment-access scan | passed |
| 26. Rollback gets new generation | `mirrored_apply_uses_monotonic_atomic_health_activation` and reconciliation tests | passed |
| 27. Failure/cancel/terminal lifecycle | supervisor shutdown, worker cancellation/join, rejected publish tests | passed |
| 28. Typed non-panic errors | config/probe/runtime/Admin stable error tests | passed |

The automatic evidence checker also rejects a missing Phase 005 marker, stale
or unknown evidence paths, symlinks, command overrides, and secret-bearing PEM,
Authorization, Cookie, or CSRF values.

## Environment

```text
os: Darwin Leonards-MacBook-Pro.local 25.5.0 arm64
docker: Docker version 29.1.3, build f52814d
docker_compose: Docker Compose version v5.0.1
build_or_commit: see environment.txt in the accepted collector output; it is a git commit, external build id, or source-tree-sha256:<digest>
```

`.tasks/` git evidence:

```text
git ls-files .tasks
```

Expected result: no output.

```text
git check-ignore -v .tasks/phase007/plan.md
.gitignore:69:.tasks/	.tasks/phase007/plan.md
```

## Automatic Gate Evidence

Commands verified:

```bash
./scripts/check_release_docs.sh
./scripts/check.sh
./scripts/smoke_mvp.sh
```

Latest collector verification:

```text
command: RELEASE_EVIDENCE_DIR=artifacts/release-evidence/phase005-20260713-final ./scripts/collect_release_evidence.sh
release_id: phase005-20260713-final
collector_date: 2026-07-13
exact_utc_started_at: see environment.txt in the accepted collector output
build_or_commit: see environment.txt in the accepted collector output
check_release_docs_exit_code: 0
check_exit_code: 0
smoke_mvp_exit_code: 0
check_release_evidence: release evidence check passed
test_command_overrides_used: false
test_command_overrides_allowed: false
```
MVP release evidence requires a concrete `build_or_commit` value in automatic
evidence. When git metadata is unavailable, the automatic
collector records a `source-tree-sha256:<digest>` identity derived from
release-relevant source files. Post-MVP ACME staging evidence should copy that
same value through `SPONZEY_STAGING_BUILD_OR_COMMIT`, or use
`scripts/init_acme_staging_from_release_evidence.sh` to copy `release_id` and
`build_or_commit` from validated automatic evidence.

The accepted summary must not include override `true` values or smoke-only
release evidence warnings. Its Automatic Gates table must report exit code `0`
for `./scripts/check_release_docs.sh`, `./scripts/check.sh`, and
`./scripts/smoke_mvp.sh`, matching `status.env`. It must also include
`Build/Commit` matching automatic `environment.txt` `build_or_commit`.

For future release builds, `scripts/collect_release_evidence.sh` can run these
automatic gates and write transcripts plus `.tasks/` git evidence under
`artifacts/release-evidence/`. Validate the generated directory with
`scripts/check_release_evidence.sh` before using it as release evidence. The
automatic `environment.txt` must include `utc_started_at` in
`YYYYMMDDTHHMMSSZ` format. The automatic evidence directory tree must contain no symlinks.
The collector refuses pre-existing symlink required output files and any other symlink inside
the evidence tree before writing. The collector and validator also reject any
unknown or stale path outside the collector's known automatic output filenames.
Required snippets are matched from the current gate transcripts only,
with source-specific provenance for `check_release_docs.log`, `check.log`, and
`smoke_mvp.log`. If `snippet-check.txt` claims a required snippet that is absent
from its expected current gate transcript, `scripts/check_release_evidence.sh`
rejects the evidence. Any `missing in <log>` line in `snippet-check.txt` also
rejects the evidence. If the release artifact has an external build id, pass
`SPONZEY_EVIDENCE_BUILD_OR_COMMIT=build-id` to the collector. Required
automatic `environment.txt` and `status.env` keys must appear exactly once.
Post-MVP ACME evidence can still use the same `RELEASE_ID` basename and the
ACME evidence-bound initializer, but that flow is outside MVP completion.

Observed required snippets:

```text
release docs check passed
architecture check passed
acme staging evidence smoke passed
core headless smoke passed
admin web smoke passed
admin web live browser smoke deferred by release policy
test admin_http::tests::admin_http_listener_serves_static_admin_web_assets_over_tcp ... ok
test tests::http_status_route_returns_current_revision_json ... ok
test admin_http::tests::admin_http_listener_serves_status_over_tcp ... ok
test tests::http_health_route_returns_minimal_operational_json ... ok
test admin_http::tests::admin_http_listener_serves_health_over_tcp ... ok
test tests::service_policy_config_parses_and_renders_losslessly ... ok
test tests::round_robin_selection_skips_unhealthy_and_accepts_unknown ... ok
test tests::snapshot_mio_runtime_round_robins_new_requests_across_service_upstreams ... ok
test tests::snapshot_mio_runtime_round_robins_https_requests_across_service_upstreams ... ok
test tests::snapshot_mio_runtime_publishes_health_503_and_recovery_through_command_queue ... ok
test tests::snapshot_mio_runtime_keeps_selected_websocket_during_health_change ... ok
test health::tests::stale_duplicate_and_unknown_probe_results_are_ignored_without_state_change ... ok
test health::tests::reconciliation_preserves_matching_health_counter_and_resets_changed_endpoint ... ok
test tests::upstream_health_route_requires_session_and_returns_ordered_safe_status_items ... ok
test admin_http::tests::admin_http_listener_uses_injected_health_status_reader_over_tcp ... ok
test health::tests::health_transition_observability_has_exact_safe_product_fields_and_bounded_labels ... ok
test health::tests::field_debug_health_sampler_enforces_sixty_second_boundary_and_capacity ... ok
test health_runtime::tests::saturated_health_observability_queues_do_not_stop_state_progression ... ok
test tests::unified_mio_tls_apply_activates_config_health_and_tls_together ... ok
test tests::rejected_atomic_health_activation_preserves_current_runtime_and_mirror ... ok
phase 005 multi-upstream health smoke passed
test tests::http_login_before_setup_returns_setup_required ... ok
test tests::http_login_success_emits_secure_cookie_and_csrf_json ... ok
test tests::http_logout_requires_csrf_and_invalidates_session ... ok
test tests::http_mutation_without_csrf_returns_csrf_required_error ... ok
test admin_http::tests::admin_http_listener_rejects_mutation_without_session_over_tcp ... ok
test admin_http::tests::admin_http_listener_logs_in_and_logs_out_over_tcp ... ok
test admin_http::tests::admin_http_listener_sets_up_first_password_over_tcp ... ok
test tests::parses_minimal_toml_config ... ok
test bootstrap::tests::ensures_runtime_data_layout ... ok
test tests::config_schema_roundtrips_route_certificate_ref ... ok
test tests::snapshot_mio_runtime_routes_by_host_to_different_upstreams ... ok
test tests::path_prefix_match_succeeds ... ok
test tests::more_specific_path_prefix_wins_with_same_priority ... ok
test tests::snapshot_mio_runtime_maps_backend_reset_to_502 ... ok
test tests::snapshot_mio_runtime_maps_upstream_read_timeout_to_504 ... ok
test tests::snapshot_mio_runtime_maps_upstream_connect_timeout_to_504 ... ok
test tests::snapshot_mio_runtime_maps_slow_client_header_to_408 ... ok
test tests::snapshot_mio_runtime_passes_chunked_response_without_upstream_close ... ok
test tests::snapshot_mio_runtime_pauses_upstream_reads_when_client_backpressures ... ok
test tests::snapshot_mio_runtime_tunnels_websocket_upgrade_after_101_response ... ok
test tests::unified_mio_https_self_signed_proxy_forwards_without_connection_thread ... ok
test tests::https_listener_selects_certificate_by_sni_among_loaded_configs ... ok
test tests::tls_handshake_machine_selects_certificate_and_establishes ... ok
test tests::tls_handshake_machine_unknown_sni_fails_without_panic ... ok
test tests::tls_handshake_interest_follows_current_state ... ok
test tests::tls_handshake_events_drive_state_transitions ... ok
test tests::tls_handshake_event_timeout_sets_failed_state ... ok
test tests::tls_handshake_machine_timeout_is_explicit_failure ... ok
test tests::rustls_tls_session_completes_with_fragmented_client_hello ... ok
test tests::startup_preloads_https_tls_configs_before_runtime_start ... ok
test tests::startup_missing_https_certificate_fails_before_runtime_start ... ok
test tests::install_certificate_command_replaces_tls_runtime_snapshot_after_ack ... ok
test tests::install_certificate_missing_ref_rejects_without_core_command ... ok
test tests::install_certificate_core_rejection_preserves_tls_runtime_snapshot ... ok
test tests::install_certificate_rejects_sni_domain_conflict_without_core_command ... ok
test tests::unified_mio_https_hot_install_uses_new_certificate_for_new_connection ... ok
test tests::https_proxy_connection_closes_idle_tls_handshake_on_timeout ... ok
test tests::fake_acme_client_issues_staging_certificate ... ok
test tests::fake_acme_client_presents_http01_challenge_before_issuing ... ok
test tests::letsencrypt_http01_client_rejects_challengeless_issue ... ok
test tests::letsencrypt_staging_client_requires_terms_before_network_io ... ok
test tests::letsencrypt_staging_client_rejects_production_before_network_io ... ok
test bootstrap::tests::acme_client_mode_accepts_explicit_letsencrypt_staging ... ok
test bootstrap::tests::acme_client_mode_defaults_to_fake_for_automatic_smoke ... ok
test bootstrap::tests::acme_client_mode_rejects_unknown_values ... ok
test tests::production_acme_requires_opt_in ... ok
test tests::http01_token_store_matches_exact_token ... ok
test tests::http01_without_http_listener_fails ... ok
test tests::acme_challenge_path_bypasses_redirect_route_action ... ok
test tests::snapshot_mio_runtime_serves_http01_challenge_from_token_store ... ok
test tests::certificate_issue_with_http01_registers_probes_and_clears_token ... ok
test tests::certificate_issue_with_http01_clears_token_when_probe_fails ... ok
test tests::certificate_issue_with_http01_clears_token_when_acme_fails ... ok
test admin_http::tests::admin_http_listener_issues_certificate_after_runtime_http01_probe ... ok
test admin_http::tests::admin_http_listener_issues_certificate_over_tcp ... ok
test admin_http::tests::admin_http_listener_issues_certificate_to_file_store_over_tcp ... ok
test tests::http_certificate_renew_uses_existing_domains_and_sends_install_command ... ok
test admin_http::tests::admin_http_listener_renews_certificate_over_tcp ... ok
test tests::certificate_renew_missing_certificate_does_not_call_acme_or_core ... ok
test tests::certificate_renewal_is_due_inside_window ... ok
test tests::certificate_renewal_is_skipped_outside_window ... ok
test tests::certificate_renewal_retryable_failure_sets_next_retry ... ok
test tests::certificate_renewal_fatal_failure_has_no_retry ... ok
test tests::certificate_renewal_retryable_failure_stops_at_max_attempts ... ok
test admin_http::tests::admin_http_listener_records_certificate_issue_product_log_over_tcp ... ok
test admin_http::tests::admin_http_listener_records_certificate_issue_failure_product_log_over_tcp ... ok
test admin_http::tests::admin_http_listener_creates_proxy_host_through_lifecycle_over_tcp ... ok
test admin_http::tests::admin_http_listener_lists_and_gets_proxy_hosts_over_tcp ... ok
test admin_http::tests::admin_http_listener_updates_proxy_host_through_lifecycle_over_tcp ... ok
test admin_http::tests::admin_http_listener_deletes_proxy_host_through_lifecycle_over_tcp ... ok
test tests::http_config_get_requires_session ... ok
test tests::http_config_get_returns_rendered_current_config ... ok
test tests::http_config_validate_accepts_valid_raw_config_without_csrf ... ok
test admin_http::tests::admin_http_listener_gets_and_validates_config_over_tcp ... ok
test tests::http_config_diff_returns_route_and_upstream_changes ... ok
test admin_http::tests::admin_http_listener_diffs_and_applies_config_over_tcp ... ok
test tests::http_config_apply_goes_through_lifecycle_and_core_command ... ok
test tests::http_config_apply_invalid_candidate_does_not_send_command ... ok
test tests::http_config_rollback_goes_through_lifecycle_and_core_command ... ok
test admin_http::tests::admin_http_listener_rolls_back_config_through_lifecycle_over_tcp ... ok
test tests::config_lifecycle_apply_with_core_ack_failure_keeps_current_revision ... ok
test tests::config_lifecycle_listener_change_commits_restart_required_revision_without_hot_command ... ok
test daemon_config_lifecycle_applies_and_rolls_back_through_core_command_boundary ... ok
test daemon_config_lifecycle_runtime_rejection_preserves_current_revision ... ok
test tests::startup_imports_valid_primary_config_into_file_revision_store ... ok
test tests::startup_invalid_primary_config_does_not_import_revision ... ok
test tests::snapshot_mio_runtime_rollback_apply_preserves_previous_route ... ok
test tests::snapshot_runtime_redirect_preserves_host_authority ... ok
test tests::snapshot_http_handler_accepts_generic_read_write_stream ... ok
test tests::snapshot_http_scheme_aware_stream_sets_forwarded_proto ... ok
test tests::snapshot_mio_runtime_emits_access_log_without_blocking_runtime ... ok
test tests::snapshot_mio_runtime_counts_full_log_queue_drops_without_blocking_runtime ... ok
test tests::snapshot_mio_runtime_emits_error_log_for_upstream_timeout_without_blocking_runtime ... ok
test tests::snapshot_mio_runtime_emits_request_and_active_connection_metrics_without_blocking_runtime ... ok
test admin_http::tests::admin_http_listener_serves_access_log_received_from_runtime_queue ... ok
test admin_http::tests::admin_http_listener_serves_error_log_received_from_runtime_queue ... ok
test tests::http_access_logs_require_session_and_omit_raw_path ... ok
test tests::http_error_logs_return_recent_errors ... ok
test admin_http::tests::admin_http_listener_serves_recent_logs_over_tcp ... ok
test admin_http::tests::admin_http_listener_serves_certificates_over_tcp ... ok
test tests::product_access_log_excludes_sensitive_request_material_and_includes_revision ... ok
test tests::process_start_product_log_records_bootstrap_fields_without_secret_values ... ok
test tests::certificate_expiry_metric_omits_domain_and_private_key ... ok
test tests::http_certificate_list_masks_private_keys_and_marks_expiry ... ok
test tests::file_certificate_store_writes_private_key_owner_only ... ok
test tests::rustls_server_config_loader_rejects_invalid_private_key_without_panic ... ok
docker compose smoke passed
mvp smoke passed
```

The `edge-proxy` bound/unit test count observed in the Phase 005 full gate is
66 passed, 0 failed. The workspace total is 457 tests after the WebSocket
health-change integration fixture was added.

Phase 004 also verified the unified mio HTTP/HTTPS data plane, atomic config/TLS
factory activation, TLS WebSocket tunneling, malformed TLS connection isolation,
and Docker Compose deployment. The Docker image uses Rust 1.94, initializes the
runtime data volume with `edge` ownership, and excludes local build artifacts
from the build context.

## Definition Of Done Audit

| Requirement | Evidence | Status |
| --- | --- | --- |
| `cargo fmt --check` | included in `./scripts/check.sh` and `./scripts/smoke_mvp.sh` | passed |
| `cargo clippy --workspace --all-targets` | included in `./scripts/check.sh` | passed |
| `cargo test --workspace` | included in `./scripts/check.sh` and `./scripts/smoke_mvp.sh` | passed |
| architecture fitness | `./scripts/check_architecture.sh`, `architecture check passed` | passed |
| release docs gate | `./scripts/check_release_docs.sh`, `release docs check passed` | passed |
| core headless operation | `./scripts/smoke_core_headless.sh`, `core headless smoke passed` | passed |
| Admin API status, health, and static UI assets | `http_status_route_returns_current_revision_json`, `admin_http_listener_serves_status_over_tcp`, `http_health_route_returns_minimal_operational_json`, `admin_http_listener_serves_health_over_tcp`, `admin_http_listener_serves_static_admin_web_assets_over_tcp` | passed |
| Admin API setup/login/session/CSRF | `http_login_success_emits_secure_cookie_and_csrf_json`, `http_logout_requires_csrf_and_invalidates_session`, `http_mutation_without_csrf_returns_csrf_required_error`, `admin_http_listener_rejects_mutation_without_session_over_tcp`, `admin_http_listener_logs_in_and_logs_out_over_tcp`, `admin_http_listener_sets_up_first_password_over_tcp` | passed |
| HTTP Host/path routing | `snapshot_mio_runtime_routes_by_host_to_different_upstreams`, `path_prefix_match_succeeds`, `more_specific_path_prefix_wins_with_same_priority` | passed |
| proxy failure, timeout, streaming, and backpressure correctness | `snapshot_mio_runtime_maps_backend_reset_to_502`, `snapshot_mio_runtime_maps_upstream_read_timeout_to_504`, `snapshot_mio_runtime_maps_upstream_connect_timeout_to_504`, `snapshot_mio_runtime_maps_slow_client_header_to_408`, `snapshot_mio_runtime_passes_chunked_response_without_upstream_close`, `snapshot_mio_runtime_pauses_upstream_reads_when_client_backpressures` | passed |
| WebSocket upgrade tunnel | `snapshot_mio_runtime_tunnels_websocket_upgrade_after_101_response` | passed |
| unified mio HTTPS self-signed proxy | `unified_mio_https_self_signed_proxy_forwards_without_connection_thread` | passed |
| multi-cert HTTPS SNI selection | `https_listener_selects_certificate_by_sni_among_loaded_configs` | passed |
| TLS/config boundary correctness | `config_schema_roundtrips_route_certificate_ref`, `tls_handshake_machine_selects_certificate_and_establishes`, `tls_handshake_machine_unknown_sni_fails_without_panic`, `tls_handshake_interest_follows_current_state`, `tls_handshake_events_drive_state_transitions`, `tls_handshake_event_timeout_sets_failed_state`, `tls_handshake_machine_timeout_is_explicit_failure`, `rustls_tls_session_completes_with_fragmented_client_hello`, `snapshot_mio_runtime_serves_http_and_https_from_one_poll_loop` | passed |
| startup TLS/config safety and hot certificate install | `startup_preloads_https_tls_configs_before_runtime_start`, `startup_missing_https_certificate_fails_before_runtime_start`, `install_certificate_command_replaces_tls_runtime_snapshot_after_ack`, `install_certificate_core_rejection_preserves_tls_runtime_snapshot`, `unified_mio_https_hot_install_uses_new_certificate_for_new_connection`, `https_proxy_connection_closes_idle_tls_handshake_on_timeout` | passed |
| fake ACME e2e | `fake_acme_client_issues_staging_certificate`, `fake_acme_client_presents_http01_challenge_before_issuing`, `admin_http_listener_issues_certificate_to_file_store_over_tcp` | passed |
| HTTP-01 Admin API/runtime lifecycle | `admin_http_listener_issues_certificate_after_runtime_http01_probe` | passed |
| ACME staging adapter/bootstrap safety and HTTP-01 cleanup | `letsencrypt_http01_client_rejects_challengeless_issue`, `letsencrypt_staging_client_requires_terms_before_network_io`, `letsencrypt_staging_client_rejects_production_before_network_io`, `acme_client_mode_accepts_explicit_letsencrypt_staging`, `acme_client_mode_defaults_to_fake_for_automatic_smoke`, `acme_client_mode_rejects_unknown_values`, `production_acme_requires_opt_in`, `http01_token_store_matches_exact_token`, `http01_without_http_listener_fails`, `acme_challenge_path_bypasses_redirect_route_action`, `snapshot_mio_runtime_serves_http01_challenge_from_token_store`, `certificate_issue_with_http01_registers_probes_and_clears_token`, `certificate_issue_with_http01_clears_token_when_probe_fails`, `certificate_issue_with_http01_clears_token_when_acme_fails` | passed |
| Admin API certificate issue/renew control path | `admin_http_listener_issues_certificate_over_tcp`, `admin_http_listener_issues_certificate_to_file_store_over_tcp`, `http_certificate_renew_uses_existing_domains_and_sends_install_command`, `admin_http_listener_renews_certificate_over_tcp` | passed |
| certificate renewal policy and retry/fatal classification | `certificate_renew_missing_certificate_does_not_call_acme_or_core`, `certificate_renewal_is_due_inside_window`, `certificate_renewal_is_skipped_outside_window`, `certificate_renewal_retryable_failure_sets_next_retry`, `certificate_renewal_fatal_failure_has_no_retry`, `certificate_renewal_retryable_failure_stops_at_max_attempts` | passed |
| certificate issue product log success/failure | `admin_http_listener_records_certificate_issue_product_log_over_tcp`, `admin_http_listener_records_certificate_issue_failure_product_log_over_tcp` | passed |
| HTTP to HTTPS redirect | `snapshot_runtime_redirect_preserves_host_authority` | passed |
| Admin API Proxy Host CRUD | `admin_http_listener_creates_proxy_host_through_lifecycle_over_tcp`, `admin_http_listener_lists_and_gets_proxy_hosts_over_tcp`, `admin_http_listener_updates_proxy_host_through_lifecycle_over_tcp`, `admin_http_listener_deletes_proxy_host_through_lifecycle_over_tcp` | passed |
| config lifecycle get/validate/diff/apply/rollback | `http_config_get_requires_session`, `http_config_get_returns_rendered_current_config`, `http_config_validate_accepts_valid_raw_config_without_csrf`, `admin_http_listener_gets_and_validates_config_over_tcp`, `http_config_diff_returns_route_and_upstream_changes`, `admin_http_listener_diffs_and_applies_config_over_tcp`, `http_config_apply_goes_through_lifecycle_and_core_command`, `http_config_rollback_goes_through_lifecycle_and_core_command`, `admin_http_listener_rolls_back_config_through_lifecycle_over_tcp` | passed |
| access log, recent error, certificate status API | `admin_http_listener_serves_access_log_received_from_runtime_queue`, `admin_http_listener_serves_error_log_received_from_runtime_queue`, `http_access_logs_require_session_and_omit_raw_path`, `http_error_logs_return_recent_errors`, `admin_http_listener_serves_recent_logs_over_tcp`, `admin_http_listener_serves_certificates_over_tcp` | passed |
| Admin API setup/create/apply/rollback | bound TCP Admin API tests in `edge-proxy` | passed |
| Admin Web UI real API smoke | opt-in only; excluded from Phase 006 automatic sign-off | deferred |
| Docker Compose smoke | `docker compose smoke passed` | passed |
| invalid config cannot become current | `http_config_apply_invalid_candidate_does_not_send_command` | passed |
| apply command failure preserves current revision | `config_lifecycle_apply_with_core_ack_failure_keeps_current_revision`, `daemon_config_lifecycle_runtime_rejection_preserves_current_revision` | passed |
| rollback restores previous working route | `snapshot_mio_runtime_rollback_apply_preserves_previous_route` | passed |
| runtime observability producers are nonblocking | `snapshot_mio_runtime_emits_access_log_without_blocking_runtime`, `snapshot_mio_runtime_counts_full_log_queue_drops_without_blocking_runtime`, `snapshot_mio_runtime_emits_error_log_for_upstream_timeout_without_blocking_runtime`, `snapshot_mio_runtime_emits_request_and_active_connection_metrics_without_blocking_runtime` | passed |
| product logs omit sensitive material | `product_access_log_excludes_sensitive_request_material_and_includes_revision`, `process_start_product_log_records_bootstrap_fields_without_secret_values`, `certificate_expiry_metric_omits_domain_and_private_key` | passed |
| private key masking and file permission | `http_certificate_list_masks_private_keys_and_marks_expiry`, `file_certificate_store_writes_private_key_owner_only`, `rustls_server_config_loader_rejects_invalid_private_key_without_panic` | passed |
| docs are current | `./scripts/check_release_docs.sh` | passed |
| Admin API curl runbook | `docs/admin-curl.md` and release docs gate patterns | passed |
| release evidence template | `docs/release-evidence-template.md` | passed |

## Supplemental And Deferred Status

| Gate | Current status | Evidence note |
| --- | --- | --- |
| Static Admin Web UI inspection | automatic static TCP smoke passed; live browser is opt-in | browser/viewport evidence only when explicitly required |
| Docker Compose demo | automatic Docker Compose smoke passed | separate operator result only if a reviewer requires a human walkthrough |
| Data directory layout inspection | automatic layout test passed through `test bootstrap::tests::ensures_runtime_data_layout ... ok` | separate retained data directory path only if a reviewer requires human inspection |
| Minimal config review | `examples/minimal.toml` parse smoke and docs gate passed | separate reviewer note only if a reviewer requires human inspection |
| Let's Encrypt staging | deferred to Post-MVP | not required for MVP; when resumed, use approved public test domain, initialized staging directory, `scripts/acme_staging_preflight.sh` output, challenge curl result, HTTPS curl result, stable Admin API `X-Request-Id` recorded as `metadata.env admin_api_request_id` |

## Deferred Post-MVP Gate

External Let's Encrypt staging is deferred to Post-MVP work. This deferral is a
scope decision, not an exception approval path. MVP completion does not require
`scripts/check_acme_staging_evidence.sh` or `scripts/check_mvp_release_ready.sh`
while Let's Encrypt is out of scope. When the feature resumes, external staging
evidence must be recorded with an approved public test domain and both checkers
must pass before claiming Let's Encrypt readiness.

External Let's Encrypt staging cannot be completed from local repository state
alone. The config-file startup path can wire the real staging adapter with
`SPONZEY_ACME_CLIENT=letsencrypt-staging`, but the default fake ACME adapter is
not valid external staging evidence. The Post-MVP ACME readiness gate requires
an approved public test domain, an Admin API issue response with
`source: letsencrypt_staging`, and must follow `docs/acme-staging.md`. The
certificate issue request must use a
stable `X-Request-Id`, the same value must be recorded as
`metadata.env admin_api_request_id`, the Admin API success response `request_id`
must match it, and `required-statements.txt` must include
`Admin API issue request used X-Request-Id matching metadata.env admin_api_request_id.`.
Use `scripts/init_acme_staging_evidence.sh`
only to create the required evidence layout; a custom
`SPONZEY_STAGING_EVIDENCE_DIR` basename must match
`SPONZEY_STAGING_RELEASE_ID`; symlink staging evidence directories are refused;
pre-existing required evidence files are refused before new pending files are
written unless `SPONZEY_STAGING_EVIDENCE_OVERWRITE=true` is explicit;
pre-existing symlinks inside the evidence tree are refused before pending files
are written; unknown or stale paths outside the fixed evidence filenames are
refused before pending files are written; and completed ACME staging evidence
trees must contain no symlinks and only fixed evidence filenames plus the
initializer `README.md`.
Initialized pending files are not ACME readiness evidence until the external run
replaces them and `scripts/check_acme_staging_evidence.sh` passes.

When Post-MVP ACME validation resumes,
`scripts/init_acme_staging_from_release_evidence.sh` must be preferred so the
staging evidence inherits the already validated automatic release identity. That
helper appends an `Automatic Evidence Binding` section to ACME `README.md`.
Post-MVP final readiness requires that section, verifies its
`automatic_release_evidence_dir` line matches the automatic evidence directory,
and verifies its `release_id` plus `build_or_commit` lines match ACME
`metadata.env`. Each binding key must appear exactly once in ACME `README.md`.
A trailing slash on the automatic evidence path is normalized before writing or
checking the binding. The `Automatic Evidence Binding` section itself must also
appear exactly once, and the binding keys must be recorded inside that section.
The evidence-bound initializer inherits the lower initializer overwrite policy:
with overwrite enabled, it rewrites the pending README before appending exactly
one binding section.

## Completion Rule

The MVP automatic gate can be treated as locally verified when the commands in
this audit pass on the target release build and
`scripts/check_release_evidence.sh` accepts the collector output. Because
Let's Encrypt is deferred, the external ACME staging row does not block MVP
completion. Post-MVP ACME readiness can be marked only when
`scripts/check_mvp_release_ready.sh` passes against separate physical automatic
release evidence and external ACME staging evidence directories.
The automatic and ACME evidence directories must remain separate physical
automatic release evidence and external ACME staging evidence directories; a
symlink alias is rejected.
