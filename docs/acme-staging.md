# Post-MVP Let's Encrypt Staging Checklist

This document defines the deferred Post-MVP validation gate for Let's Encrypt
HTTP-01 staging. It is intentionally separate from `./scripts/smoke_mvp.sh`
because it requires an externally reachable test domain, public DNS, and CA
network access. It is not required for MVP completion while Let's Encrypt is
out of scope.

## Current MVP State Without Let's Encrypt

The automatic MVP gate covers the internal certificate issue boundary with the
default fake ACME adapter:

- The fake ACME adapter receives the issue request through `AcmeClient` and
  provides the HTTP-01 token/key authorization through the explicit challenge
  runtime port.
- The runtime HTTP listener serves `/.well-known/acme-challenge/{token}` from

  the injected challenge store.
- The issue use case verifies the token through the runtime listener before

  issuing the fake certificate.
- Success and failure paths clear the token.
- The certificate is stored through `CertificateStore` and installed through

  `CoreCommandClient`.

The config-file startup path selects the ACME adapter at bootstrap only through
`SPONZEY_ACME_CLIENT`. The default is `fake` for automatic MVP smoke tests. The
deferred Post-MVP external staging gate must start the process with
`SPONZEY_ACME_CLIENT=letsencrypt-staging`, which wires the real Let's Encrypt
HTTP-01 adapter through the same `AcmeClient` port. Do not claim the Post-MVP
external staging gate has passed until the checklist below is executed against
an approved test domain, the Admin API issue response reports a real
`letsencrypt_staging` source, and the evidence is recorded with
`docs/release-evidence-template.md`.
In other words, do not claim that the external staging gate has passed from
local smoke output alone, and do not treat this checklist as an MVP blocker
while Let's Encrypt is deferred.

`scripts/acme_staging_preflight.sh` is available as a manual helper. It does
not issue certificates and does not replace this checklist. It verifies the
approved-domain inputs, `production=false`, explicit terms acceptance, unknown
HTTP-01 token `404`, optional known-token body, and optional post-issue HTTPS
reachability.

After the external run, store the evidence in one directory and validate it
with `scripts/check_acme_staging_evidence.sh`. The checker does not contact
Let's Encrypt; it verifies that the recorded evidence is complete, uses staging
instead of production ACME, includes the required challenge/HTTPS proof, and
does not contain obvious secrets.

## Prerequisites

- Use a disposable test hostname controlled by the project, for example

  `edge-staging.your-approved-domain.com`.
- DNS `A` or `AAAA` records for the hostname point to the host running

  `edge-proxy`.
- Port `80/tcp` is reachable from the public internet and is routed to the

  HTTP listener configured in the active `ConfigSnapshot`.
- The route for the test hostname is enabled and has a `certificate_ref`.
- The route's HTTP listener remains enabled while the challenge is pending.
- Production ACME is disabled unless explicitly approved for a separate

  production release test.
- Terms of service acceptance is explicit in the Admin API request or typed

  config input.
- No runtime behavior is changed by editing environment variables after the

  process starts.
- The Admin API is protected by an authenticated session and CSRF token.
- The operator has completed Admin API setup/login from `docs/admin-curl.md` and
  has an active cookie jar plus `CSRF` value for mutation requests.
- Product logs, Admin API responses, and config diffs mask secret values and

  never include private key PEM.

## Prohibited Shortcuts

- Do not use a production Let's Encrypt directory for this gate.
- Do not switch ACME directories by modifying the environment of a running

  process.
- Do not bypass Admin API validation by writing directly to the revision store

  or certificate store.
- Do not write challenge tokens to ad hoc files outside the typed challenge

  store.
- Do not let ACME network I/O run on the mio event loop thread.
- Do not expose the Admin API on `0.0.0.0` without authentication.
- Do not keep temporary debug logs that include token, account key, private key,

  cookie, authorization header, request body, or full query string.

## Manual Execution

1. Build and run `edge-proxy` with the intended primary config file.

```bash
cargo build --release -p edge-proxy
SPONZEY_DATA_DIR=.sponzey-staging \
SPONZEY_CONFIG_FILE=examples/minimal.toml \
SPONZEY_ADMIN_BIND=127.0.0.1:9443 \
SPONZEY_LOG_MODE=product \
SPONZEY_ACME_CLIENT=letsencrypt-staging \
target/release/edge-proxy
```

2. Confirm bootstrap-only environment handling.

- Restart the process for every environment change.
- Do not rely on `std::env` reads after startup.
- Confirm runtime config changes go through Admin API apply/rollback.

3. Confirm HTTP-01 reachability before issuing.

Use the runtime listener and test hostname. Replace the token with a token
inserted by the staging adapter or by an approved diagnostic build.

First run the preflight helper with the approved hostname and public target:

```bash
SPONZEY_STAGING_DOMAIN=edge-staging.your-approved-domain.com \
SPONZEY_STAGING_PUBLIC_IP=PUBLIC_IP \
SPONZEY_STAGING_PRODUCTION=false \
SPONZEY_STAGING_TERMS_ACCEPTED=true \
./scripts/acme_staging_preflight.sh
```

When a known token is available, include the expected key authorization:

```bash
SPONZEY_STAGING_DOMAIN=edge-staging.your-approved-domain.com \
SPONZEY_STAGING_PUBLIC_IP=PUBLIC_IP \
SPONZEY_STAGING_PRODUCTION=false \
SPONZEY_STAGING_TERMS_ACCEPTED=true \
SPONZEY_STAGING_CHALLENGE_TOKEN=TOKEN \
SPONZEY_STAGING_KEY_AUTHORIZATION=KEY_AUTHORIZATION \
./scripts/acme_staging_preflight.sh
```

```bash
curl -v \
  --resolve edge-staging.your-approved-domain.com:80:PUBLIC_IP \
  http://edge-staging.your-approved-domain.com/.well-known/acme-challenge/TOKEN
```

Expected result:

- known token returns `200 OK` and the exact key authorization body
- unknown token returns `404 Not Found`
- redirect rules do not intercept the challenge path
- access logs do not include request body, cookie, authorization header, or full

  query string

4. Issue through the Admin API only.

Use the authenticated Admin API session and CSRF token from `docs/admin-curl.md`.
Set a stable request id before issuing; the same value must be recorded as
`admin_api_request_id` in `metadata.env` and must appear in the
`certificate.issue.success` product log line. The staging request must set
production to false.

```bash
export ADMIN=http://127.0.0.1:9443/api/v1
export ISSUE_REQUEST_ID=req-acme-staging-RELEASE_ID
```

```http
POST /api/v1/certificates/{certificate_ref}/issue
Cookie: sponzey_session=...
X-CSRF-Token: ...
X-Request-Id: req-acme-staging-RELEASE_ID

{
  "domains": ["edge-staging.your-approved-domain.com"],
  "account_email": "admin@your-approved-domain.com",
  "production": false,
  "terms_accepted": true
}
```

Expected result:

- response status is `200 OK`
- response includes matching top-level field-value pairs for `request_id`,
  `certificate_ref`, `domains`, `source=letsencrypt_staging`, and numeric
  `not_after_epoch_seconds`
- response `request_id` matches `ISSUE_REQUEST_ID`, and the product log line
  also carries the supplied `X-Request-Id`
- response omits certificate PEM and private key PEM
- `data/certs/{certificate_ref}/fullchain.pem` exists
- `data/certs/{certificate_ref}/privkey.pem` exists with owner-only permission

  on Unix
- `data/certs/{certificate_ref}/metadata.toml` exists
- `InstallCertificate` is sent through `CoreCommandClient`

5. Verify runtime behavior after issue.

Run the preflight helper with the HTTPS check enabled:

```bash
SPONZEY_STAGING_DOMAIN=edge-staging.your-approved-domain.com \
SPONZEY_STAGING_PUBLIC_IP=PUBLIC_IP \
SPONZEY_STAGING_PRODUCTION=false \
SPONZEY_STAGING_TERMS_ACCEPTED=true \
SPONZEY_STAGING_CHECK_HTTPS=true \
./scripts/acme_staging_preflight.sh
```

```bash
curl -vk \
  --resolve edge-staging.your-approved-domain.com:443:PUBLIC_IP \
  https://edge-staging.your-approved-domain.com/
```

Expected result:

- TLS handshake succeeds with the issued staging certificate
- request forwards to the configured upstream
- `X-Forwarded-Proto` is `https`
- rollback to the previous config revision still preserves the previous working

  route

6. Record release evidence.

Use `docs/release-evidence-template.md` and attach the following to the release
notes:

- test hostname and DNS record type
- UTC timestamp of the run
- commit or build identifier
- config revision id before issue
- config revision id after issue, if changed
- certificate ref
- Admin API request id
- `scripts/acme_staging_preflight.sh` output
- `curl` output showing challenge reachability
- `curl` output showing HTTPS forwarding
- product log excerpt showing issue success without secrets
- product log excerpt uses `request_id` equal to the supplied `X-Request-Id`
- statement that production ACME was not used

Recommended evidence directory layout:

```text
artifacts/acme-staging-evidence/RELEASE_ID/
  metadata.env
  preflight.log
  challenge-curl.log
  https-curl.log
  admin-api-issue-response.json
  product-log-excerpt.log
  required-statements.txt
```

You can initialize that layout before the external run:

```bash
SPONZEY_STAGING_DOMAIN=edge-staging.your-approved-domain.com \
SPONZEY_STAGING_PUBLIC_IP=PUBLIC_IP \
SPONZEY_STAGING_CERTIFICATE_REF=edge-staging \
SPONZEY_STAGING_CONFIG_REVISION_BEFORE=rev-before \
SPONZEY_STAGING_EVIDENCE_DIR=artifacts/acme-staging-evidence/RELEASE_ID \
./scripts/init_acme_staging_from_release_evidence.sh artifacts/release-evidence/RELEASE_ID
```

The evidence-bound initializer validates the automatic evidence first and
copies `release_id` plus `build_or_commit` into ACME `metadata.env`. It then
delegates to `scripts/init_acme_staging_evidence.sh` and appends an
`Automatic Evidence Binding` section to ACME `README.md` with the source
automatic evidence path, `release_id`, and `build_or_commit`. Both initializers
create pending files only. They do not contact Let's Encrypt, do not issue a
certificate, and do not make the manual gate pass. Replace the pending files
with real preflight, curl, Admin API, and product log output, then run
`scripts/check_acme_staging_evidence.sh`.
The combined final readiness checker also requires the ACME `README.md`
binding section, verifies its `automatic_release_evidence_dir` line matches the
automatic evidence directory passed to the checker, and verifies its
`release_id` plus `build_or_commit` lines match ACME `metadata.env`. Each
binding key must appear exactly once in ACME `README.md`. A trailing slash on
the automatic evidence path is normalized before writing or checking the
binding. The `Automatic Evidence Binding` section itself must also appear
exactly once, and the binding keys must be recorded inside that section.
The evidence-bound initializer inherits the lower initializer overwrite policy:
without `SPONZEY_STAGING_EVIDENCE_OVERWRITE=true`, it fails before appending the
binding when any fixed evidence file already exists; with overwrite enabled, it
rewrites the pending README before appending exactly one binding section.
If `SPONZEY_STAGING_EVIDENCE_DIR` is supplied, its directory basename must
equal `SPONZEY_STAGING_RELEASE_ID`; the initializer rejects mismatches before
writing pending evidence. The initializer also rejects any pre-existing symlink
inside the evidence tree and any unknown or stale path outside the fixed evidence
filenames before writing pending files.
Unless `SPONZEY_STAGING_EVIDENCE_OVERWRITE=true` is explicit, the initializer
checks all required evidence filenames before writing and fails without creating
new pending files when any required file already exists.

`metadata.env` must include:

```text
release_id=RELEASE_ID
build_or_commit=BUILD_OR_COMMIT
approved_test_domain=
public_ip_or_target=
acme_directory=https://acme-staging-v02.api.letsencrypt.org/directory
production_acme_used=false
terms_accepted=true
certificate_ref=
admin_api_request_id=
config_revision_before=
config_revision_after=
challenge_curl_result=challenge-curl.log
https_curl_result=https-curl.log
acme_staging_preflight_output_ref=preflight.log
product_log_excerpt_ref=product-log-excerpt.log
```

`approved_test_domain` may contain only hostname letters, numbers, dot, and
dash. `public_ip_or_target` may contain only public target letters, numbers,
dot, colon, and dash, and must be an externally reachable public IP or target.
Do not use loopback, private, link-local, reserved example names, or
documentation IP ranges such as `192.0.2.0/24`, `198.51.100.0/24`, or
`203.0.113.0/24`.
The evidence checker requires the exact Let's Encrypt staging directory and
the preflight output must show both `known_token_checked: true` and
`https_checked: true`. It rejects contradictory preflight markers such as
`production_acme_used: true`, `terms_accepted: false`,
`unknown_token_result: 200`, `known_token_checked: false`, or
`https_checked: false`. It rejects `fake-acme-*` issue responses because fake
ACME smoke output is not external staging evidence. The evidence directory
basename must equal `metadata.env` `release_id`.
Each `metadata.env` key listed above must appear exactly once; duplicate metadata keys are rejected.
The checker also requires non-empty `config_revision_after` and requires
`challenge_curl_result`, `https_curl_result`,
`acme_staging_preflight_output_ref`, and `product_log_excerpt_ref` to point to
the fixed evidence filenames listed above.
The evidence directory tree must contain no symlinks and only the fixed evidence filenames plus the initializer `README.md`; a symlinked evidence directory,
required evidence file, non-required symlink, unknown file, stale file, or nested
path inside the evidence tree is rejected before content validation.
Metadata identity values must use stable, shell-safe characters so release and
log evidence can be compared unambiguously: `release_id` may contain only
letters, numbers, dot, underscore, and dash; `build_or_commit`,
`certificate_ref`, `admin_api_request_id`, `config_revision_before`, and
`config_revision_after` may contain only letters, numbers, dot, underscore,
colon, and dash. `build_or_commit=not-recorded` is rejected for external
staging evidence; use the concrete release build id that also appears in the
automatic release evidence.
`admin-api-issue-response.json` must be a valid JSON object and include matching
top-level field-value pairs for `request_id`, `certificate_ref`, `domains`,
`source=letsencrypt_staging`, and numeric `not_after_epoch_seconds`; `request_id`
must equal `metadata.env` `admin_api_request_id`; values that
appear only in a nested object, message, or note field do not satisfy this gate.
The checker uses `python3` to parse JSON evidence files.
`challenge-curl.log` must show HTTP `200`, the approved test domain, and the
`/.well-known/acme-challenge/` path. `https-curl.log` must show the approved
test domain, TLS handshake or certificate evidence, and a successful or redirect
HTTPS response. The HTTPS evidence must also include `Let's Encrypt` and
`(STAGING)` issuer text; a production or unrelated CA certificate does not
satisfy the staging gate.
`product-log-excerpt.log` must contain only valid JSON object lines and include exactly one structured JSON object product log line containing
matching field-value pairs for `event=certificate.issue.success`,
`component=admin-api`, `revision_id=<config_revision_after from metadata.env>`,
`certificate_ref=<selected certificate reference>`, and
`request_id=<admin_api_request_id from metadata.env>`, and `status_code=200`.
Use the product log line emitted by the authenticated Admin API certificate
issue request, not an audit event or hand-written summary. The excerpt must not
contain secrets, cookies, authorization headers, request bodies, or private key
material. Values that appear only in a message or note field do not satisfy this
gate.
Evidence must also omit JSON keys such as `authorization`, `cookie`, or
`set-cookie`, PEM-bearing keys such as `certificate_pem`, `fullchain_pem`, or
`cert_pem`, PEM blocks such as `BEGIN CERTIFICATE`, and bearer/basic token strings.
The sensitive-material scan includes hidden and non-required files before the
unknown-path check; do not keep scratch files or dotfiles with secrets in the
evidence directory.
The checker reports a generic sensitive-material failure and must not echo the
matched secret-bearing evidence line into terminal output.

`required-statements.txt` must include:

```text
HTTP-01 challenge was served by the runtime HTTP listener.
Unknown HTTP-01 token returned 404.
Certificate issue went through authenticated Admin API with CSRF.
Admin API issue request used X-Request-Id matching metadata.env admin_api_request_id.
Private key PEM was not included in API responses, logs, or diffs.
Previous runtime snapshot and current revision were preserved on failure, if a failure occurred.
```

Validate the recorded evidence before release sign-off:

```bash
./scripts/check_acme_staging_evidence.sh artifacts/acme-staging-evidence/RELEASE_ID
```

Expected result:

```text
acme staging evidence check passed
```

After automatic release evidence is also collected for the Post-MVP ACME work,
run the combined readiness check. The basename of both evidence directories must equal `release_id`, and
the ACME `build_or_commit` value must equal the automatic evidence
`environment.txt` `build_or_commit` value. If git metadata is unavailable, the
automatic collector and ACME initializer can use the same
`source-tree-sha256:<digest>` identity; otherwise copy the automatic value into
`SPONZEY_STAGING_BUILD_OR_COMMIT` before initializing manual evidence:

```bash
./scripts/check_mvp_release_ready.sh \
  artifacts/release-evidence/RELEASE_ID \
  artifacts/acme-staging-evidence/RELEASE_ID
```

Expected Post-MVP result:

```text
post-MVP ACME readiness accepted by the historical mvp release readiness checker
```

## Failure Handling

If staging issue fails:

- keep the previous config revision current
- keep the previous runtime snapshot installed
- clear the HTTP-01 token
- leave existing certificate files untouched unless the new certificate write

  completed atomically
- return a stable Admin API error code with `request_id`
- record a product log issue failure without secrets
- use field-debug logs only for route match, selected listener, challenge state,

  and retry decision

## Review Criteria

The staging gate is acceptable only when:

- the challenge path is served by the runtime HTTP listener
- the Admin API is the only mutation entrypoint
- ACME client, DNS/network, certificate store, clock, audit, and metrics

  dependencies remain behind ports or adapters
- the domain and application layers do not import network, file-system,

  environment, rustls, or Admin HTTP framework types
- environment values are read once at bootstrap and then passed explicitly
- product logs stay minimal and safe
- field-debug/dev logs are not enabled by default
