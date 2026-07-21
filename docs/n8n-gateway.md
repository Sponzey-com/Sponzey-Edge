# n8n Gateway Smoke

Sponzey Edge can now run as a minimal HTTP reverse proxy in front of an n8n Docker container.

Current supported scope:

- HTTP listener
- config snapshot route selection
- deterministic round-robin across eligible `http://` upstreams
- request forwarding
- response forwarding
- request body forwarding
- WebSocket upgrade tunnel
- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Forwarded-Host`
- hop-by-hop header removal
- MVP config file parsing for `examples/minimal.toml`-style configuration

Current limitations:

- HTTPS termination has a local self-signed smoke gate, but the n8n compose smoke is still HTTP-only.
- WebSocket tunnel is implemented at a basic TCP tunnel level after `101 Switching Protocols`.
- Admin API currently binds status, health, upstream-health, setup/login/logout, config lifecycle, proxy host CRUD, certificate issue/renew through the selected bootstrap certificate issue adapter, certificate read status, and recent log read-only endpoints. Automatic smoke uses the default fake adapter; external Let's Encrypt staging requires `SPONZEY_ACME_CLIENT=letsencrypt-staging` and is deferred to Post-MVP work in `docs/acme-staging.md`. HTTP-01 token lifecycle is covered through the Admin API/runtime boundary with an injected token store. Multi-cert TLS/SNI selection and TLS connection progress run in the unified mio state machine.
- The n8n smoke compose uses explicit `SPONZEY_DEV_LISTEN` and `SPONZEY_DEV_UPSTREAM_URL` bootstrap overrides so the upstream can target Docker service DNS (`n8n:5678`). These are development smoke helpers, not the intended runtime config lifecycle.
- The packaged n8n example uses one upstream. Multi-upstream round-robin and
  active-health exclusion are implemented, while retry policy remains deferred.

## Run

From the repository root:

```bash
docker compose -f examples/n8n-gateway.compose.yml up --build
```

Open:

```text
http://localhost:8080
```

The traffic path is:

```text
browser
  -> Sponzey Edge :8080
  -> n8n :5678
```

## Runtime Environment

The Edge container uses bootstrap-only environment values. `SPONZEY_CONFIG_FILE` points to the packaged sample config; for this smoke, `SPONZEY_DEV_LISTEN` and `SPONZEY_DEV_UPSTREAM_URL` explicitly override the listener/upstream pair:

```text
SPONZEY_CONFIG_FILE=/etc/sponzey-edge/current.toml
SPONZEY_DEV_LISTEN=0.0.0.0:8080
SPONZEY_DEV_UPSTREAM_URL=http://n8n:5678
SPONZEY_ACME_CLIENT=fake
```

n8n is configured as a proxied service:

```text
N8N_HOST=localhost
N8N_PORT=5678
N8N_PROTOCOL=http
WEBHOOK_URL=http://localhost:8080/
N8N_PROXY_HOPS=1
```

Use HTTPS values only after installing a matching certificate and configuring an
HTTPS listener. The n8n compose smoke itself intentionally remains HTTP-only.

For the MVP release path, listener/upstream changes must go through config
validation, revision apply, and rollback rather than these smoke overrides.
