# Deploy

Deployment and environment guide for the Deep Analysis server stack.

## Prerequisites

- Docker Engine 24+ with the Compose v2 plugin
- [uv](https://github.com/astral-sh/uv) for running Alembic migrations on the host
- Hosts-file entry for local dev:
  ```
  127.0.0.1   deepanalysis.local
  ```

## Quickstart (dev)

```bash
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD and any other credentials

docker compose up -d

# Verify the gateway is up
curl -k https://deepanalysis.local/auth/healthz
```

## Environment variables

Source of truth is `.env.example`. Summary:

| Variable | Description |
|---|---|
| `POSTGRES_USER` | Postgres superuser name for the stack's DB. |
| `POSTGRES_PASSWORD` | Postgres superuser password. Must be set before first boot. |
| `DA_DATABASE_URL` | SQLAlchemy-style DSN used by all services to reach Postgres. |
| `DA_REDIS_URL` | Redis connection URL (event bus + cache). |
| `DA_JWT_PUBLIC_KEY_PATH` | Path (inside each service container) to the JWT verification public key. |
| `DA_LOG_LEVEL` | Python logging level (`DEBUG`, `INFO`, `WARN`, `ERROR`). |
| `GATEWAY_DOMAIN` | Public hostname Caddy serves; `deepanalysis.local` in dev. |

## TLS modes

- **Local dev:** Caddy uses `tls internal` — self-signed certs are generated automatically. Browsers will warn; `curl -k` bypasses verification.
- **Production:** a real certificate is supplied via the fleet Caddy in front of the stack. The stack-internal Caddy can be pointed at a managed cert or fronted by the fleet proxy; either way the app services don't terminate TLS.

## Volumes

Named volumes (managed by Docker):

- `postgres_data` — Postgres data directory.
- `caddy_data` — Caddy's internal CA, issued certs, and OCSP state.

Inspect: `docker volume ls | grep deep-analysis`. Inspect mount path: `docker volume inspect <name>`.

Reset everything (destructive — drops DB + re-issues local certs):

```bash
docker compose down -v
```

## Port publishing

- `127.0.0.1:5432` — Postgres, bound to localhost only (never exposed on a routable interface).
- `:80` / `:443` — Caddy gateway.

> **Lab-box note:** `:443` conflicts with pka-dashboard on the shared lab host. For dev sessions there, drop a `docker-compose.override.yml` (gitignored) that remaps gateway ports to free alternatives.

## JWT keys

The `auth` service signs access tokens with an RS256 private key; every
other service verifies with the corresponding public key. Operators
generate the keypair once at deploy time:

```bash
uv run python -m auth_service.keygen --out ./secrets/
```

Mount the files into the containers via Docker Compose secrets or a
read-only bind:

- `auth` container: both keys, with
  `DA_JWT_PRIVATE_KEY_PATH=/run/secrets/jwt_private.pem` and
  `DA_JWT_PUBLIC_KEY_PATH=/run/secrets/jwt_public.pem`.
- `ingest`, `parser`, `analytics`, `web`: public key only, mounted at
  the path named by `DA_JWT_PUBLIC_KEY_PATH`.

See `docs/admin-bootstrap.md` for the rotation procedure.

## First boot — migrations

The compose stack does **not** run Alembic migrations automatically on startup (intentional — gives operators explicit control over schema changes). After the stack is healthy, run migrations separately against the published Postgres port:

```bash
uv run alembic upgrade head
```

<!-- TODO: consider migration-on-start sidecar if this becomes painful -->
