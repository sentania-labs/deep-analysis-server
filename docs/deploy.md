# Deploy

Deployment and environment guide for the Deep Analysis server stack.

## Prerequisites

- Docker Engine 24+ with the Compose v2 plugin
- [uv](https://github.com/astral-sh/uv) for running Alembic migrations on the host
- DNS A or CNAME record for your chosen domain must resolve to this host. ACME certificate issuance requires public DNS.

## Quickstart

```bash
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD, GATEWAY_DOMAIN, DEEP_ANALYSIS_ACME_EMAIL,
# and any other credentials

docker compose up -d

# Verify the gateway is up (replace with your GATEWAY_DOMAIN)
curl https://deepanalysis.sentania.net/auth/healthz
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
| `GATEWAY_DOMAIN` | Public hostname Caddy serves and obtains an ACME cert for. Must resolve publicly. |
| `DEEP_ANALYSIS_ACME_EMAIL` | Let's Encrypt contact email for ACME certificate issuance. |

## TLS modes

The committed `gateway/Caddyfile` uses ACME (Let's Encrypt) driven by the
`GATEWAY_DOMAIN` and `DEEP_ANALYSIS_ACME_EMAIL` env vars. No separate dev
Caddyfile is shipped — one config, one code path.

If an operator wants to skip real TLS (e.g. local-only testing with no public
DNS), override the gateway service via `docker-compose.override.yml` to mount
a local Caddyfile with `tls internal`:

```yaml
# docker-compose.override.yml — local/no-DNS testing
services:
  gateway:
    volumes:
      - ./gateway/Caddyfile.local:/etc/caddy/Caddyfile:ro
```

With a `gateway/Caddyfile.local` such as:

```
deepanalysis.local {
    tls internal
    handle /health { respond "ok" 200 }
    handle_path /auth/*      { reverse_proxy auth:8000 }
    handle_path /ingest/*    { reverse_proxy ingest:8000 }
    handle_path /analytics/* { reverse_proxy analytics:8000 }
    handle                   { reverse_proxy web:8000 }
}
```

Add `127.0.0.1 deepanalysis.local` to your hosts file and use `curl -k` to
bypass the self-signed cert warning.

## Behind a reverse proxy (fleet-caddy, Traefik, nginx)

When the stack sits behind an upstream edge proxy (for example, a shared
fleet Caddy or a Traefik frontdoor), the gateway still terminates its own TLS
via ACME. Configure the upstream for **L4 SNI pass-through to port 443** of
this host or container — do not re-terminate TLS at the edge, or Caddy's ACME
challenge will fail and the service cert chain will not match what clients
see.

Typical override: swap `ports:` for `expose:` and attach the gateway to a
shared external Docker network owned by the fleet proxy.

```yaml
# docker-compose.override.yml — behind a reverse proxy
services:
  gateway:
    ports: !reset []
    expose:
      - "80"
      - "443"
    networks:
      - default
      - proxy
networks:
  proxy:
    external: true
    name: fleet-caddy
```

This is an illustrative sketch — adjust the network name to match your fleet
proxy's actual Docker network.

## Volumes

Named volumes (managed by Docker):

- `postgres_data` — Postgres data directory.
- `caddy_data` — Caddy's internal CA, issued certs, and OCSP state.
- `auth_secrets` — mounted into the `auth` container at `/data/secrets`.
  Holds `initial_admin.txt` (mode `0600`) when the auto-generate
  bootstrap path runs. See "First run" below.

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

## Redis

Redis is both the internal event bus (ingest → parser) and a
user-facing short-lived cache. Agent registration codes live in
Redis with a 10-minute TTL (see `docs/agent-protocol.md`), so the
instance must be reachable from the `auth` service. The connection
URL is set via `DA_REDIS_URL` (default `redis://redis:6379/0` in
compose). Persistence is not required — registration codes are
deliberately ephemeral; if Redis is flushed the user just mints a
fresh code.

## First run

The first time the `auth` service starts against an empty database, it
creates an initial admin account. Two paths:

**Auto-generate (default).** If neither
`DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL` nor
`DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD` is set, the service generates
a random 24-char password, creates `admin@local` with
`must_change_password=true`, and writes the plaintext password to
`/data/secrets/initial_admin.txt` on the `auth_secrets` volume. Grab
it via logs:

```bash
docker compose logs auth | grep "INITIAL ADMIN PASSWORD"
```

or directly from the file:

```bash
docker compose exec auth cat /data/secrets/initial_admin.txt
```

On first login with that credential, the client is forced through the
password-change flow. The file is deleted automatically once the
password has been rotated. Full flow lives in
`docs/admin-bootstrap.md`.

**Scripted (unattended).** Set both
`DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL` and
`DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD` in `.env`. The service uses
those credentials, sets `must_change_password=false`, and writes no
plaintext file. Neither value is ever logged.

Bootstrap is idempotent: if any enabled admin already exists it is a
no-op.

## First boot — migrations

The compose stack does **not** run Alembic migrations automatically on startup (intentional — gives operators explicit control over schema changes). After the stack is healthy, run migrations separately against the published Postgres port:

```bash
uv run alembic upgrade head
```

<!-- TODO: consider migration-on-start sidecar if this becomes painful -->

## Admin lockout protection

The admin endpoints under `/admin/*` (see
`docs/admin-bootstrap.md`) intentionally refuse operations that
would leave the system with no way to recover admin access:

- An admin cannot disable their own account
  (`400 cannot_disable_self`).
- An admin cannot delete their own account
  (`400 cannot_delete_self`).
- An admin cannot demote the last active admin to `user` role
  (`400 cannot_demote_last_admin`).
- An admin cannot delete the last active admin
  (`400 cannot_delete_last_admin`).

If you hit one of these errors the fix is to first create or
promote a second admin, then retry. There is no super-admin
override; the invariant is enforced by the auth service itself.
