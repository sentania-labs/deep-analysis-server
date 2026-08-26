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
- `minio_data`: the raw game-log archive, in the stack's own MinIO.
- `raw_archive`: the pre-object-store archive, on hosts upgraded from
  it. Declared `external: true`, so Compose neither creates nor removes
  it and `down -v` leaves it alone. Nothing mounts it any more except
  the one-shot backfill job. See "Raw archive" below.
- `caddy_data` — Caddy's internal CA, issued certs, and OCSP state.
- `auth_secrets` — mounted into the `auth` container at `/data/secrets`.
  Holds `initial_admin.txt` (mode `0600`) when the auto-generate
  bootstrap path runs. See "First run" below.

Inspect: `docker volume ls | grep deep-analysis`. Inspect mount path: `docker volume inspect <name>`.

Reset everything (destructive — drops DB + re-issues local certs):

```bash
docker compose down -v
```

`-v` removes every named volume Compose manages, which is all of them
except `raw_archive`. That one is declared external precisely so this
command cannot take the pre-backfill archive with it.

## Raw archive (object storage)

The raw uploads live in an S3-compatible object store, not on a shared
filesystem. `ingest` writes them and `parser` reads them, both through
the same adapter, so the two services share no volume.

The stack ships its own MinIO service. It comes up with `docker compose
up` and a one-shot `minio-init` container creates the bucket if it is
missing, in the same shape as the `*-migrate` jobs. Nothing has to be
clicked in a console and no setting has to be filled in first.

Placement is entirely config. To move the archive to a shared object
store or a real cloud bucket, change four values and restart; no code
changes:

| Variable | Default | Notes |
|---|---|---|
| `DA_S3_ENDPOINT_URL` | `http://minio:9000` | |
| `DA_S3_ACCESS_KEY` | `deep-analysis` | Also seeds MinIO's root user |
| `DA_S3_SECRET_KEY` | `deep-analysis-dev-secret` | Change this on any host that is not a throwaway |
| `DA_S3_BUCKET` | `deep-analysis-raw` | |
| `DA_S3_FORCE_PATH_STYLE` | `true` | MinIO needs `true`; AWS S3 wants `false` |
| `DA_S3_REGION` | `us-east-1` | Signing region. Ignored by MinIO, required by AWS S3 |
| `DA_S3_CONNECT_TIMEOUT_SECONDS` | `3.0` | |
| `DA_S3_READ_TIMEOUT_SECONDS` | `10.0` | |
| `DA_S3_MAX_ATTEMPTS` | `3` | |
| `DA_S3_KEY_PREFIX` | `raw` | Key prefix objects are written under |

Every one of these is forwarded to `ingest`, `parser` and the backfill
job from a single `x-s3-env` block in `docker-compose.yml`. `.env`
supplies Compose *interpolation* values only, so a setting that is not
in that block never reaches a container no matter what `.env` says. If
you add a setting to the adapter, add it there too.

Objects are keyed by sha256 (`raw/<ab>/<cd>/<sha256>`), which is what
`ingest.game_log_files.storage_path` records. The key is derivable from
the sha alone, so a lost `storage_path` is recoverable.

### Failure behaviour

Every store call has a bounded connect timeout (3s), read timeout (10s)
and retry count (3), so an unreachable archive produces an error in
seconds instead of blocking. `/healthz` on `ingest` and `parser` heads
the bucket on every call (own 1.5s budget, capped at 2s by the health
helper) and reports `object_store: error` with HTTP 503 when it cannot
be reached. A stuck archive is now visible from the outside rather than
hiding behind a healthy-looking service. An upload that cannot be
stored answers 503 `storage_unavailable` (or 507 when the store reports
itself full) and rolls the database row back, so the table never claims
content the archive does not have.

### Backfill from the old volume

Migrating an existing install off the `raw_archive` volume:

```bash
docker compose --profile backfill run --rm raw-backfill
```

The volume is external, so this only works on a host that actually has
one. On a fresh install it fails with an external-volume-not-found
error, which is the right answer: there is no legacy archive to move.

Until the backfill has run, every legacy sha is already in
`ingest.game_log_files` with no object behind it. Uploads handle that
safely: an upload writes its bytes to the archive on every request,
dedup hit or not, so a re-upload of a not-yet-backfilled file stores the
content instead of returning 201 over an empty archive. The same
behaviour repairs an object deleted by accident. The backfill is still
what moves files nobody re-uploads.

It is idempotent (keys are content-addressed), so re-running it is the
supported way to confirm the first run finished. It prints a count
block: expected, uploaded, already present, missing source, hash
mismatch, failed, verified. `result: OK` means every row in
`ingest.game_log_files` was verified present in the bucket. Anything
else is `INCOMPLETE` and the job exits non-zero. Add `--dry-run` (via
`run --rm raw-backfill python -m ingest_service.backfill_s3 --source
/data/raw --dry-run`) to see the plan without writing.

**The backfill never deletes anything.** The old volume is left exactly
as it was, so the change is reversible until someone deliberately
removes it. The volume is declared `external: true` in the Compose file,
so `docker compose down -v` does not remove it either. Once the run reports `result: OK` and you have confirmed
uploads and parses are working against the object store, reclaim the
space yourself:

```bash
docker volume rm deep-analysis_raw_archive
```

That is the only step that destroys the old copy, and nothing does it
for you.

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
  `DA_JWT_PRIVATE_KEY_PATH=/data/secrets/jwt_private.pem` and
  `DA_JWT_PUBLIC_KEY_PATH=/data/secrets/jwt_public.pem`. These land on
  the `auth_secrets` named volume (see "Volumes" above) — either
  `docker compose cp` the keypair into the volume, or mount a host
  directory over `/data/secrets` via an override.
- `ingest`, `parser`, `analytics`, `web`: public key only, mounted at
  the path named by `DA_JWT_PUBLIC_KEY_PATH` (default
  `/data/secrets/jwt_public.pem`).

> **Note on paths:** do not use `/run/secrets/...` — that is Docker
> Compose's *secrets* convention and requires a top-level `secrets:`
> block, which this stack does not use. The committed compose stack
> mounts a named volume at `/data/secrets` instead. Align any `.env`
> override to `/data/secrets/...`.

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
