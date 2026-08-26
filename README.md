# Deep Analysis

Open-source AGPL-3.0 server for the Deep Analysis platform — a self-hosted MTGO match analytics system.

## What this is

Deep Analysis is a self-hosted platform for tracking and analyzing Magic: The Gathering Online match data. This repository contains the server-side stack: six independent services running as a single Docker Compose application.

The matching Windows agent (MIT license) lives at [sentania-labs/deep-analysis-agent](https://github.com/sentania-labs/deep-analysis-agent) *(coming soon)*.

## Documentation

- [docs/deploy.md](docs/deploy.md) — Deployment + environment
- [docs/admin-bootstrap.md](docs/admin-bootstrap.md) — Initial admin password flow
- [docs/backup.md](docs/backup.md) — Backup strategy
- [docs/events.md](docs/events.md) — Redis event topics (AI contract)
- [docs/migrations.md](docs/migrations.md) — Alembic usage
- [docs/diagrams/](docs/diagrams/) — Architecture + flow diagrams (diagram content arrives in W1c-iii)

## Architecture

![Deep Analysis architecture — 6-service topology with Postgres logical schemas, Redis event bus, and AI add-on seam](docs/diagrams/architecture.png)

Source: [`docs/diagrams/architecture.excalidraw`](docs/diagrams/architecture.excalidraw). See [`docs/diagrams/README.md`](docs/diagrams/README.md) for regeneration instructions.

## Quickstart

The current slice (W1a) stands up the infra containers only — PostgreSQL,
Redis, and the Caddy gateway. Application services land in subsequent
slices; the gateway will 502 on `/api/*` routes until then.

```bash
# 1. Clone and enter the repo
git clone https://github.com/sentania-labs/deep-analysis-server.git
cd deep-analysis-server

# 2. Configure secrets
cp .env.example .env
# Edit .env and set POSTGRES_PASSWORD to a real value

# 3. Start the stack
docker compose up -d

# 4. Sanity-check
docker compose ps                  # postgres + redis should report healthy
curl http://localhost/health       # gateway → "ok"

# 5. Tear down (volumes preserved)
docker compose down
```

Requirements: Docker Engine 24+ with the Compose v2 plugin.

## Services

| Service    | Role                                               |
|------------|----------------------------------------------------|
| `gateway`  | TLS termination, request routing, rate limiting    |
| `auth`     | User accounts, sessions, agent registrations       |
| `ingest`   | File upload, deduplication, event publishing       |
| `parser`   | Async parse worker: `.dat`/`.log` → match records  |
| `analytics`| Read-only stats and win-rate query API             |
| `web`      | Dashboard UI                                       |

Shared infrastructure: PostgreSQL (single instance, per-service schemas), Redis (event bus + cache), Caddy (TLS).

## Self-hosting

> **Note:** Service code is under development. This scaffolding is the foundation for v0.4.0.

```bash
# Coming in Phase 2 — service implementations
docker compose up -d
```

Full deployment documentation will live in `docs/` once services are implemented.

## Observability

Each service emits structured JSON logs and exposes a `/metrics` endpoint (Prometheus text format).

Optional Loki + Grafana + Prometheus stack:

```bash
docker compose --profile observability up -d
```

## Contributing

Every push must go through a feature branch + PR, and only merges when CI is green. Direct pushes to `main` are reserved for urgent fixes with Scott's sign-off.

### What CI covers

CI runs on the `lab` runner pool (ARC pods on the homelab Kubernetes cluster). Jobs: `lint`, `typecheck`, `test-common`, `test-integration` (real PostgreSQL 16 + Redis 7, started by `ci/start-test-services.sh`), `docker-build` (all five service images, via the shared in-cluster BuildKit), and `diagram-drift`.

### Pre-push smoke test (run this locally)

The runner pods have no Docker daemon, so the full-stack compose smoke tests are **not** run by CI. They are a local step, and they are the only coverage of the composed stack: gateway routing, service wiring, and the built images actually starting. Run both before pushing anything that touches `docker-compose.yml`, the Caddyfile, a service Dockerfile, or a routing prefix.

Both scripts need the bootstrap admin credentials in the environment, and the CI compose override bind-mounts a JWT keypair from `/tmp/ci-jwt-keys`, so the setup below is not optional. It needs `docker`, `uv`, `curl`, `python3`, and `unzip` on your PATH. Run it from a clean checkout, in order, in one shell:

```bash
# 0. once per machine: the external network the gateway attaches to
docker network create edge-slots 2>/dev/null || true

# 1. bootstrap admin credentials. Both the .env (so the auth container
#    creates the account on first boot) and the shell (so the smoke
#    scripts can log in as it) need them.
export DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL=admin@smoke.local
export DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD='SmokeAdminPass2026!'

# 2. compose environment. The appended URLs use the `postgres` container
#    hostname: DATABASE_URL overrides the localhost form in .env.example,
#    DA_DATABASE_URL is only a commented-out example there.
cp .env.example .env
cat >> .env <<EOF
DA_DATABASE_URL=postgresql+asyncpg://da:changeme@postgres:5432/deep_analysis
DATABASE_URL=postgresql+psycopg://da:changeme@postgres:5432/deep_analysis
DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL}
DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}
EOF

# 3. JWT keypair at the path ci/docker-compose.ci.yml bind-mounts.
uv sync --all-packages --dev
mkdir -p /tmp/ci-jwt-keys
uv run python -m auth_service.keygen --out /tmp/ci-jwt-keys
chmod 644 /tmp/ci-jwt-keys/jwt_public.pem
chmod 600 /tmp/ci-jwt-keys/jwt_private.pem

# 4. bring the stack up. The root/auth/ingest migrate containers run
#    Alembic automatically, so no host-side migration step is needed.
docker compose -f docker-compose.yml -f ci/docker-compose.ci.yml up -d --build

# 5. wait for the stack. Two separate waits, both required. The gateway
#    answers 502 for any service that has not finished starting, and a
#    502 reads as a smoke failure, so do not skip the health wait.
for i in $(seq 1 90); do
  unhealthy=$(docker compose -f docker-compose.yml -f ci/docker-compose.ci.yml ps \
    --format '{{.Service}} {{.Health}}' | awk '$2 != "" && $2 != "healthy"')
  [ -z "$unhealthy" ] && { echo "all services healthy after ${i} tries"; break; }
  sleep 2
done
[ -n "$unhealthy" ] && echo "WARNING: still not healthy, smoke results below are not trustworthy:
$unhealthy"

for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://localhost:8080/auth/login \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL}\",\"password\":\"${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}\"}")
  [ "$code" = "200" ] && { echo "bootstrap admin ready after ${i} tries"; break; }
  sleep 2
done
[ "$code" = "200" ] || {
  echo "STOP: the bootstrap admin never came online (last status ${code})."
  echo "Do not read the smoke output below as regressions, the stack is not up."
  docker compose -f docker-compose.yml -f ci/docker-compose.ci.yml ps
  docker compose -f docker-compose.yml -f ci/docker-compose.ci.yml logs --tail=100
}

# 6. the smoke runs themselves
bash ci/smoke_e2e.sh http://localhost:8080
bash ci/smoke_ui.sh  http://localhost:8080

# 7. teardown
docker compose -f docker-compose.yml -f ci/docker-compose.ci.yml down -v
```

`ci/smoke_e2e.sh` walks the auth + ingest happy path through the gateway; `ci/smoke_ui.sh` walks the browser UI (login, dashboard, profile, admin CRUD).

Both scripts are re-runnable against a live stack. `ci/smoke_ui.sh` temporarily rotates the admin password and restores it before it exits, so if it dies partway through its password section the admin password is left as `ui-smoke-<original>`. Tear down with `down -v` and start again from step 2 if that happens.

> **Known failures:** on a healthy stack `ci/smoke_e2e.sh` ends with exactly
> `=== Smoke result: 11 PASS, 8 FAIL ===`. That is
> [issue #139](https://github.com/sentania-labs/deep-analysis-server/issues/139):
> `/admin/*` now serves the web admin UI and answers `302` where the script
> still expects auth's bare `401`. Only one of the 8 is that redirect itself.
> The other 7 cascade from it, because the admin-user-creation step fails and
> every later step needs that user. The script is stale, not the stack.
> Compare the counts, not the individual lines: anything other than 11/8 is a
> real regression. `ci/smoke_ui.sh` should end `62 PASS, 0 FAIL`.
>
> If you see a `502` anywhere, a service was not up yet. Do not skip the
> health wait in step 5.

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

The Deep Analysis AI add-on (advanced analytics and coaching) is a separate proprietary component distributed via Docker image. Source for this repository is AGPL-3.0.
