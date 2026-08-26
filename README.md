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

Jobs and where each one runs (issue #161 set the placement, per the `github-ci` rule that the `lab` pool exists to reach the lab, not to avoid GitHub):

| Job | Runner | Why there |
|---|---|---|
| `lint`, `typecheck`, `test-common` | `lab` | Needs nothing but Python. Deliberately left on the lab pool. |
| `docker-build` (all five images) | `lab` | Builds through the shared in-cluster BuildKit. |
| `test-integration` | `ubuntu-latest` | Needs real PostgreSQL 16 and Redis 7 daemons, via Actions `services:`. |
| `compose-smoke`, `smoke-ui` | `ubuntu-latest` | Needs a real Docker daemon for `docker compose`. |
| `diagram-drift` | `ubuntu-latest` | The lab runner image is missing chromium's NSS libraries (sentania-labs/homelab-runner#1). |

### Pre-push smoke test (run this locally)

The full-stack smoke test is the only coverage of the composed stack: gateway routing, service wiring, and the built images actually starting. Run it before pushing anything that touches `docker-compose.yml`, the Caddyfile, a service Dockerfile, or a routing prefix.

There is one definition of it, `ci/smoke.sh`, and CI runs the same script. From a clean checkout:

```bash
bash ci/smoke.sh
```

That is the whole sequence. The script creates the external `edge-slots` network, writes a throwaway compose env file (it never touches your `.env`), generates the JWT keypair the compose override bind-mounts, brings the stack up, waits for container health and for the bootstrap admin to answer, runs both smoke suites, dumps logs if anything failed, and tears the stack down. It needs `docker`, `uv`, `curl` and `python3` on your PATH, and Docker Compose **v2.24.4 or newer** (the compose override uses the `!override` / `!reset` merge tags). The script checks the Compose version up front and tells you if it is too old.

Run one suite at a time with `bash ci/smoke.sh e2e` (the API and gateway happy path, `ci/smoke_e2e.sh`) or `bash ci/smoke.sh ui` (the browser UI: login, dashboard, profile, admin CRUD, `ci/smoke_ui.sh`). Those are exactly what the `compose-smoke` and `smoke-ui` CI jobs invoke.

Useful knobs, all optional:

| Variable | Default | What it does |
|---|---|---|
| `DA_SMOKE_PROJECT` | `deep-analysis-smoke` | Compose project name, so a smoke stack does not collide with your dev stack. |
| `DA_SMOKE_PORT` | `8080` | Host port for the gateway. |
| `DA_SMOKE_JWT_DIR` | `/tmp/ci-jwt-keys` | Where the throwaway keypair is written and mounted from. |
| `DA_SMOKE_KEEP` | unset | Set to `1` to leave the stack up for poking at. It prints the teardown command. |
| `DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` | `admin@smoke.local` / `SmokeAdminPass2026!` | The account both suites log in as. |

> **Expected result:** on a healthy stack `ci/smoke_e2e.sh` ends
> `=== Smoke result: 23 PASS, 0 FAIL ===` and exits 0. `ci/smoke_ui.sh` ends
> `0 FAIL`; its PASS count moves between roughly 62 and 66 because a few of
> its admin checks only run when the stack already has an agent row to act
> on. Read the FAIL count, not the PASS count: any FAIL line is a real
> regression. `ci/smoke.sh` exits non-zero if either suite reports a FAIL.

`ci/smoke_ui.sh` temporarily rotates the admin password and restores it before it exits. If it dies partway through its password section against a stack you kept with `DA_SMOKE_KEEP=1`, the admin password is left as `ui-smoke-<original>`; tear the stack down and start again.

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

The Deep Analysis AI add-on (advanced analytics and coaching) is a separate proprietary component distributed via Docker image. Source for this repository is AGPL-3.0.
