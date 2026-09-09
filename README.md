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
| `analytics`| Stats, win-rate queries, and admin match review             |
| `web`      | Dashboard UI                                       |

Shared infrastructure: PostgreSQL (single instance, per-service schemas), Redis (event bus + cache), Caddy (TLS).

## Self-hosting

> **Note:** Service code is under development. This scaffolding is the foundation for v0.4.0.

```bash
# Coming in Phase 2 — service implementations
docker compose up -d
```

Full deployment documentation will live in `docs/` once services are implemented.

## Match review and force-reparse

Admins can Reject a match from the Matches page to hide it from the user's
stats and match history without deleting it. Restore makes it visible again.
Review decisions survive ordinary reparses and user-scoped, agent-scoped, and
global force-reparses, including a parser restart between deletion and rebuilding.

Force-reparse removes parsed matches and lets the backfill scanner rebuild them
from archived files asynchronously. Its result reports matches deleted and
review verdicts carried forward. The latter counts selected matches already
protected by a stored admin decision, not completed rebuilds. The dashboard
may be temporarily unavailable while rebuilding runs.

## Releases and rollout

A release builds and publishes the five service images to GHCR, then creates a
GitHub Release. That is the end of this repository's release path. The published
image digest is the handoff artifact.

Lab rollout is owned by
[`sentania-labs/lab-deployment`](https://github.com/sentania-labs/lab-deployment).
That repository pins the selected image digest under `apps/deep-analysis/`, and
Argo CD reconciles the cluster to that declared state. This repository does not
deploy a release to the lab.

## Observability

Each service emits structured JSON logs and exposes a `/metrics` endpoint (Prometheus text format).

Optional Loki + Grafana + Prometheus stack:

```bash
docker compose --profile observability up -d
```

## Contributing

Every push must go through a feature branch + PR, and only merges when CI is green. Direct pushes to `main` are reserved for urgent fixes with Scott's sign-off.

A local PreToolUse hook also gates pushes on a `/self-review` marker that matches the HEAD of the tree being pushed. See [CONTRIBUTING.md](CONTRIBUTING.md#pre-push-review-gate).

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

Run one suite at a time with `bash ci/smoke.sh e2e` (the API and gateway happy path, `ci/smoke_e2e.sh`) or `bash ci/smoke.sh ui` (the browser UI: login, dashboard, profile, admin CRUD via curl in `ci/smoke_ui.sh`, then every rendered page and control driven in a real Chromium under the production Content Security Policy by `ci/browser/smoke_csp.py`). Those are exactly what the `compose-smoke` and `smoke-ui` CI jobs invoke.

The browser pass needs Playwright's Chromium. `ci/smoke.sh` installs the browser binary itself (`uv run playwright install chromium`, cached under `~/.cache/ms-playwright`), but on a bare machine the system libraries Chromium links against have to be present; `cd ci/browser && uv run playwright install --with-deps chromium` adds them (it uses `sudo apt`, which is why CI does that step in the workflow rather than in the script).

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
> on. `ci/browser/smoke_csp.py` ends `=== Browser CSP smoke result: N PASS,
> 0 FAIL ===`; its PASS count also moves with the rows the stack has. Read
> the FAIL count, not the PASS count: any FAIL line is a real regression.
> `ci/smoke.sh` exits non-zero if any suite reports a FAIL.

### Frontend assets and the Content Security Policy

The gateway sends `script-src 'self'; style-src 'self'` with no `'unsafe-inline'`, no `'unsafe-eval'` and no third-party origin (`gateway/Caddyfile`, issue #126). Everything the browser loads therefore lives under `services/web/web_service/static/`:

| What | Where | How it is kept honest |
|---|---|---|
| Tailwind utilities | `static/css/tailwind.css`, compiled and committed | `bash services/web/build-css.sh` rebuilds it from the templates with the Tailwind CLI pinned in `services/web/package-lock.json`; the `frontend-assets` CI job rebuilds and fails on drift. Run it after editing any template, static JS file, Python file under `web_service/` (the content scan covers them too) or `tailwind.config.js`. |
| htmx, Alpine.js (CSP build), Chart.js, Inter, JetBrains Mono | `static/vendor/`, `static/fonts/` | Pinned with upstream URL, integrity and sha256 in `static/vendor/manifest.json`; `services/web/tests/test_csp_hygiene.py` verifies every file against it. |
| App behaviour | `static/js/app.js` plus one file per page that needs more | No inline `<script>`, `on*=` handler or `style=` attribute may appear in a template; the same test fails the build if one does. Alpine's CSP build cannot see globals (`window`, `Math`, `document`) from an `x-*` attribute, so anything of that shape goes in the JS files. |

Small behaviours are opt-in data attributes handled once in `app.js`: `data-confirm` on a form (prompt before submit), `data-autosubmit` on a select, `data-href` on a row, `data-toggle-target`, `data-copy-target`, `data-submit-once`, and `data-progress-percent`. To upgrade a vendored library, follow the steps at the top of the manifest.

`ci/smoke_ui.sh` temporarily rotates the admin password and restores it before it exits. If it dies partway through its password section against a stack you kept with `DA_SMOKE_KEEP=1`, the admin password is left as `ui-smoke-<original>`; tear the stack down and start again.

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

The Deep Analysis AI add-on (advanced analytics and coaching) is a separate proprietary component distributed via Docker image. Source for this repository is AGPL-3.0.
