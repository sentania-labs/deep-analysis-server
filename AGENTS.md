# AGENTS.md — deep-analysis-server

This file is authoritative for all agent sessions working in this repo. Read it
before taking any action.

## What this is

AGPL-3.0 server for the Deep Analysis platform. Six independent services running
as a single Docker Compose stack for self-hosted MTGO match analytics.

This is the server half of a three-repo split:
- `deep-analysis-server` (this repo) — AGPL-3.0, open source
- `deep-analysis-agent` — MIT, Windows client
- `deep-analysis-ai` — Proprietary, private GHCR image (AI add-on)

**Origin:** v0.4.0 is a clean greenfield rewrite. The predecessor (`manalog`
through v0.3.8) was a proof-of-concept. No code from manalog is ported. You may
read manalog source at `workspaces/manalog/` for design patterns, but do not copy
it wholesale.

## Charter

This workspace is software. The "What this is" / product
scope above is the charter. Software authors don't touch
infrastructure outside their charter — even with credentials
available. For work that needs out-of-charter access, use a
sanctioned cross-system channel.

## Roadmap

`ROADMAP.md` at the repo root is authoritative for active outcomes, priority order, dependencies, and operational blockers. When picking up new work, start there. Shipped releases are recorded in `CHANGELOG.md`; tactical bugs live in GitHub Issues.

## Tech stack

- **Language:** Python 3.12+
- **Web framework:** FastAPI
- **Database:** PostgreSQL (single instance, per-service logical schemas)
- **Event bus / cache:** Redis
- **TLS / proxy:** Caddy
- **Containerization:** Docker Compose
- **Migrations:** Alembic (starts fresh — no carry-forward from manalog)
- **API contracts:** OpenAPI spec (lives in `openapi/`; source of truth for external API surface)

## Services

For the service table, shared infrastructure, and the CI job map, see
[README.md](README.md#services) and
[README.md](README.md#what-ci-covers).

### Event topics

`docs/events.md` is the owning document for the Redis topic names and payload
shapes (`file.ingested`, `match.parsed`, `insight.requested`); the constants and
payload dataclasses live in `common/events.py`. Any subscriber must tolerate
extra fields.

## Design decisions — do not change without discussion

These are locked decisions from the v0.4.0 plan. If you think one needs revisiting, surface it to Scott — don't unilaterally change it.

1. **Six services, one application.** Docker Compose remains the supported
   self-hosting path. Lab rollout is declared by `sentania-labs/lab-deployment`
   under `apps/deep-analysis/`, with images pinned by digest and reconciled by
   Argo CD.
2. **Single Postgres, per-service logical schemas.** Schemas: `auth.*`, `ingest.*`, `parser.*`, `analytics.*`. Analytics reads across schemas but owns no tables.
3. **Redis for event bus and caches.** Ingest publishes `file.ingested`; parser consumes it. Services also use Redis for short-lived caches.
4. **Short-lived JWTs for service-to-service auth.** `auth` service issues JWTs; each service holds the public key to verify inbound tokens.
5. **OpenAPI spec is the contract.** `openapi/` contains the spec. The agent repo vendors generated types from it. Server is source of truth.
6. **Observability is app-level by default.** Structured JSON logs + `/metrics` endpoints on every service. Loki+Grafana+Prometheus available via `--profile observability` compose overlay — not on by default.
7. **No manalog code ported.** Read manalog source for patterns; write v0.4.0 fresh.
8. **No data migration.** Alembic starts at `001_initial_schema` covering all six schemas. No carry-forward from the manalog postgres.
9. **Multi-user attribution from day one.** `ingest` schema design: `game_log_files` (sha PK, device-neutral dedup) + `user_uploads` (user_id + sha FK, per-user attribution). Not a migration after the fact.
10. **No license-check code / phone-home.** GHCR token auth is the license gate for the AI add-on. Server code is clean.
11. **Server emits standard events on Redis for cross-service consumption.** The parser and ingest services publish; any service (internal or add-on) can subscribe. This is the same Redis that ingest→parser uses internally; the AI add-on subscribes opportunistically. Don't collapse these into HTTP callbacks.

## Development guidelines

- **Type hints everywhere.** All functions annotated; Pydantic for request/response models.
- **Structured logging.** JSON formatter on Python's `logging` module. Every log line is machine-readable.
- **Ruff for linting/formatting, mypy for type checking.** Both must pass clean before commit.
- **Terse conventions.** Prefer explicit over magic. No clever metaclass tricks.
- **Tests per service.** Each service has its own `tests/` directory. Integration tests use a real Postgres + Redis (not mocks).
- **Web templates run under a strict CSP.** The rules, the Tailwind rebuild trigger, data-attribute behaviours and the vendoring procedure are in `services/web/README.md`; `services/web/tests/test_csp_hygiene.py` and `ci/browser/smoke_csp.py` enforce them.
- **Self-review protocol.** For non-trivial changes, spawn a subagent to review before committing. Catch your own bugs.
- **PR discipline.** See [README.md](README.md#contributing) for the required feature-branch + PR flow, and [CONTRIBUTING.md](CONTRIBUTING.md#pre-push-review-gate) for the local pre-push review gate.
- **CI runner placement.** `runs-on: lab` is an exact scale-set name, not a label array. See [README.md](README.md#what-ci-covers) for which job runs where, and `sentania-labs/homelab-runner` `docs/ci-consumer-contract.md` for the runner contract.
- **Compose smoke: run it locally before pushing.** `bash ci/smoke.sh` is the pre-push check for anything touching `docker-compose.yml`, the Caddyfile, a service Dockerfile, or a route prefix — it is the only coverage of the image builds composing into a working stack. A passing run ends with `0 FAIL` in every suite and exits 0; any FAIL line is a real regression. The full sequence, the environment knobs, and the expected per-suite counts are in README ["Pre-push smoke test"](README.md#pre-push-smoke-test-run-this-locally) — the script writes its own throwaway env file and generates the JWT keypair itself.
- **Releases are tag-based.** To cut a release, merge work to `main` via PR (CI green), then `git tag vX.Y.Z && git push origin vX.Y.Z` from `main`. The release workflow builds the 5 service images, publishes them to GHCR (tagged with the semver and `:latest`), and creates a GitHub Release. The version is baked into the images at build time as the `VERSION` build arg. No version-bump commit is required — the tag is the source of truth.

## Directory layout

```
deep-analysis-server/
├── services/
│   ├── gateway/        # Caddy + thin FastAPI shim
│   ├── auth/           # User accounts, sessions, agent registration
│   ├── ingest/         # Upload, dedup, event publish
│   ├── parser/         # Async worker: parse .dat/.log
│   ├── analytics/      # Query and administration API
│   └── web/            # Dashboard UI
├── openapi/            # OpenAPI spec (source of truth)
├── alembic/            # Database migrations (all schemas)
├── docker-compose.yml  # Primary stack (all 6 services + infra)
├── docker-compose.observability.yml  # Optional profile overlay
└── .github/workflows/  # CI (Phase 1 will add workflows)
```

## PKA integration

- **Source of truth lives in this repo.** `ROADMAP.md` owns active outcomes, priority, and operational blockers. `CHANGELOG.md` owns shipped releases. `.pka/updates/current.md` reports session activity.
- **Riker reads, does not direct.** Riker (the project-liaison agent in PKA) reads `ROADMAP.md`, `CHANGELOG.md`, and `.pka/updates/current.md` to surface status in Scott's daily briefing. He does not author "next steps," "attention needed," or "blockers" sections of his own — those decisions live in this repo.
- Status marker (Riker's): `agents/riker/status/deep-analysis-server.md` in the PKA repo. It is a derived view, not a source of truth.
- Session updates: write `.pka/updates/current.md` at session end per the `pka-workspace-updates` skill convention.
- Full delegation: Scott has granted full delegation on Deep Analysis (inherited from manalog posture).
