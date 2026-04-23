# CLAUDE.md — deep-analysis-server

This file is authoritative for all Claude sessions working in this repo. Read it before taking any action. Cross-reference the approved plan at `/home/scott/.claude/plans/steady-dazzling-charm.md`.

## What this is

AGPL-3.0 server for the Deep Analysis platform. Six independent services running as a single Docker Compose stack for self-hosted MTGO match analytics.

This is the server half of a three-repo split:
- `deep-analysis-server` (this repo) — AGPL-3.0, open source
- `deep-analysis-agent` — MIT, Windows client
- `deep-analysis-ai` — Proprietary, private GHCR image (AI add-on)

**Origin:** v0.4.0 is a clean greenfield rewrite. The predecessor (`manalog` through v0.3.8) was a proof-of-concept. No code from manalog is ported. You may read manalog source at `workspaces/manalog/` for design patterns, but do not copy it wholesale.

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

| Service    | Responsibility                                                           | Compose container       |
|------------|--------------------------------------------------------------------------|-------------------------|
| `gateway`  | TLS termination, HTTP entry, auth middleware, rate limiting              | deep-analysis-gateway   |
| `auth`     | Users, sessions, agent registrations, admin endpoints, TTL/rotation      | deep-analysis-auth      |
| `ingest`   | Upload endpoints, sha256 dedup, raw file archive, publishes `file.ingested` | deep-analysis-ingest |
| `parser`   | Async worker: consumes ingest events, parses `.dat`/`.log`, populates match/game tables | deep-analysis-parser |
| `analytics`| Read-only query API: stats, win rate, device-attribution cuts            | deep-analysis-analytics |
| `web`      | Dashboard UI, talks only through gateway                                 | deep-analysis-web       |

Shared infra containers: `postgres`, `redis`, `caddy`.

### Event topics

| Topic | Published by | Payload shape |
|---|---|---|
| `match.parsed` | `parser` | match_id, user_id, game_count, parsed_at (TBD) |
| `upload.received` | `ingest` | sha256, user_id, filename, received_at (TBD) |
| `insight.requested` | `analytics` or client | match_id, user_id, request_id (TBD) |

Payload shapes are TBD — final schema will be in openapi/ or a dedicated events spec. Any subscriber must tolerate extra fields.

## Design decisions — do not change without discussion

These are locked decisions from the v0.4.0 plan. If you think one needs revisiting, surface it to Scott — don't unilaterally change it.

1. **Six services, one compose stack.** Not a monolith, not a k8s deployment. Compose on `docker.int` for ship.
2. **Single Postgres, per-service logical schemas.** Schemas: `auth.*`, `ingest.*`, `parser.*`, `analytics.*`. Analytics reads across schemas but owns no tables.
3. **Redis for event bus and caches.** Ingest publishes `file.ingested`; parser consumes it. Services also use Redis for short-lived caches.
4. **Short-lived JWTs for service-to-service auth.** `auth` service issues JWTs; each service holds the public key to verify inbound tokens.
5. **OpenAPI spec is the contract.** `openapi/` contains the spec. The agent repo vendors generated types from it. Server is source of truth.
6. **Observability is app-level by default.** Structured JSON logs + `/metrics` endpoints on every service. Loki+Grafana+Prometheus available via `--profile observability` compose overlay — not on by default.
7. **No manalog code ported.** Read manalog source for patterns; write v0.4.0 fresh.
8. **No data migration.** Alembic starts at `001_initial_schema` covering all six schemas. No carry-forward from the manalog postgres.
9. **Multi-user attribution from day one.** `ingest` schema design: `game_log_files` (sha PK, device-neutral dedup) + `user_uploads` (user_id + sha FK, per-user attribution). Not a migration after the fact.
10. **No license-check code / phone-home.** GHCR token auth is the license gate for the AI add-on. Server code is clean.
11. **Server emits standard events on Redis for cross-service consumption.** Topics: `match.parsed`, `upload.received`, `insight.requested`. The parser and ingest services publish. Any service (internal or add-on) can subscribe. This is the same Redis that ingest→parser uses internally; AI add-on subscribes opportunistically. Don't collapse these into HTTP callbacks.

## Development guidelines

- **Type hints everywhere.** All functions annotated; Pydantic for request/response models.
- **Structured logging.** JSON formatter on Python's `logging` module. Every log line is machine-readable.
- **Ruff for linting/formatting, mypy for type checking.** Both must pass clean before commit.
- **Terse conventions.** Prefer explicit over magic. No clever metaclass tricks.
- **Tests per service.** Each service has its own `tests/` directory. Integration tests use a real Postgres + Redis (not mocks).
- **Self-review protocol.** For non-trivial changes, spawn a subagent to review before committing. Catch your own bugs.

## Directory layout

```
deep-analysis-server/
├── services/
│   ├── gateway/        # Caddy + thin FastAPI shim
│   ├── auth/           # User accounts, sessions, agent registration
│   ├── ingest/         # Upload, dedup, event publish
│   ├── parser/         # Async worker: parse .dat/.log
│   ├── analytics/      # Read-only query API
│   └── web/            # Dashboard UI
├── openapi/            # OpenAPI spec (source of truth)
├── alembic/            # Database migrations (all schemas)
├── docker-compose.yml  # Primary stack (all 6 services + infra)
├── docker-compose.observability.yml  # Optional profile overlay
└── .github/workflows/  # CI (Phase 1 will add workflows)
```

## PKA integration

- Status marker: `agents/riker/status/deep-analysis-server.md` in the PKA repo
- Updates: write `.pka/updates/current.md` at session end per the pka-workspace-updates skill convention
- Full delegation: Scott has granted full delegation on Deep Analysis (inherited from manalog posture)
