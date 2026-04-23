# .pka/updates/current.md — deep-analysis-server

Rolling session log. Append at session end per pka-workspace-updates convention.

---

## 2026-04-23 00:44 — claude-md-event-topics  [batch]

**Type:** status

Added design decision #11 and a new "Event topics" subsection to CLAUDE.md documenting the standard Redis event topics (`match.parsed`, `upload.received`, `insight.requested`) for cross-service consumption, with TBD payload shapes. Committed to master as 14d6551.

---

## 2026-04-23 21:00 — w1a-infra-slice  [batch]

**Type:** build

Replaced the placeholder docker-compose.yml with a working infra-only slice: postgres:16, redis:7-alpine (no persistence), and caddy:2-alpine gateway with a `/health` endpoint. Application services (auth/ingest/parser/analytics/web) are commented-out TODO stubs for W1b. Added `gateway/Caddyfile` (auto_https off, health handler, commented reverse_proxy routes for the topology), `.env.example` (POSTGRES_USER/POSTGRES_PASSWORD only), and a README Quickstart section. Verified: `docker compose config` passes, all three containers come up healthy. Host port 443 is held by pka-dashboard on this box so end-to-end `/health` was verified via a temporary `18080:80` override; the committed 80/443 binding is correct for deployment targets.

---

## 2026-04-23 21:05 — w1b-i-common-package  [batch]

**Type:** build

Shipped the shared `common/` Python package on main at `43e7c16`. Rewrote `pyproject.toml` with full runtime deps (fastapi, sqlalchemy[asyncio], asyncpg, alembic, structlog, prometheus-client, redis, pyjwt[crypto], httpx, pydantic, pydantic-settings) and a `dev` extra (pytest, pytest-asyncio, ruff, mypy); added ruff/mypy/pytest tool config and hatchling wheel targeting `common`. Modules: `logging.py` (structlog JSON, idempotent), `metrics.py` (Prometheus `/metrics` + per-service request Histogram), `jwt_verify.py` (RS256 public-key verifier, raises `InvalidTokenError`), `redis_client.py` (singleton async pool + `EventPublisher`), `events.py` (topic constants + TypedDict payload stubs — the AI-subscription seam), `settings.py` (`BaseServiceSettings` with `DA_` env prefix). Tests in `tests/common/` cover logging, event constants, JWT verify (valid / tampered / expired with real RSA keypair via `cryptography`), and settings env binding — 10 passed, ruff clean, mypy clean. Pushed to origin/main direct per rapid-build convention.

---

## 2026-04-23 21:11 — w1b-ii-alembic-initial-schema  [batch]

**Type:** build

Landed the Alembic skeleton and `001_initial_schema` migration on main at `d252f95`. `alembic.ini` with placeholder sqlalchemy.url (env.py overrides) and standard logging sections; `alembic/env.py` reads `DATABASE_URL` from the process env directly (no pydantic-settings dependency for the migration entrypoint) and uses the sync psycopg driver — `target_metadata = None` at the root head since services register their own from W2. Revision 001 creates four logical schemas (`auth`, `ingest`, `parser`, `analytics`) and four NOLOGIN service roles (`deep_analysis_auth/ingest/parser/analytics`) via DO/EXCEPTION blocks for idempotency, plus cross-schema grants (ingest→auth SELECT for user FK validation, parser→ingest SELECT for game_log_files/user_uploads, analytics read-only across all three for attribution joins) and ALTER DEFAULT PRIVILEGES for future tables. Role password assignment is deliberately out-of-band — migrations stay free of secrets; a W1b-iii or deploy bootstrap step will ALTER ROLE ... PASSWORD from env vars. Supporting updates: `psycopg[binary]>=3.2` added to pyproject deps, `DATABASE_URL` added to `.env.example`, new `docs/migrations.md` covering the multi-head architecture and common commands. Verified end-to-end: upgrade → 5 schemas + 4 roles present, downgrade → clean, re-upgrade idempotent. Ruff clean. Note for W2: compose's postgres container isn't port-published to the host — had to target the container IP via `docker inspect`; consider publishing 5432 or a `migrate` profile when W1b-iii lands.

## 2026-04-23 21:29 — w1c-i-ci-workflows  [batch]

**Type:** build

W1c-i landed on main at `a47e4b4` and pushed. Added `.github/workflows/ci.yml` with six fork-gated jobs: `lint` (ruff check + format --check), `typecheck` (mypy common/ + services/), `test-common` (pytest tests/common/), `test-integration` (postgres:16 + redis:7 GH Actions service containers, `alembic upgrade head`, pytest tests/integration/ placeholder), `docker-build` (matrix across the five service Dockerfiles, `push: false` via `docker/build-push-action@v5`), and `compose-smoke` (adds deepanalysis.local to /etc/hosts, `docker compose up -d --build`, 60 s poll loop on `curl -sk https://deepanalysis.local/auth/healthz`, asserts 200 on auth/ingest/analytics/web, tears down with `-v`). Every PR-triggered job carries the `sentania-labs` fork gate. `.github/workflows/release.yml` — tag-triggered GHCR matrix build skeleton, `push: false` pending namespace go-live, tags `ghcr.io/sentania-labs/deep-analysis-<svc>:<tag>|latest`. openapi-drift deferred to W5 (comment in ci.yml). Supporting: `tests/integration/__init__.py` + placeholder `test_migrations.py`; ruff auto-fix picked up import sort in five service main.py stubs and a few common tests; uv.lock drifted slightly from `uv sync --dev`. No deviations — alembic env.py already reads DATABASE_URL lazily so no guard was needed. Local verification green: ruff clean, format clean, mypy clean, pytest 11/11, `docker compose build` all 5 images built. Next: W1c-ii (docs stubs), W1c-iii (diagram-drift CI).

---

## 2026-04-23 21:25 — w1b-iii-complete  [batch]

**Type:** status

W1b-iii landed on main at `c69ebd9` and pushed. Five FastAPI service stubs (auth/ingest/parser/analytics/web) + compose wiring + Caddy gateway activation; all 8 containers come up healthy and routed healthz through the gateway returns the correct service JSON for auth/ingest/analytics. Postgres now publishes `127.0.0.1:5432:5432`. Two deviations from the plan worth noting: added `common/pyproject.toml` because plan's `pip install ./common/` had no buildable project there, and Caddyfile `:80` block uses `handle { redir … }` instead of bare `redir /*` (bare form caught `/health` and broke the gateway healthcheck via SSL redirect to the localhost cert). One flag for Scott, not blocking: pka-dashboard currently holds host `:443`, so the committed compose can't be brought up on this dev box as-is — verification ran with a gitignored `docker-compose.override.yml` remapping gateway to 8080/8443. Completion note + status marker updated. Next: W1c (CI + docs).

## 2026-04-23 22:09 — w2a-auth-db-layer  [batch]

**Type:** build

W2a landed on main. Added a service-scoped Alembic head under `services/auth/alembic/` (own `alembic.ini`, own `version_table=auth_alembic_version` in the auth schema, `include_name` hook scoping autogenerate to the auth schema only) and SQLAlchemy models in `services/auth/auth_service/models.py`: `User` (auth.users — functional unique index on `lower(email)` avoids a citext dependency; role CHECK user|admin), `Session` (auth.sessions — UUID PK via `gen_random_uuid()`, FK to users with ON DELETE CASCADE, unique refresh_token_hash, composite index on (user_id, expires_at)), `AgentRegistration` (auth.agent_registrations — same UUID/FK pattern, unique api_token_hash). Migration `001_auth_tables.py` enables `pgcrypto` (not dropped on downgrade — cluster-wide). Added sqlalchemy/alembic/psycopg to `services/auth/pyproject.toml`; wired `from auth_service import models as _models  # noqa` into main.py. 5 integration tests in `services/auth/tests/test_models.py` using real postgres via DATABASE_URL (roundtrip / email-unique / role-CHECK / FK cascade / token-unique). Updated `docs/migrations.md` with a "Service-scoped heads" section and the concrete auth upgrade/downgrade invocations. Verified end-to-end against compose postgres: root head → auth head → `\dt auth.*` shows users/sessions/agent_registrations, downgrade base reverses cleanly, re-upgrade idempotent, all 5 tests pass. Ruff clean, mypy clean. Out-of-scope items (endpoints, JWT, bootstrap, argon2) untouched — those arrive in W2b+.

---

## 2026-04-23 16:36 — W1c-ii docs + excalidraw vendor  [batch]

**Type:** status

W1c-ii landed on main at commit `a93075a`. Created docs stubs (`deploy.md`, `admin-bootstrap.md`, `backup.md`, `events.md`; left `migrations.md` alone) and vendored the excalidraw renderer into `docs/diagrams/` with a local `pyproject.toml` (renamed to `deep-analysis-diagrams`), `render.py`, `render_template.html`, and a new `README.md`. `uv sync` + `playwright install chromium` verified clean; chromium cached out-of-tree. Added `extend-exclude = ["docs/diagrams"]` to root ruff config so vendored code isn't linted. Root `README.md` now has a Documentation section. Completion note dropped at `team/completions/2026-04-23-1636-riker-deep-analysis-server-w1c-ii.md`. No blockers.
