# .pka/updates/current.md — deep-analysis-server

Rolling session log. Append at session end per pka-workspace-updates convention.

---

## 2026-04-23 19:23 — w2e-admin-bootstrap  [batch]

**Type:** build

W2e landed on main at `21a7775`. First-boot admin bootstrap + must-change-password flow: new `auth_service.bootstrap` module hooked into a FastAPI lifespan — idempotent (no-op if any enabled admin exists), auto-generate path creates `admin@local` with `secrets.token_urlsafe(18)` and writes plaintext to `/data/secrets/initial_admin.txt` at mode `0600` (directory `0700`) with `must_change_password=true`, env-var path (`DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL`/`_PASSWORD`) creates the admin with scripted credentials and never writes a plaintext file. `/auth/login` now issues a short-lived (`password_change_token_ttl_seconds=300`) scoped JWT (`scope=password-change-only`) when `must_change_password=true`; normal logins unchanged. New `POST /auth/password/change` endpoint accepts both scoped and full-scope tokens, enforces a stub 12-char minimum (returns 400 `weak_password`, TODO comment notes policy-TBD), verifies `current_password` via argon2id (`401 invalid_credentials` on fail), hashes + stores the new password, flips `must_change_password=false`, revokes all user sessions, and deletes `/data/secrets/initial_admin.txt` when rotating `admin@local`. `get_current_user` now rejects scoped tokens with `403 password_change_required` (applies to `/auth/me` and all `/admin/*` via `require_admin`); `get_current_user_any_scope` is a parallel dep used only by the password-change endpoint. `jwt_issue.issue_access_token` gained optional `scope` + `override_ttl_seconds` params; `AuthSettings` gained the bootstrap env vars (via `AliasChoices` accepting both `DEEP_ANALYSIS_*` and `DA_*` names, `populate_by_name=True` so tests can construct directly) and `initial_admin_secret_path`. Compose: new `auth_secrets` named volume mounted at `/data/secrets` on the auth container; `.env.example` + `docker-compose.yml` thread the bootstrap env vars through commented/default-empty. Tests: 6 bootstrap tests (default path, idempotency, no-op when admin exists, disabled-admin-doesn't-count, env-var-path, file permissions `0o600`), 8 password-change tests (scoped login/TTL, /auth/me + admin rejection, happy path, subsequent-login full-scope, weak-pw, wrong-current-pw, initial_admin.txt deletion), plus one extension on `test_admin_auth.py` asserting admin endpoints 403 on scoped tokens — 71 auth tests + 10 common tests green locally; ruff + mypy clean. Docs: `admin-bootstrap.md` replaced the W2e STUB preamble with the full flow incl. an inline ASCII auth-JWT-flow diagram (Excalidraw stub deferred); `deploy.md` gained a "First run" section covering both bootstrap paths + how to retrieve the initial password. CI green on run 24865636952 (11/11 jobs). W2 now complete.

---

## 2026-04-23 22:33 — w2b-auth-credential-flow  [batch]

**Type:** build

W2b shipped on main at `d04332a`. Auth service now owns credential flow: argon2id hashing (OWASP m=64MiB,t=3,p=4), RS256 15-minute access tokens with 30-day opaque refresh tokens (SHA-256 at rest), login/refresh/logout/me endpoints with async SQLAlchemy + `get_current_user` dep, `auth_service.keygen` for operator key generation, env + docs wired. 29 auth tests + 10 common tests green on real Postgres, ruff + mypy clean, docker build verified. CI run: https://github.com/sentania-labs/deep-analysis-server/actions/runs/24864118525. Collateral: migrated root dev deps to `[dependency-groups]` and switched CI to `uv sync --all-packages --dev` (uv 0.10 quietly stopped installing `[project.optional-dependencies].dev` under `--dev`, which had silently broken lint/typecheck/test-common on main); also deflakened `tests/common/test_jwt_verify.py`'s tamper test.

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

---

## 2026-04-24 00:08 — w2d-admin-endpoints  [batch]

**Type:** build

W2d landed on main at `f8df65c`. Admin endpoints + admin-claim enforcement: new `require_admin` dep (403 for authed-non-admin, 401 for unauthed via `get_current_user`), dedicated `auth_service.admin` router with `GET/POST/PATCH/DELETE /admin/users`, `/admin/users/{id}/reset-password`, `/admin/users/{id}/revoke-sessions`, `GET /admin/agents`, `POST /admin/agents/{id}/revoke`, `POST /admin/agents/cleanup-stale`. Lockout guards enforced: `cannot_disable_self`, `cannot_delete_self`, `cannot_demote_last_admin`, plus a defense-in-depth `cannot_delete_last_admin` that is structurally unreachable under normal flow (documented in completion note). Schemas in `schemas.py` stay free of hashes/tokens. 19 new tests (5 claim-gate + 14 behavioral) plus 37 pre-existing = 56 auth tests green on real Postgres; 10 common tests green; ruff + mypy clean. Docs: `admin-bootstrap.md` gained a full "Admin operations" section with curl for every endpoint, `deploy.md` gained a lockout-protection summary. Added `TODO(W5): openapi-drift CI job` comment; `openapi/auth.yaml` deliberately not created this session. CI run: https://github.com/sentania-labs/deep-analysis-server/actions/runs/24865182550 — all 11 jobs green. W2e (first-admin bootstrap flow) is next.

---

## 2026-04-23 23:33 — w2b-auth-credential-flow  [batch]

**Type:** build

W2b landed on main at `d04332a`. Argon2id password hashing (OWASP m=64 MiB, t=3, p=4), RS256 JWT access tokens (15 min), opaque refresh tokens stored SHA-256-hashed (30 d) with rotation on `/auth/refresh` (old session revoked, new pair minted), `POST /auth/login|refresh|logout` + `GET /auth/me`, `get_current_user` dep that verifies the JWT via `common.jwt_verify` and re-validates the session row, keygen helper (`python -m auth_service.keygen --out <dir>`). pytest-asyncio tests against real postgres cover passwords/jwt_issue/login/refresh/logout. Four CI-fix follow-ups were needed after the initial push (JWT key env vars via `GITHUB_ENV`, dev deps under `[dependency-groups]`, deterministic tamper-signature test — last-char flips are flaky under base64url padding-bit equivalence, `uv sync --all-packages` so workspace members are importable); all labelled `W2b CI fix:` so the history reads as one W2b band. CI green on run 24864118525 (11/11 jobs). W2c (admin endpoints) is next.

---

## 2026-04-24 19:57 — w3-ingest-service  [batch]

**Type:** build

W3 landed on main. Ingest service now owns `POST /ingest/upload`: agent-bearer-token auth (refactored — `AuthenticatedAgent` + SHA-256 token hashing moved into `common/agent_auth.py` + `common/token_utils.py` so auth and ingest share one shape; auth's `registration.hash_api_token` thinly re-exports the shared helper to keep existing call sites working), multipart upload with `file` + optional `original_filename` + `content_type` form fields (enum `match-log|decklist|unknown`), sha256 content hash, 413 on oversize (Content-Length short-circuit + post-read re-check against `DA_INGEST_MAX_FILE_BYTES`), content-addressed raw archive under `<root>/<sha[0:2]>/<sha[2:4]>/<sha>.<ext>` with atomic write-to-temp + fsync + rename (ENOSPC surfaces as 507), `INSERT ... ON CONFLICT DO NOTHING RETURNING` on `ingest.game_log_files` to detect dedup vs. fresh, always-record `ingest.user_uploads` row for per-user attribution, `file.ingested` published to Redis only on fresh content (skipped on dedup, best-effort — log-and-continue if publish fails). Response: `{sha256, size_bytes, deduped, upload_id}`.

New service-scoped Alembic head under `services/ingest/alembic/` creates `ingest.game_log_files` (sha PK, CHECK on content_type IN match-log/decklist/unknown, size ≥ 0 CHECK) and `ingest.user_uploads` (BigInteger PK, FK to game_log_files, FK to auth.users ON DELETE CASCADE, FK to auth.agent_registrations ON DELETE CASCADE, composite index on user_id+uploaded_at). New root migration `002_cross_schema_grants` grants REFERENCES on auth.* to the ingest role via ALTER DEFAULT PRIVILEGES so the cross-schema FKs can be created.

`common.events.FileIngestedPayload` reshaped: `user_id: int` (was str), added `agent_registration_id` (UUID str) + `content_type`, renamed `received_at`→`uploaded_at`, dropped `filename` (attribution lives in DB, not the event).

19 new ingest tests + 81 auth/common tests = 100 green on real Postgres + Redis. Tests cover: storage layer (roundtrip, idempotency, ENOSPC→InsufficientStorageError), model CHECKs + cross-schema FK cascades, cross-schema grants resolve, upload happy path + 401 (missing/bad token) + 413 + 400 (missing file) + dedup (second upload records attribution, suppresses event) + content-type enum acceptance/rejection.

Lint/typecheck housekeeping: tightened `tool.mypy` with `explicit_package_bases=true` and excluded `services/*/alembic/` (two env.py modules collide otherwise); pytest `--import-mode=importlib` so auth/tests and ingest/tests don't clash on duplicate basenames (`test_models.py`); replaced the empty `tests/__init__.py` files with importlib-mode collection; `ContentType` → `StrEnum` (UP042); `contextlib.suppress` in storage cleanup (SIM105). CI workflow gained ingest alembic head + `pytest services/ingest/tests/` steps.

Docker build: `deep-analysis-ingest` image builds cleanly from the committed Dockerfile.

---

## 2026-04-23 22:35 — v0.4.0-tag-move-and-release  [batch]

**Type:** release

Moved the `v0.4.0` tag from `3c662c3` (Caddyfile-flip, push:false era) to `ab439c3` (push:true enable). Force-deleted remote tag, recreated locally, pushed; the prior Release run was a no-op so nothing was clobbered. Tag push triggered Release workflow run [24870809213](https://github.com/sentania-labs/deep-analysis-server/actions/runs/24870809213) — all 5 publish jobs (auth/ingest/parser/analytics/web) green in ~45 s each. GHCR verification: all 5 images present at `:v0.4.0` and `:latest`; **`:0.4.0` (no leading v) is MISSING for all 5** — confirmed tech-debt: `release.yml` does not strip the leading `v` from `github.ref_name`. Not fixed this session, deferred as a D-series item. Package visibility: all 5 packages are PUBLIC (anonymous bearer-token manifest pull returns 200 for each); toolkit deploy will pull without auth. No deviations otherwise; no code changes in-repo.

---

## 2026-04-24 03:25 — gateway-caddyfile-prod-flip  [batch]

**Type:** config

Flipped `gateway/Caddyfile` from local-dev (`tls internal` + `deepanalysis.local`) to production ACME config driven by `GATEWAY_DOMAIN` and `DEEP_ANALYSIS_ACME_EMAIL` env vars. Committed `3c662c3` on main; CI run https://github.com/sentania-labs/deep-analysis-server/actions/runs/24870555217 — all 11 jobs green including `compose-smoke`. Caddyfile uses `{$VAR}` parse-time substitution (not `{env.VAR}`, which is runtime-only and fails in site-address / `tls` argument positions — caught by `caddy validate` before push). Config-only change; nothing under `services/` touched. `.env.example` gained a `Caddy / ACME` section with sentania.net defaults and an `ops@example.com` placeholder; `docker-compose.yml` gateway `environment:` now passes the two new vars. `docs/deploy.md` rewrote the "TLS modes" section (no more fleet-Caddy talk) and added a new "Behind a reverse proxy" section with a `ports: !reset []` / `expose:` + external network override sketch for fleet-caddy/Traefik topologies. Prerequisites gained a public-DNS bullet. New `ci/docker-compose.ci.yml` + `ci/Caddyfile.ci` overlay pins `GATEWAY_DOMAIN=deepanalysis.local` and swaps in a `tls internal` Caddyfile for CI's compose-smoke job (runners have no public DNS, so ACME would hang); `.github/workflows/ci.yml` compose-smoke now runs `docker compose -f docker-compose.yml -f ci/docker-compose.ci.yml up/down` and seeds the CI env vars into `.env`. Verified merge behavior via `docker compose config` — base Caddyfile bind-mount is replaced at `/etc/caddy/Caddyfile` by the CI bind, `caddy_data` named volume preserved. Self-review via `superpowers:code-reviewer` caught one minor nit (Quickstart heading still said "(dev)"), fixed before commit. Follow-up worth tracking: `docs/admin-bootstrap.md` still has ~10 `https://deepanalysis.local -k` curl examples that are now inconsistent with the ACME-by-default posture — not blocking, out of this scope.

## 2026-04-23 22:54 — gh-release-workflow  [batch]

**Type:** status

Added `create-release` job to `.github/workflows/release.yml` (softprops/action-gh-release@v2, `needs: publish`, job-level `contents: write`). YAML validated, committed as 9dac5ca, pushed to main. Backfilled v0.4.0 GitHub Release entry via `gh release create` with GHCR pull coordinates in body; `gh release list` confirms v0.4.0 marked Latest. No blockers.

## 2026-04-24 04:40 — gateway-routing-fix  [batch]

**Type:** status

Fixed gateway routing bug: Caddyfile used `handle_path` for /auth, /ingest, /analytics which stripped the prefix before proxying, breaking every real endpoint (backends register full paths). Swapped to `handle`. Also re-pointed /admin/* from web:8000 stub to auth:8000 until W6 is built. Commit fac34b2 pushed direct to main, CI run 24872476867 green. Hot-reloaded on docker.int (had to checkout main from detached HEAD first). Probes confirm routing works: GET /auth/login → 405, POST /auth/login → 422 (real handler), GET /admin/users → 401. D-series debt flagged: compose-smoke only hits /healthz, which is why the routing regression wasn't caught in CI — recommend extending smoke to probe /auth/login + /admin/users. Completion note at team/completions/2026-04-24-0439-riker-deep-analysis-server-gateway-routing-fix.md.

## 2026-04-24 04:48 — pwchange-500-prod-fix  [batch]

**Type:** status

Production `POST /auth/password/change` 500 on docker.int fixed — root cause was `.env` drift, not code. `/srv/deep-analysis-server/.env` had `DA_JWT_PUBLIC_KEY_PATH=/data/secrets/jwt_public.pem` (and matching private-key path) but `docker-compose.override.yml` bind-mounts both keys to `/run/secrets/`. Login worked because the override explicitly sets `DA_JWT_PRIVATE_KEY_PATH=/run/secrets/jwt_private.pem` in the auth env block, overriding `.env`; the public-key var was only defaulted in the base compose (`:-/run/secrets/...`) so `.env`'s wrong value won inside the container. `JWTVerifier.__init__` eagerly opens the file in `common/jwt_verify.py:17` → `FileNotFoundError: '/data/secrets/jwt_public.pem'` → 500 from every JWT-verification path (password-change surfaced first; `/auth/me`, `/admin/*`, and ingest/parser/analytics/web were all latently broken — same env var wrong across all five app containers). `.env.example` and `docs/deploy.md` in the repo were already correct; only prod had drifted. Patched the prod `.env` to `/run/secrets/*.pem` + refreshed the misleading comment, backup at `.env.bak.2026-04-24-pwchange-fix`, `docker compose up -d` recreated all five app containers, all healthy. Four-step E2E verification against `https://deepanalysis.sentania.net` green: login→scoped token (200), password-change (204, was 500), login→unscoped token (200), admin-create-user (201). Used `testPass1234!` for new admin pw instead of the prompt's `test1234!` (9 chars — below server's 12-char min; server now returns 400 weak_password instead of 500, which is itself proof the root cause is gone). **New prod admin password is `testPass1234!` — Scott should rotate.** Side effect: `testuser@local` (id=2) created in prod auth.users from step 4 — deletable via `DELETE /admin/users/2`. No repo code changed, no CI run, no commit. D-series debt flagged (second instance this session): `compose-smoke` only hits `/healthz`, so JWT-verify path mismatches slip through; also no compose-config linter cross-checks `DA_JWT_*_KEY_PATH` env vars against declared mounts. Unit `test_password_change.py` passed because its conftest sets `DA_JWT_PUBLIC_KEY_PATH` to a valid file — test/prod config divergence is the gap. Completion note at `team/completions/2026-04-24-0448-riker-deep-analysis-server-pwchange-500-fix.md`.

## 2026-04-24 05:37 — v0.4.1 JWT key path drift fix  [batch]

**Type:** status

Cut v0.4.1. Root cause of the v0.4.0 operator-deploy crash: `auth` service in `docker-compose.yml` was missing `DA_JWT_PRIVATE_KEY_PATH` (required pydantic field, no default), and every service's `DA_JWT_PUBLIC_KEY_PATH` default was `/run/secrets/jwt_public.pem` — Docker Compose *secrets* syntax that requires a top-level `secrets:` block this stack does not use. The actual mount is the `auth_secrets` named volume at `/data/secrets`; operator's `.env` override to `/run/secrets/...` had the same underlying problem. Aligned compose + `.env.example` + `docs/deploy.md` to `/data/secrets/...`; added `ci/check-compose-paths.sh` drift guard (greps for forbidden paths, asserts auth has the private key var, renders compose config when docker is available) wired into the lint job. Version bumped 0.4.0.dev0 → 0.4.1. Auth + ingest tests green. CI green on main, v0.4.1 tagged, release workflow published all five GHCR images and created GitHub Release at https://github.com/sentania-labs/deep-analysis-server/releases/tag/v0.4.1.
