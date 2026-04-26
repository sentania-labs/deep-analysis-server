# Changelog

All notable changes to the Deep Analysis server are recorded here. The
project follows [Semantic Versioning](https://semver.org/) loosely while
in pre-1.0; expect minor versions to introduce breaking changes until the
API surface stabilizes.

## Unreleased

### Added

- **W3.5-B: self-service dashboard.** `/profile` (view email + role),
  `/profile/edit` (change email — handles `email_taken` / `invalid_email`),
  and `/profile/agents` (list user-owned agent registrations + revoke). All
  routes flow through the gateway and reuse the existing browser-session
  cookie. Auth service gains `GET /auth/me`, `PATCH /auth/me`,
  `GET /auth/me/agents`, and `POST /auth/me/agents/{id}/revoke`.
- **W3.5-C: admin panel.** `GET /admin/users` (list), `POST /admin/users/{id}/delete`,
  and `POST /admin/users/{id}/reset-password` on the `web` service —
  admin-gated browser surface for the auth service's existing JSON
  `/admin/*` API. Self-delete is short-circuited at the web layer
  (auth still enforces it as the source of truth). Reset-password
  renders the temporary credential inline once for the admin to hand
  off out-of-band.
- **Gateway: `/admin/*` now serves the web admin UI.** Browser
  requests to `https://${DOMAIN}/admin/*` reach the web service;
  the auth JSON `/admin/*` API remains reachable on the internal
  compose network for service-to-service calls and direct ops
  access via `docker compose exec auth curl ...`.
- **`smoke-ui` admin coverage.** `ci/smoke_ui.sh` now seeds
  `testuser@local` via the internal auth admin API, exercises the
  reset-password and delete flows through the web admin UI, and
  asserts the row is gone after delete. Self-delete is verified to
  return 400 inline.

## v0.4.3 — 2026-04-26

### Added

- **W3.5-A: admin UI auth shell.** Login page, dashboard stub, password-change
  flow, and logout for the `web` service. Sessions are tracked via the
  auth service's session cookie (HTTP-only, secure when behind the gateway).
  Templates, static styles, and the `auth_client` HTTP wrapper all land in
  `services/web/`.
- **`smoke-ui` CI job.** End-to-end UI smoke covering login, dashboard
  redirect, password change, and logout against the full compose stack.
  Runs alongside the existing `smoke-e2e` gate.

### Fixed

- **`auth_client` transport-error translation (web service).** `auth_client.login`
  and `auth_client.change_password` now wrap `httpx` transport errors
  (timeouts, connection refused, DNS failures) as `AuthClientError` so the
  caller can distinguish "auth service unreachable" from "credentials wrong"
  without leaking httpx exceptions through the request handler. The
  `password_submit` view catches `AuthClientError` and renders a 503 page
  instead of a 500 stack trace.

## v0.4.2 — 2026-04-24

### Fixed

- **Ingest route prefix.** `/upload` → `/ingest/upload` on the ingest service,
  so requests through the gateway resolve correctly.
- **Service-prefix convention test.** `tests/test_route_prefix_convention.py`
  imports each HTTP service's FastAPI app and asserts every route sits under
  the service's namespace; catches this bug class at unit-test time.

### Added

- **`smoke-e2e` CI gate.** `ci/smoke_e2e.sh` walks the auth + ingest happy
  path through the gateway. The full compose stack runs in CI; PRs only
  merge when this gate is green.
- **PR discipline on `main`.** Non-trivial work lands via feature branch + PR.
  Direct pushes to `main` are reserved for urgent fixes.

## v0.4.1 — 2026-04-24

### Fixed

- **JWT key path config drift.** Aligned `docker-compose.yml`, `.env.example`,
  and `docs/deploy.md` on `/data/secrets/` (the actual mount) instead of
  `/run/secrets/` (Docker secrets syntax that this stack does not use). Added
  `ci/check-compose-paths.sh` as a drift guard.

## v0.4.0 — 2026-04-23

- Initial v0.4.x release. Six-service compose stack
  (gateway, auth, ingest, parser, analytics, web), single Postgres with
  per-service logical schemas, Redis event bus, short-lived JWTs for
  service-to-service auth. Greenfield rewrite — no code carried forward
  from the manalog proof-of-concept.
