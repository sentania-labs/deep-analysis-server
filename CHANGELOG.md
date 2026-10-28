# Changelog

All notable changes to the Deep Analysis server are recorded here. The
project follows [Semantic Versioning](https://semver.org/) loosely while
in pre-1.0; expect minor versions to introduce breaking changes until the
API surface stabilizes.

## Unreleased

### Added

- **Bounded retry for transient object-store errors in the parser (#158).**
  `ParserConsumer.handle_event` and `handle_decklist_event` no longer skip a
  file on a single storage error. A transient failure (unreachable store,
  timed-out read) now queues the file for retry with capped, jittered
  exponential backoff — `min(cap, base * 2**(n-1))`, then scaled by a random
  factor — and the consumer loop re-attempts it once its backoff elapses,
  alongside every other in-flight file. The window and both backoff bounds are
  settings: `DA_STORAGE_RETRY_WINDOW_SECONDS` (default 86400, i.e. 24 hours),
  `DA_STORAGE_RETRY_BASE_DELAY_SECONDS` (1) and
  `DA_STORAGE_RETRY_MAX_DELAY_SECONDS` (60). A file that runs out its window
  fails visibly: it is logged at ERROR with its sha256 and the outage
  duration, and counted (match logs and decklists alike) by
  `parser_storage_giveups_total`; no holding-pen row is written and the
  backfill scan parses the file once storage recovers.
  `parser_storage_retries_total` counts deferred attempts. Both counters are on
  the metrics port. The retry queue is process-local, so a restart restarts
  the window for in-flight files; the durable `parser.*` rows and the backfill scan remain the source
  of truth. Non-transient reads keep their previous handling: a missing object
  or an oversized one is logged and skipped without a retry.

- **Matchup key cards and sideboard effectiveness (#129).** A new read-only
  `GET /analytics/stats/matchups/cards` takes a `hero_archetype_id` and an
  `opponent_archetype_id` (both required) and the usual `format`, `date_from`
  and `date_to`, scoped to the caller with pending-review matches left out, and
  returns two lists built from the hero's rows in `analytics.card_game_stats`.
  `cards` gives each card's games seen (decided games only), wins, losses, win
  rate, 95% Wilson range, casts, a game 1 / games 2+ split and a `low_sample`
  flag. `sideboard` lists cards seen in a game 2 or later of a match whose game 1
  they were not seen in, with the win rate over those games, the win rate over
  the matchup's other decided post-board games (`baseline_*`, which excludes
  every post-board game the card appeared in) and `delta` in percentage points;
  `delta` is null with no baseline game, and `low_sample` is set when either
  side has fewer than `min_sample` games. A card never seen in any game 1 is
  always a sideboard candidate, and matches that ended after game 1 add card
  rows but no sideboard games. On the web, choosing both archetypes on
  `/matchups` shows Key cards and Sideboard effectiveness tables under the
  matrix (each matrix row links there), with low-sample rows dimmed and badged
  and card names linking to card search. This completes #129. Card rows come
  only from matches already materialized into `card_game_stats`, and the
  sideboard baseline is drawn from those same matches. The response's
  `matches` stays the total in scope and `matches_with_card_data` counts the
  ones the card tables are built from; `/matchups` reads "across N of M
  matches with card data" when they differ. A card counts as "not in game 1"
  when it was not logged in that game, so a card that stayed in the library all
  game reads as sided in.

- **Matchup pre-board / post-board split and drill-down links (#129).** Each
  cell of `GET /analytics/stats/matchups` now carries `preboard` (game 1) and
  `postboard` (games 2 and up) objects with `games`, `wins`, `losses`, win
  rate, the 95% Wilson range and their own `low_sample` flag, judged on that
  split's game count against the same `min_sample`. Games without a recorded
  winner are skipped; a cell whose matches all ended after game 1 has an empty
  post-board (0 games, low sample) rather than a 0% win rate. `/stats/matches`
  and `/stats/by-opponent` accept `hero_archetype_id` and `opponent_archetype_id`
  with the same hero rule the matrix uses, so a cell's matches can be listed
  exactly. On the web `/matchups` table the match count and the win and loss
  figures link to Match History narrowed to that archetype pair (format and date
  range kept), and Match History shows a "clear matchup filter" note while one is
  active. Per-matchup key cards and sideboard effectiveness follow in the entry above.

- **Matchup matrix API and dashboard table, first slice (#129).** A new
  read-only `GET /analytics/stats/matchups` returns one cell per hero
  archetype x opponent archetype pair: matches, wins, losses, draws, win rate
  (wins over decided matches, like `/stats/by-opponent`), a 95% Wilson range
  around it, and a `low_sample` flag for cells under `min_sample` (5) decided
  matches. It honours `format`, `date_from` and `date_to` through the same
  match loader as by-opponent, can be narrowed with `hero_archetype_id` and
  `opponent_archetype_id`, is scoped to the caller, and leaves out
  pending-review matches. Matches missing either archetype are reported as
  `unclassified_matches` rather than silently dropped. The web service gains a
  `/matchups` page ("Matchups" in the sidebar) with those filters, low-sample
  rows dimmed and badged, and archetype names that drill down by narrowing the
  matching filter. Game-number and pre/post-board splits, per-matchup key
  cards and sideboard effectiveness are still to do.

- **The X-Request-ID header is logged and echoed by every service (#182).**
  A shared ASGI middleware, `common.request_id.RequestIDMiddleware`, reads the
  `X-Request-ID` that the gateway stamps on each request (generating a UUID4
  when it is missing), adds it as `request_id` to every structured log line
  written while that request is handled, and returns it on the response. It is
  registered on the auth, ingest, parser, analytics and web apps. The web
  service forwards the header on its httpx calls to the backend services, so
  a browser request can be traced through the gateway and every service it
  reaches with one id. Non-http ASGI scopes (lifespan, websocket) pass through
  the middleware untouched, so service startup hooks keep running.
  The uvicorn access line now carries the id too: `common.logging` installs
  `RequestIdAccessFormatter`, a `uvicorn.logging.AccessFormatter` that appends
  `request_id=<id>` to the usual
  `INFO: 10.0.0.5 - "GET /analytics/stats HTTP/1.1" 200 OK` line (`-` only for
  a line written outside the middleware), so a reverse-proxy log line matches a service access line by
  that one value. Only the request id is added; no other header is logged.

### Fixed

- **Analytics background loops are safe to run on more than one replica
  (#155).** The Scryfall sync, the card stats materializer and the card
  stats backfill scan now run under the shared Postgres job lock
  (`common.job_lock`, the mechanism the scrapers got in #127), each under
  its own name in `analytics.scraper_runs`: `scryfall_sync`,
  `card_materializer`, `card_stats_backfill`. Two analytics replicas
  booting together run each of them once; a replica killed mid-run is
  replaced after the lock's stale window (`STALE_AFTER_SECONDS`, 180s).
  The materializer is held as a long-lived lease with the other replica
  standing by (new `run_locked_standby`); the sync and the backfill are
  locked per pass. The cache invalidator is deliberately left unlocked,
  because every replica serves the cache and a duplicate key delete is a
  no-op. The per-loop decisions are written down in the
  `analytics_service.main` module docstring and in `docs/deploy.md`.
  `POST /analytics/admin/sync-cards` now takes the same lock before
  answering 202 and answers 409 `sync_already_running` while a sync is
  live, as the scraper triggers already did; the admin Cards page shows
  "already running" instead of "Sync started" in that case. Housekeeping
  on the way: the empty `__init__.py` markers in the analytics, parser
  and web test directories are gone, so the suites can be collected in a
  single pytest invocation (pytest 9 refused the duplicate
  `tests.conftest` they produced); CI's per-suite runs are unaffected.

### Security

- **Browser execution boundary hardened (#126).** The gateway CSP is now
  `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'
  data:; font-src 'self'; connect-src 'self'; object-src 'none';
  base-uri 'self'`: no `'unsafe-inline'`, no
  `'unsafe-eval'`, no CDN or Google Fonts origin. Tailwind is compiled ahead
  of time (`services/web/build-css.sh`) instead of the play CDN; htmx,
  Alpine.js (its CSP build), Chart.js, and the Inter and JetBrains Mono fonts
  are vendored under
  `services/web/web_service/static/` and pinned in
  `static/vendor/manifest.json`; every executable inline script, `on*=`
  handler, and `style=` attribute in the templates moved to `static/js/`.
  Card art on `/cards` stays blocked by `img-src`, unchanged from `main`;
  that is a pre-existing product bug tracked as its own follow-up issue
  (#173), not part of this hardening.
  New guards: `services/web/tests/test_csp_hygiene.py`, the `frontend-assets`
  CI job (stylesheet drift), and `ci/browser/smoke_csp.py`, a Playwright pass
  over every page and control that fails on any CSP violation (part of
  `bash ci/smoke.sh ui`). Rollback is reverting `gateway/Caddyfile` and the
  web service templates and static files together; nothing else depends on
  them.

## v0.7.12 — 2026-05-10

### Added

- **Agent registration code UI.** Profile agents page (`/profile/agents`) now
  has a "Register New Agent" section with a "Generate Registration Code" button.
  On click, the code is displayed prominently with its 10-minute expiry and
  copy instructions.

- **`POST /auth/agent/register-with-credentials`.** One-step agent registration
  endpoint: accepts `{email, password, agent_name, client_version}`, authenticates
  the user, and returns `{agent_id, api_token, user_id}` — same response as the
  code-based flow. Allows agents to offer username/password registration without
  a separate UI step. Rejects admin users (same guard as existing register endpoint).

## v0.7.5 — 2026-05-10

### Fixed

- **fleet-caddy networking: 503 after CI deploy.** Added `edge-slots` as an
  external network in `docker-compose.yml` and attached `web`, `auth`, `ingest`,
  and `analytics` services to it. Rewrote the fleet-caddy caddy snippet to route
  directly to service containers (`deep-analysis-<svc>-1`) instead of through the
  internal gateway — fleet-caddy handles TLS, so routing two Caddy instances in
  series was unnecessary. The fix is permanent: `compose up -d` now attaches
  services to `edge-slots` automatically on every deploy.

## v0.5.0 — 2026-04-26

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
