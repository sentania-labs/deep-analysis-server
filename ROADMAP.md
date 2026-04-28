# Deep Analysis Server — Roadmap

Active and planned outcomes for the Deep Analysis server. Each outcome is named and scoped so it can be picked up and shipped on its own.

Priority numbers are the default working order, but items are independent unless a dependency is called out — pull anything forward when it's the right time.

Shipped versions are recorded in [CHANGELOG.md](CHANGELOG.md). Tactical bugs live in [GitHub Issues](https://github.com/sentania/deep-analysis-server/issues).

---

## Active

The next 1–3 outcomes to pick up. Priority 1 is current focus.

### 1. Admin user invitation & role management

Extends the existing invite system so admins can invite other admin users, and gives the original installer (the very first registered user, UID=1) tools to manage them.

- **Acceptance criteria:**
  - Admin invites can specify the role at invite time (admin or user); the role is set when the invite is consumed
  - Original installer can demote or delete other admin accounts via the admin UI
  - Demote/delete actions are recorded in an audit log
  - Non-installer admins cannot manage other admins (reuses the existing UID=1 gating pattern)
- **Dependencies:** None
- **Status:** Not started

### 2. CI auto-deploy on release

When the repo has deploy credentials configured, tagging a release automatically updates the running containers on the target host. Silent no-op when credentials are absent so forks still build cleanly.

- **Acceptance criteria:**
  - New CI workflow triggered on release-tag creation
  - When repo or org secrets `DOCKER_HOST` (and a deploy SSH/API key) are present, the job pulls the new GHCR images on the target host and runs `docker compose up -d --force-recreate`
  - Post-deploy smoke check (gateway responds; auth healthy)
  - Rolls back to previous tag on failure and surfaces a clear error
  - When secrets are absent, the job is silently skipped (no failure)
- **Dependencies:** None — parallel work, can run alongside any other outcome
- **Status:** Not started

---

## Next up

In rough priority order. Re-shuffle freely when a different next-pick makes more sense.

### 3. Extended user account actions

Admin tooling to manage individual user accounts beyond the current "delete + reset password" surface.

- **Acceptance criteria:**
  - Admin can disable a user (login refused; existing sessions revoked); ban is the same disable with no expiry
  - Admin can edit any user's name, contact info, and MTGO username
  - Edit and disable actions are recorded in an audit log
- **Dependencies:** Soft dep on #1 for shared role-management UI patterns
- **Status:** Not started

### 4. Cross-user agent management

Extends the existing cross-user revoke functionality to also support key rotation and full deletion.

- **Acceptance criteria:**
  - Admin can trigger a key rotation on any user's agent (revoke existing key, issue new one without deleting the agent)
  - Admin can delete any user's agent entirely
  - Both actions surface in the existing cross-user agents view alongside revoke
- **Dependencies:** None — can run parallel to #3
- **Status:** Not started

### 5. User profile expansion

Lets users record more about themselves than just their email.

- **Acceptance criteria:**
  - User profile fields: name, contact info, MTGO username (in addition to existing email)
  - Users can edit their own values via `/profile/edit`
  - MTGO username has a format-validity check; contact info is free-form
  - New fields surface in the admin user view
- **Dependencies:** None
- **Status:** Not started

### 6. Server config UI: notifications backend

Admin-configurable notification transport, starting with email. Foundation that the future Discord bot ping idea plugs into.

- **Acceptance criteria:**
  - Admin UI to configure SMTP transport (host, port, auth, from-address, TLS mode)
  - "Send test email" button to verify the config end-to-end
  - Backend abstraction is shaped so additional transports (Discord webhook, etc.) can be added later without rewriting
- **Dependencies:** None
- **Status:** Not started

### 7. Game state reconstruction from gamelog

The parser walks an MTGO gamelog and produces a structured game-state object per game. This is the foundation for richer match analysis (#10) and the virtual-replay stretch goal.

- **Acceptance criteria:**
  - Per game: structured state including zones (battlefield, hand, library, graveyard, exile), permanents with attached counters/auras, life totals, mana pool, the stack
  - State is queryable per turn and per player
  - Stored alongside the parsed match record
- **Dependencies:** None
- **Status:** Not started

### 8. Data scraping configuration

Admin UI to define where archetype/decklist data is pulled from. Feeds #9.

- **Acceptance criteria:**
  - Admin can enable, disable, and configure data sources (MTGGoldfish, Untapped, MTGTop8, others)
  - Per-source: credentials if needed, scrape frequency, last-run status, last-success timestamp
  - Data lands in a normalized internal format that the archetype detector consumes
- **Dependencies:** None
- **Status:** Not started

### 9. Archetype detection & management

Admin-managed catalog of MTG archetypes plus automatic classification of decks into them.

- **Acceptance criteria:**
  - Admin-managed archetype catalog: name, format, defining cards, sample decklists
  - Catalog seeded from scraped sources (#8) and editable/overridable by admin
  - Auto-classifier: given a decklist, returns the closest archetype + confidence
  - Surfaces in the macro match view (#11) and per-match analysis (#10)
- **Dependencies:** Depends on #8 when archetype data is sourced externally
- **Status:** Not started

### 10. Match analysis (the core product)

Per-user dashboard for what users actually want from the product: how they're performing.

- **Acceptance criteria:**
  - Performance breakdowns: win rate by archetype played, by archetype faced, by format, by event type, by opponent
  - Time-window filtering, sortable tables, basic charts
  - Read-only API surface so the AI add-on can subscribe and query
- **Dependencies:** Depends on #7 (game state) and #9 (archetypes)
- **Status:** Not started

### 11. Macro match view in admin

System-wide match-and-analysis surface for admins.

- **Acceptance criteria:**
  - All matches across all users, with filtering by user, archetype, format, and date range
  - Drill into a single match for game-by-game state from #7
  - Read-only — no admin-edit on match data
- **Dependencies:** Depends on #10
- **Status:** Not started

---

## Cleanup

Tactical bugs and small tech-debt items. Resolve when convenient or alongside related work.

- **Issue #4** — `change_password` form lost its inline "wrong current password" error after the AuthForbidden refactor. Falls through to a generic banner instead.
- **Issue #5** — wrong template renders on `/profile` subpages when the auth service is unreachable. Returns a generic 503 instead of the contextual `_service_unavailable` template.

---

## Operational blockers

Non-feature items currently blocking releases or deploys. Resolve as they arise; this section is empty when nothing is in the way.

_None._

---

## Future Ideas (Unprioritized)

Parking lot for ideas worth keeping but not currently scheduled. No acceptance criteria yet — promote into Next up when ready to scope.

- **Virtual game replay** — Cockatrice/xmage-style visual battlefield recreation driven by reconstructed game state from #7. Stretch goal.
- **Key card identification in matchup analysis** — surface which cards mattered most in a given matchup (depends on #10)
- **Discord bot integration** — community pings, match summaries, leaderboard posts (depends on #6)
- **AI add-on integration contract** — formalize the events the proprietary AI repo subscribes to (`match.parsed`, `upload.received`, `insight.requested`); lock the payload shapes
- **Production observability profile** — the Loki + Grafana + Prometheus stack is already scaffolded behind `docker-compose.observability.yml`. Activating in prod would need provisioned dashboards, a log retention policy, and alerting rules.
