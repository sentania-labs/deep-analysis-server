# Deep Analysis Server — Roadmap

Active and planned outcomes for the Deep Analysis server. Each outcome is named and scoped so it can be picked up and shipped on its own.

Shipped versions are recorded in [CHANGELOG.md](CHANGELOG.md). Tactical bugs live in [GitHub Issues](https://github.com/sentania-labs/deep-analysis-server/issues).

---

## Shipped

Previously roadmapped items that are now in production.

- **User profile + hero identification** — MTGO username(s), auto-detection from upload frequency, profile edit, hero/opponent attribution at query time. Shipped v0.8.4–v0.9.6.
- **Data scraping configuration** — Admin UI for scraper sources (mtgtop8), run status, last-success timestamps. Shipped v0.9.4.
- **Archetype detection & management** — Admin catalog, ML classifier, metagame browser, per-match archetype display. Shipped v0.9.6.
- **Game state reconstruction** — Per-turn structured snapshots (zones, life, stack), turn viewer in match detail. Shipped v0.9.0.
- **Admin invite + role management** — Role at invite time, agent key rotation/deletion. Shipped v0.9.1.
- **CI auto-deploy on release** — Tag push → Release workflow → Deploy workflow → SSH compose pull/up on edge.int. Shipped v0.7.5.
- **Cross-user agent management** — Admin key rotation, deletion, revoke across all users. Shipped v0.9.1.
- **Admin match detail + review** — Admin-scoped match detail view, hold-reason display, read-only inspection. Shipped v0.9.15.
- **Holding pen for inconclusive parses** — Partial matches flagged `pending_review`, admin accept/reject flow. Shipped v0.9.7.
- **Dashboard date range filter** — Preset dropdown (7/14/30d) + custom From/To date picker, composes with format filter. Shipped v0.9.13.
- **Card analytics engine** — Card performance table with sortable columns, avg cast turn, materialized stats. Shipped v0.9.6–v0.9.12.

---

## Active

The next 1–3 outcomes to pick up.

### 1. Matchup analysis dashboard

The core product value — per-user performance breakdowns beyond the current overview stats.

- **Acceptance criteria:**
  - Win rate by archetype played, by archetype faced, by opponent
  - Archetype-vs-archetype matrix (hero archetype × opponent archetype)
  - Filterable by format and date range (infrastructure already exists)
  - Read-only API surface so the AI add-on can query
- **Dependencies:** Archetype detection (shipped), date filtering (shipped)
- **Status:** Not started

### 2. BNR epoch awareness

Date filtering with awareness of Banned & Restricted changes, so users can scope stats to "current meta" without manually picking dates.

- **Acceptance criteria:**
  - Reference data for B&R announcement dates per format (source: mtg.fandom.com/wiki/Banned_and_restricted_cards/Timeline)
  - Dashboard date filter gains a "Since last B&R" preset per format
  - Optional: admin UI to manage B&R dates manually
- **Dependencies:** Date filter (shipped)
- **Status:** Not started — reference resource identified

### 3. Extended user account actions

Admin tooling beyond the current delete + reset password surface.

- **Acceptance criteria:**
  - Admin can disable/ban a user (login refused, sessions revoked)
  - Admin can edit any user's MTGO username and contact info
  - Actions recorded in audit log
- **Dependencies:** None
- **Status:** Not started

---

## Next up

In rough priority order. Re-shuffle freely.

### 4. Server config UI: notifications backend

Admin-configurable notification transport, starting with email.

- **Acceptance criteria:**
  - Admin UI to configure SMTP transport (host, port, auth, from-address, TLS mode)
  - "Send test email" button for end-to-end verification
  - Backend shaped for additional transports (Discord webhook, etc.)
- **Dependencies:** None
- **Status:** Not started

### 5. Macro match view in admin

System-wide match-and-analysis surface for admins.

- **Acceptance criteria:**
  - All matches across all users, with filtering by user, archetype, format, date range
  - Drill into single match for game-by-game state and turn viewer
  - Read-only — no admin-edit on match data
- **Dependencies:** None (admin match detail already shipped)
- **Status:** Not started

---

## Cleanup

Tactical bugs and small tech-debt items. Resolve when convenient or alongside related work.

- **Issue #4** — `change_password` form lost its inline "wrong current password" error after the AuthForbidden refactor. Falls through to a generic banner instead.
- **Issue #5** — wrong template renders on `/profile` subpages when the auth service is unreachable. Returns a generic 503 instead of the contextual `_service_unavailable` template.

---

## Operational blockers

_None._

---

## Future Ideas (Unprioritized)

Parking lot for ideas worth keeping but not currently scheduled.

- **Virtual game replay** — Cockatrice/xmage-style visual battlefield recreation driven by reconstructed game state. Stretch goal.
- **Key card identification in matchup analysis** — surface which cards mattered most in a given matchup
- **Discord bot integration** — community pings, match summaries, leaderboard posts
- **AI add-on integration contract** — formalize the events the proprietary AI repo subscribes to; lock payload shapes
- **Production observability profile** — Loki + Grafana + Prometheus stack already scaffolded behind compose overlay. Needs dashboards, retention policy, alerting rules.
