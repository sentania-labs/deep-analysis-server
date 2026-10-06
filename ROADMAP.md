# Deep Analysis Server — Roadmap

Active and planned outcomes for the Deep Analysis server. Each outcome is named and scoped so it can be picked up and shipped on its own.

Shipped versions are recorded in [CHANGELOG.md](CHANGELOG.md). Tactical bugs live in [GitHub Issues](https://github.com/sentania-labs/deep-analysis-server/issues).

The last published release is `v0.11.0`. `main` currently sits 10 commits ahead of that tag with real, tested work (the object-storage migration, the force-reparse data-integrity fix, and the CSP hardening below): none of it has gone out in a release yet, so it is not running anywhere until the next `vX.Y.Z` tag is cut.

---

## Shipped

Previously roadmapped items that are now in production.

- **User profile + hero identification** — MTGO username(s), auto-detection from upload frequency, profile edit, hero/opponent attribution at query time. Shipped v0.8.4–v0.9.6.
- **Data scraping configuration** — Admin UI for scraper sources (mtgtop8), run status, last-success timestamps. Shipped v0.9.4.
- **Archetype detection & management** — Admin catalog, ML classifier, metagame browser, per-match archetype display. Shipped v0.9.6.
- **Game state reconstruction** — Per-turn structured snapshots (zones, life, stack), turn viewer in match detail. Shipped v0.9.0.
- **Admin invite + role management** — Role at invite time, agent key rotation/deletion. Shipped v0.9.1.
- **CI auto-deploy on release (retired)**: Shipped in v0.7.5 and retired by
  #137 when rollout ownership moved to `lab-deployment` and Argo CD.
- **Cross-user agent management** — Admin key rotation, deletion, revoke across all users. Shipped v0.9.1.
- **Admin match detail + review** — Admin-scoped match detail view, hold-reason display, read-only inspection. Shipped v0.9.15.
- **Holding pen for inconclusive parses** — Partial matches flagged `pending_review`, admin accept/reject flow. Shipped v0.9.7.
- **Dashboard date range filter** — Preset dropdown (7/14/30d) + custom From/To date picker, composes with format filter. Shipped v0.9.13.
- **Card analytics engine** — Card performance table with sortable columns, avg cast turn, materialized stats. Shipped v0.9.6–v0.9.12.
- **Raw archive moved to S3-compatible object storage** (#135, #159, #167): admin-controlled migration with a GUI toggle for the automatic backfill, a manual "run now" trigger, and a configurable legacy-volume name so it points at the real volume on each host. Merged to `main`, not yet released.
- **Force-reparse preserves admin review verdicts** (#154): rejected matches stay hidden after a force-reparse rebuild instead of quietly coming back into view. Merged to `main`, not yet released.
- **Browser execution boundary hardened with a strict CSP** (#126): no inline scripts, no `unsafe-eval`, no third-party script/font/style origins; the gateway CSP is `'self'` only. One known side effect: card art on `/cards` is now blocked by the same policy (#173, listed below). Merged to `main`, not yet released.
- **CI stopped deploying releases** (#137): the release workflow publishes images and cuts a GitHub Release; it no longer SSHes anywhere. `lab-deployment` and Argo CD are the only path that changes what is actually running.
- **CI realigned to the `lab` runner pool** (#161): placement follows the `github-ci` rule: lab-only jobs need vCenter/cluster/lab CA access, everything else runs on GitHub-hosted runners.
- **Push review gate made worktree-aware** (#160): the pre-push hook that requires a passed self-review now resolves the correct worktree instead of trusting an ambient path. A narrower gap remains, tracked as #164 below.

---

## Active

The next 1–3 outcomes to pick up.

### 1. Matchup analysis dashboard

The core product value — per-user performance breakdowns that answer "what should I change about my play?"

- **Use cases:**
  - "I play Modern Burn — what's my win rate against each archetype I've faced?"
  - "Am I losing Game 1 or post-board against Tron?" → pre-board vs post-board win rate per matchup
  - "Which cards are actually winning me games against Tron?" → key card performance by matchup
  - "What are my best sideboard cards?" → cards appearing in G2-3 but not G1, with win rate delta
- **Acceptance criteria:**
  - Archetype-vs-archetype matrix: hero archetype × opponent archetype with win rate, match count, pre-board/post-board split
  - Key card breakdown per matchup: card name, games cast, win rate, pre-board vs post-board — filterable by format and by archetype matchup
  - Sideboard effectiveness: surface cards with significant G2-3 vs G1 win rate delta
  - Existing format and date range filters apply to all views
  - Read-only API surface so the AI add-on can query
- **Dependencies:** Archetype detection (shipped), date filtering (shipped), card analytics engine (shipped)
- **Status:** Not started. Tracked as issue [#129](https://github.com/sentania-labs/deep-analysis-server/issues/129). The building blocks (per-user game context, pre-board/post-board win rate) exist, but no matchup route or archetype-vs-archetype query exists yet. Land the dashboard date-range bug fix (#128, in Cleanup below) first since matchup filtering will build on the same date inputs.

### 2. BNR epoch awareness

Format-scoped Banned & Restricted epoch tracking, so users can scope stats to a metagame era by selecting a named event rather than guessing dates.

- **Use cases:**
  - "Show me my stats since Fury was banned in Modern" → select the epoch by name, date fills automatically
  - "How did my Vintage win rate change after Urza's Saga was restricted?" → compare across epochs
- **Acceptance criteria:**
  - Data model: B&R events with format, date, description (e.g. "Fury banned"), and affected cards
  - Events keyed by format — the date filter preset list is context-aware: selecting format "Vintage" shows Vintage-specific B&R epochs, not Modern ones
  - Dashboard date filter gains a "Since [B&R event]" preset dropdown that populates from the epoch list for the active format
  - Seed data sourced from mtg.fandom.com/wiki/Banned_and_restricted_cards/Timeline
  - Admin UI to add/edit/delete B&R events manually (corrections, new announcements)
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

### 6. Kubernetes-safe service behavior

Two gaps that matter once `lab-deployment`/Argo CD runs this stack on the cluster instead of Compose on one host.

- **Acceptance criteria:**
  - Split `/healthz` (dependency-aware, stays as the readiness probe) from a new shallow `/livez` (process-alive only), so a brief Postgres/Redis blip doesn't restart-loop a healthy container. Tracked as [#156](https://github.com/sentania-labs/deep-analysis-server/issues/156).
  - Lock the analytics background loops that aren't already replica-safe (Scryfall sync, card materializer, card-stat backfill) the same way the scrapers already are, so running more than one analytics replica doesn't duplicate work or race the database. Tracked as [#155](https://github.com/sentania-labs/deep-analysis-server/issues/155).
- **Dependencies:** None
- **Status:** Not started. Not urgent on today's single-Compose-host deployment; becomes a prerequisite the day analytics needs more than one replica.

### 7. Scraper diagnostics and run history

Admin UI currently shows scraper health and the last run; it does not show a history of runs.

- **Acceptance criteria:**
  - Bounded run-history list: start, finish, status, record counts, sanitized error snippet
  - Retention policy so history doesn't grow unbounded
  - Linked from the existing scraper admin cards
- **Dependencies:** None
- **Status:** Not started. Tracked as issue [#130](https://github.com/sentania-labs/deep-analysis-server/issues/130).

---

## Cleanup

Tactical bugs and small tech-debt items. Resolve when convenient or alongside related work.

- **Issue [#128](https://github.com/sentania-labs/deep-analysis-server/issues/128):** dashboard and match-history date filters accept an inverted or malformed range with no feedback; it just renders empty results.
- **Issue [#141](https://github.com/sentania-labs/deep-analysis-server/issues/141):** the reset-password smoke check fails intermittently (roughly 1 run in 3) against an otherwise healthy stack; root cause not yet confirmed.
- **Issue [#158](https://github.com/sentania-labs/deep-analysis-server/issues/158):** the parser silently skips a file when object storage is briefly unreachable; it self-heals on the next backfill pass, but nothing surfaces the skip to an admin.
- **Issue [#164](https://github.com/sentania-labs/deep-analysis-server/issues/164):** the pre-push review gate still fails open for a few shell forms it doesn't recognize as a push. A fix has to land the same way in this repo, `deep-analysis-agent`, and `deep-analysis-ai` at once, or the three repos drift out of sync.
- **Issue [#171](https://github.com/sentania-labs/deep-analysis-server/issues/171):** on mobile widths, the hamburger menu never opens the sidebar (an outside-click handler closes it in the same event that opened it).
- **Issue [#173](https://github.com/sentania-labs/deep-analysis-server/issues/173):** card art on `/cards` doesn't load; the new CSP (shipped, above) blocks the Scryfall image origin. Pre-existing gap, not a regression from the CSP work.
- **Issue [#174](https://github.com/sentania-labs/deep-analysis-server/issues/174):** the pre-push smoke steps are written out twice (README and CLAUDE.md) and the CLAUDE.md copy is now wrong; needs consolidating onto one authoritative copy.

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
