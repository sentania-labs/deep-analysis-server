#!/usr/bin/env bash
# ci/smoke.sh - the single definition of the full-stack smoke test.
#
# ONE DEFINITION, TWO CALLERS (see the `sdlc` skill). This script is what
# CI's `compose-smoke` and `smoke-ui` jobs run, and it is what README tells
# a human to run before pushing. Nothing hand-copies the sequence any more:
# if the setup changes, it changes here and both callers pick it up.
#
# What it does, from a clean checkout:
#   1. preflight the tools it needs
#   2. create the external `edge-slots` network if it is missing
#   3. write a throwaway compose env file (never touches your .env)
#   4. generate a throwaway JWT keypair at the path the CI overlay mounts
#   5. bring the stack up and wait for it to actually be healthy
#   6. run the requested smoke suite(s); the ui suite ends with a real
#      browser pass under the production CSP (ci/browser/smoke_csp.py)
#   7. dump logs on failure, then tear the stack down
#
# Usage:
#   bash ci/smoke.sh            # both suites (default)
#   bash ci/smoke.sh e2e        # API/gateway happy path only
#   bash ci/smoke.sh ui         # browser UI only
#
# Environment knobs (all optional):
#   DA_SMOKE_PROJECT   compose project name        (default deep-analysis-smoke)
#   DA_SMOKE_PORT      host port for the gateway   (default 8080)
#   DA_SMOKE_JWT_DIR   host dir for the keypair    (default /tmp/ci-jwt-keys)
#   DA_SMOKE_KEEP      set to 1 to skip teardown   (default unset)
#   DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL / _PASSWORD
#                      bootstrap admin used by both suites (defaults below)
#
# Exit 0 = every requested suite passed. Exit 1 = something failed.

set -euo pipefail

SUITE="${1:-all}"
case "$SUITE" in
    e2e|ui|all) ;;
    *)
        echo "usage: bash ci/smoke.sh [e2e|ui|all]" >&2
        exit 2
        ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

PROJECT="${DA_SMOKE_PROJECT:-deep-analysis-smoke}"
PORT="${DA_SMOKE_PORT:-8080}"
JWT_DIR="${DA_SMOKE_JWT_DIR:-/tmp/ci-jwt-keys}"
BASE_URL="http://localhost:${PORT}"

# Both suites log in as this account. The auth service creates it on first
# boot from the two env vars below, with must_change_password=false.
export DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL="${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL:-admin@smoke.local}"
export DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD="${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD:-SmokeAdminPass2026!}"

# --------------------------------------------------------------------------
# 1. preflight
# --------------------------------------------------------------------------
missing=""
for tool in docker uv curl python3; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
    echo "STOP: missing required tool(s):$missing" >&2
    exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
    echo "STOP: 'docker compose' (v2) is not available." >&2
    exit 1
fi

# ci/docker-compose.ci.yml uses the `!override` and `!reset` merge tags, and
# this script passes the compose env file via COMPOSE_ENV_FILES. All three
# landed in Compose v2.24.4. On anything older the override file fails to
# parse with a bare YAML error that says nothing about the cause, so check
# it here and say so plainly instead.
COMPOSE_MIN="2.24.4"
compose_version=$(docker compose version --short 2>/dev/null | sed 's/^v//')
if [ -z "$compose_version" ] || \
   [ "$(printf '%s\n%s\n' "$COMPOSE_MIN" "$compose_version" | sort -V | head -1)" != "$COMPOSE_MIN" ]; then
    echo "STOP: docker compose ${compose_version:-unknown} is too old." >&2
    echo "      ci/docker-compose.ci.yml needs the !override / !reset merge tags" >&2
    echo "      and COMPOSE_ENV_FILES, all of which need Compose v${COMPOSE_MIN} or newer." >&2
    exit 1
fi

# A throwaway compose env file rather than .env: this script must never
# clobber a developer's real .env, and --env-file makes compose read this
# one INSTEAD of .env, so there is no ambiguity about which values won.
SMOKE_ENV="$(mktemp)"

# The CI override publishes the gateway on DA_SMOKE_PORT and resets the
# postgres host publish, so concurrent stacks do not fight over ports.
export DA_SMOKE_PORT="$PORT"
export DA_SMOKE_JWT_DIR="$JWT_DIR"

# Point compose at this stack through the ENVIRONMENT rather than through
# flags, so a bare `docker compose ...` resolves to it. ci/smoke_ui.sh runs
# `docker compose exec -T auth` for the admin-CRUD section, and without
# these it would silently resolve to whatever the default project is and
# report "service auth is not running". Absolute paths because the callee
# does not necessarily share this script's working directory.
export COMPOSE_PROJECT_NAME="$PROJECT"
export COMPOSE_FILE="$REPO_ROOT/docker-compose.yml:$REPO_ROOT/ci/docker-compose.ci.yml"
export COMPOSE_ENV_FILES="$SMOKE_ENV"

compose() {
    docker compose "$@"
}

dump_logs() {
    echo ""
    echo "--- compose ps ---"
    compose ps || true
    echo "--- compose logs (tail 200) ---"
    compose logs --tail=200 || true
}

teardown() {
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        dump_logs
    fi
    if [ "${DA_SMOKE_KEEP:-}" = "1" ]; then
        echo ""
        echo "DA_SMOKE_KEEP=1: leaving the stack up. Tear down with:"
        echo "  COMPOSE_PROJECT_NAME=$PROJECT COMPOSE_FILE='$COMPOSE_FILE' docker compose down -v"
    else
        echo ""
        echo "--- tearing down ---"
        compose down -v --remove-orphans || true
    fi
    rm -f "$SMOKE_ENV"
    exit "$rc"
}
trap teardown EXIT

echo "=== Deep Analysis smoke ==="
echo "  suite:   $SUITE"
echo "  project: $PROJECT"
echo "  base:    $BASE_URL"

# --------------------------------------------------------------------------
# 2. external network
# --------------------------------------------------------------------------
# The gateway attaches to `edge-slots`, which is external: compose will not
# create it. It is shared with anything else on this host, so this only ever
# creates it, never removes it.
docker network inspect edge-slots >/dev/null 2>&1 || docker network create edge-slots >/dev/null

# --------------------------------------------------------------------------
# 3. compose env
# --------------------------------------------------------------------------
# The appended URLs use the `postgres` container hostname. .env.example ships
# DATABASE_URL pointed at localhost (for host-side alembic) and leaves
# DA_DATABASE_URL commented out, so both have to be set here for the
# containers to reach the database.
cp .env.example "$SMOKE_ENV"
cat >> "$SMOKE_ENV" <<EOF
DA_DATABASE_URL=postgresql+asyncpg://da:changeme@postgres:5432/deep_analysis
DATABASE_URL=postgresql+psycopg://da:changeme@postgres:5432/deep_analysis
DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL}
DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}
EOF

# --------------------------------------------------------------------------
# 4. JWT keypair
# --------------------------------------------------------------------------
# ci/docker-compose.ci.yml bind-mounts this directory at /data/secrets in
# every service. Generating it here rather than letting auth generate its
# own means every service verifies against the same public key.
echo ""
echo "--- generating JWT keypair in $JWT_DIR ---"
uv sync --all-packages --dev
mkdir -p "$JWT_DIR"
uv run python -m auth_service.keygen --out "$JWT_DIR"
chmod 644 "$JWT_DIR/jwt_public.pem"
chmod 600 "$JWT_DIR/jwt_private.pem"

# --------------------------------------------------------------------------
# 5. bring the stack up and wait for it
# --------------------------------------------------------------------------
echo ""
echo "--- docker compose up ---"
compose up -d --build

# Two separate waits, both required. The gateway answers 502 for any
# upstream that has not finished starting, and a 502 reads as a smoke
# failure rather than as "not ready yet".
echo ""
echo "--- waiting for container health ---"
unhealthy=""
for i in $(seq 1 90); do
    unhealthy=$(compose ps --format '{{.Service}} {{.Health}}' | awk '$2 != "" && $2 != "healthy"')
    if [ -z "$unhealthy" ]; then
        echo "all services healthy after ${i} tries"
        break
    fi
    sleep 2
done
if [ -n "$unhealthy" ]; then
    echo "STOP: services never became healthy:" >&2
    echo "$unhealthy" >&2
    exit 1
fi

echo ""
echo "--- waiting for the bootstrap admin ---"
admin_login_json=$(python3 -c '
import json, os, sys
json.dump(
    {
        "email": os.environ["DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL"],
        "password": os.environ["DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD"],
    },
    sys.stdout,
)
')
code=""
for i in $(seq 1 60); do
    code=$(printf '%s' "$admin_login_json" | curl -s -o /dev/null -w '%{http_code}' \
        -X POST "$BASE_URL/auth/login" \
        -H 'Content-Type: application/json' \
        --data-binary @- || true)
    if [ "$code" = "200" ]; then
        echo "bootstrap admin ready after ${i} tries"
        break
    fi
    sleep 2
done
if [ "$code" != "200" ]; then
    echo "STOP: the bootstrap admin never came online (last status ${code})." >&2
    echo "The stack is not up, so smoke output would not mean anything." >&2
    exit 1
fi

# --------------------------------------------------------------------------
# 6. the smoke runs
# --------------------------------------------------------------------------
# The /metagame/<format> page is the UI's most involved piece of client-side
# rendering (Alpine x-for/x-if, a :style binding, a Chart.js chart, JSON API
# refreshes) and a fresh stack has no scraped data to render it with. Seed
# one mtgtop8 event with three results straight into analytics.* so the
# browser pass can exercise that page; the fixture is inert for every other
# suite. A seed failure is a hard failure: the ui suite never runs the
# browser pass without the fixture, and the browser pass is always told to
# expect it, so a /metagame page that renders nothing is a FAIL, not a SKIP.
seed_metagame_fixture() {
    local sql
    sql=$(cat <<'SQL'
INSERT INTO analytics.mtgtop8_events (event_name, format, event_date, event_url, player_count)
VALUES ('CSP Smoke Challenge', 'Pauper', CURRENT_DATE - 3, 'https://smoke.local/mtgtop8/csp-smoke', 3)
ON CONFLICT (event_url) DO NOTHING;
INSERT INTO analytics.mtgtop8_results (event_id, player_name, placement, deck_name, decklist_main, decklist_sideboard)
SELECT e.id, r.player_name, r.placement, r.deck_name,
       '{"Island": 20, "Counterspell": 4}'::jsonb, '{"Hydroblast": 4}'::jsonb
FROM analytics.mtgtop8_events e
CROSS JOIN (VALUES ('smoke_alpha', 1, 'Mono Blue Faeries'),
                   ('smoke_beta', 2, 'Boros Synthesizer'),
                   ('smoke_gamma', 3, 'Mono Blue Faeries')) AS r(player_name, placement, deck_name)
WHERE e.event_url = 'https://smoke.local/mtgtop8/csp-smoke'
  AND NOT EXISTS (SELECT 1 FROM analytics.mtgtop8_results x WHERE x.event_id = e.id);
SQL
)
    if compose exec -T postgres psql -v ON_ERROR_STOP=1 -U da -d deep_analysis -q -c "$sql"; then
        echo "metagame fixture seeded (analytics.mtgtop8_events: CSP Smoke Challenge)"
    else
        echo "STOP: could not seed the metagame fixture; the browser pass needs /metagame/<format> to render" >&2
        return 1
    fi
}

# The match detail and scraper event paths need owned rows on a fresh stack.
# Create a dedicated ordinary user through auth, then seed deterministic rows
# in the same schemas the parser and analytics services own. Any setup failure
# is fatal because the browser pass must never skip these paths.
seed_csp_browser_fixture() {
    local login_response admin_jwt fixture_user_json create_response fixture_user_id
    local list_response sql

    if ! login_response=$(printf '%s' "$admin_login_json" | curl -fsS \
        -X POST "$BASE_URL/auth/login" \
        -H 'Content-Type: application/json' \
        --data-binary @-); then
        echo "STOP: could not log in as the bootstrap admin for the browser fixture" >&2
        return 1
    fi
    admin_jwt=$(printf '%s' "$login_response" | python3 -c \
        'import json, sys; print(json.load(sys.stdin).get("access_token", ""))')
    if [ -z "$admin_jwt" ]; then
        echo "STOP: bootstrap admin login returned no JWT for the browser fixture" >&2
        return 1
    fi

    fixture_user_json=$(python3 -c '
import json, sys
json.dump(
    {
        "email": "csp-fixture@local",
        "password": "CspFixtureUserPw2026!",
        "role": "user",
        "must_change_password": False,
    },
    sys.stdout,
)
')
    if ! create_response=$(printf '%s\n%s\n' "$admin_jwt" "$fixture_user_json" \
        | compose exec -T auth sh -c '
read -r token
read -r payload
curl -sS -X POST http://localhost:8000/admin/users \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    --data-binary "${payload}"
'); then
        echo "STOP: could not create csp-fixture@local through the auth admin API" >&2
        return 1
    fi
    fixture_user_id=$(printf '%s' "$create_response" | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("id", ""))
except json.JSONDecodeError:
    pass
')

    if [ -z "$fixture_user_id" ]; then
        if ! list_response=$(printf '%s\n' "$admin_jwt" | compose exec -T auth sh -c '
read -r token
curl -sS -H "Authorization: Bearer ${token}" http://localhost:8000/admin/users?limit=200
'); then
            echo "STOP: could not look up csp-fixture@local through the auth admin API" >&2
            return 1
        fi
        fixture_user_id=$(printf '%s' "$list_response" | python3 -c '
import json, sys
for user in json.load(sys.stdin).get("users", []):
    if user.get("email") == "csp-fixture@local":
        print(user["id"])
        break
')
    fi
    if ! [[ "$fixture_user_id" =~ ^[0-9]+$ ]]; then
        echo "STOP: auth returned no numeric id for csp-fixture@local" >&2
        return 1
    fi

    sql=$(cat <<'SQL'
INSERT INTO parser.matches
    (sha256, user_id, format, players, game_count, played_at, parsed_at, review_status)
VALUES
    (repeat('c', 64), :'fixture_user_id'::integer, 'Pauper',
     '["csp_fixture", "csp_opponent"]'::jsonb, 1, now() - interval '1 day',
     now() - interval '1 day', NULL)
ON CONFLICT (sha256, user_id) DO NOTHING;

INSERT INTO parser.games (match_id, game_number, winner)
SELECT id, 1, 'csp_fixture'
FROM parser.matches
WHERE sha256 = repeat('c', 64) AND user_id = :'fixture_user_id'::integer
ON CONFLICT (match_id, game_number) DO NOTHING;

INSERT INTO parser.game_states
    (game_id, turn_number, active_player, player_states, stack)
SELECT g.id, s.turn_number, s.active_player, s.player_states, s.stack
FROM parser.games g
JOIN parser.matches m ON m.id = g.match_id
CROSS JOIN (VALUES
    (1, 'csp_fixture',
     '{"csp_fixture":{"life":20,"zones":{"hand":["Island"]}},"csp_opponent":{"life":20,"zones":{"hand":["Mountain"]}}}'::jsonb,
     '[]'::jsonb),
    (2, 'csp_opponent',
     '{"csp_fixture":{"life":18,"zones":{"battlefield":["Island"]}},"csp_opponent":{"life":20,"zones":{"battlefield":["Mountain"]}}}'::jsonb,
     '["Counterspell"]'::jsonb)
) AS s(turn_number, active_player, player_states, stack)
WHERE m.sha256 = repeat('c', 64)
  AND m.user_id = :'fixture_user_id'::integer
  AND g.game_number = 1
ON CONFLICT (game_id, turn_number, active_player) DO NOTHING;

-- One archetype and one B&R event so /admin/archetypes and /admin/bnr-events
-- render an edit link each. Without a row those list pages carry no link and
-- the browser pass cannot reach the edit templates at all. Both ids are
-- UUIDs, which is why the browser pass matches a UUID path segment.
INSERT INTO analytics.archetypes (name, format, defining_cards)
SELECT 'CSP Smoke Archetype', 'Pauper', '["Counterspell"]'::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM analytics.archetypes WHERE name = 'CSP Smoke Archetype'
);

INSERT INTO analytics.bnr_events (format, effective_date, description, card_actions)
VALUES
    ('Pauper', DATE '2026-01-01', 'CSP smoke B&R event',
     '[{"card": "Counterspell", "action": "banned"}]'::jsonb)
ON CONFLICT (format, effective_date) DO NOTHING;
SQL
)
    if printf '%s\n' "$sql" | compose exec -T postgres \
        psql -v ON_ERROR_STOP=1 -U da -d deep_analysis -q \
        -v fixture_user_id="$fixture_user_id"; then
        echo "browser fixture seeded (csp-fixture@local, match, turns)"
    else
        echo "STOP: could not seed the fixture-backed browser paths" >&2
        return 1
    fi
}

rc=0
if [ "$SUITE" = "e2e" ] || [ "$SUITE" = "all" ]; then
    echo ""
    bash ci/smoke_e2e.sh "$BASE_URL" || rc=1
fi
if [ "$SUITE" = "ui" ] || [ "$SUITE" = "all" ]; then
    echo ""
    bash ci/smoke_ui.sh "$BASE_URL" || rc=1

    # Browser pass (issue #126). ci/smoke_ui.sh is curl-only; this drives a
    # real Chromium through every rendered page under the production CSP
    # and fails on any violation, console error or broken control. It is a
    # hard requirement of the ui suite, not an optional extra: a stack whose
    # pages render but whose scripts are refused by the CSP is broken.
    echo ""
    echo "--- browser CSP smoke (ci/browser/smoke_csp.py) ---"
    if ! seed_metagame_fixture || ! seed_csp_browser_fixture; then
        rc=1
    elif (cd ci/browser && uv sync --quiet && uv run playwright install chromium >/dev/null); then
        (cd ci/browser && uv run smoke_csp.py "$BASE_URL") || rc=1
    else
        echo "STOP: could not install Playwright's Chromium for ci/browser (see README, pre-push smoke test)" >&2
        rc=1
    fi
fi

echo ""
if [ "$rc" -ne 0 ]; then
    echo "=== smoke FAILED ==="
else
    echo "=== smoke PASSED ==="
fi
exit "$rc"
