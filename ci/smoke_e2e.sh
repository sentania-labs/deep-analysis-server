#!/usr/bin/env bash
# ci/smoke_e2e.sh — End-to-end smoke test against the running compose stack.
#
# Verifies the full happy path: bootstrap admin login → provision a CI
# test user through the web admin UI → user login → mint agent reg code
# → agent register → heartbeat → ingest upload (POST /ingest/upload →
# 201).
#
# Also probes auth gates for unauthenticated access. Note the split:
# auth's JSON API answers a bare 401, while /admin/* (the web admin UI
# since W3.5-C) answers a 302 to /login and ignores bearer headers.
#
# Requires DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL and
# DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD to be set in the environment.
# The bootstrap env-var path creates the admin with must_change_password=false,
# so no password-change step is required in CI.
#
# Usage:
#   DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL=... \
#   DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD=... \
#   bash ci/smoke_e2e.sh http://localhost:8080
#
# Exit code 0 = all checks passed.
# Exit code 1 = one or more checks failed.

set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"

# The CI test user the agent + ingest path runs as. Provisioned below
# through the admin UI; re-runs against a live stack reuse it.
CI_USER_EMAIL="ci-smoke@test.local"
CI_USER_PASSWORD="CIsmokePass2024!"

# Client version the simulated agent reports. Ingest enforces the
# `min_agent_version` tunable (default 0.5.0) and answers 426 Upgrade
# Required below it, so this has to track a shipping agent release.
CI_AGENT_VERSION="0.6.2"

PASS=0
FAIL=0

# One trap for every temp file the run creates: a later trap would
# silently replace an earlier one and leak the cookie jar.
ADMIN_JAR=$(mktemp)
TEST_FILE=$(mktemp --suffix=.dat)
trap 'rm -f "$ADMIN_JAR" "$TEST_FILE"' EXIT

check() {
    local label="$1"
    local expected="$2"
    local actual="$3"
    if [ "$actual" = "$expected" ]; then
        echo "  PASS: $label (got $actual)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (expected $expected, got $actual)" >&2
        FAIL=$((FAIL + 1))
    fi
}

http_status() {
    # Returns just the HTTP status code; -k skips TLS verify (self-signed in CI).
    curl -s -o /dev/null -w "%{http_code}" "$@"
}

http_body() {
    curl -s "$@"
}

echo "=== Deep Analysis E2E smoke — $BASE_URL ==="

# --------------------------------------------------------------------------
# 0. Infrastructure probes (no credentials)
# --------------------------------------------------------------------------
echo ""
echo "--- Infrastructure probes ---"

# Bare /metrics on the gateway is Caddy's OWN telemetry (the `metrics`
# directive in the Caddyfile), not any application's. It is expected to
# answer 200 here; fleet-caddy restricts it to lab source IPs at the
# public edge. Do NOT confuse this with app metrics.
status=$(http_status "$BASE_URL/metrics")
check "GET /metrics → 200 (Caddy's own gateway telemetry, not app metrics)" "200" "$status"

# The real issue #134 regression guard: every service now serves its
# Prometheus metrics on its own DA_METRICS_PORT (default 9000), and the
# gateway proxies only the app port. The four per-service proxy routes
# that used to expose app metrics publicly are gone, so these must all
# be unreachable through the gateway.
for svc in auth ingest analytics parser; do
    status=$(http_status "$BASE_URL/${svc}/metrics")
    check "GET /${svc}/metrics → 404 (app metrics off the gateway, issue #134)" "404" "$status"
done

# Infra exporters are still proxied deliberately: they are separate
# exporter containers, not app services, and #134 did not touch them.
status=$(http_status "$BASE_URL/postgres/metrics")
check "GET /postgres/metrics → 200" "200" "$status"

status=$(http_status "$BASE_URL/redis/metrics")
check "GET /redis/metrics → 200" "200" "$status"

# --------------------------------------------------------------------------
# 1. Auth gate checks (no credentials)
# --------------------------------------------------------------------------
echo ""
echo "--- Auth gate probes ---"

status=$(http_status -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{}')
check "POST /auth/login empty body → 422" "422" "$status"

# W3.5-C: /admin/* is the web admin UI now, not auth's JSON API, so
# browser-redirect semantics apply. No session cookie gives a 302 to
# /login, and an Authorization bearer header is ignored entirely (it is
# a cookie session or nothing).
noauth_admin=$(curl -s -D - -o /dev/null "$BASE_URL/admin/users" | tr -d "\r")
status=$(echo "$noauth_admin" | awk 'NR == 1 { print $2 }')
check "GET /admin/users no cookie → 302" "302" "$status"

location=$(echo "$noauth_admin" | grep -i "^location:")
case "$location" in
    *"/login"*) check "GET /admin/users no cookie redirects to /login" "ok" "ok" ;;
    *) check "GET /admin/users no cookie redirects to /login" "ok" "FAILED: $location" ;;
esac

status=$(http_status "$BASE_URL/admin/users" \
    -H "Authorization: Bearer fakejwt")
check "GET /admin/users bearer header ignored → 302" "302" "$status"

status=$(http_status -X POST "$BASE_URL/ingest/upload" \
    -H "Authorization: Bearer fakejwt" \
    -F "file=@/dev/null;filename=test.dat")
check "POST /ingest/upload no real auth → 401" "401" "$status"

# --------------------------------------------------------------------------
# 2. Bootstrap admin login
# --------------------------------------------------------------------------
echo ""
echo "--- Bootstrap admin login ---"

if [ -z "${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL:-}" ] || \
   [ -z "${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD:-}" ]; then
    echo "  FAIL: DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL and DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD must be set" >&2
    FAIL=$((FAIL + 1))
    echo ""
    echo "=== Smoke result: $PASS PASS, $FAIL FAIL ==="
    exit 1
fi

login_body=$(http_body -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL}\", \"password\": \"${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}\"}")

admin_token=$(echo "$login_body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null || echo "")
must_change=$(echo "$login_body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('must_change_password','unknown'))" 2>/dev/null || echo "unknown")

if [ -n "$admin_token" ]; then
    check "Admin login (access_token present)" "ok" "ok"
else
    check "Admin login (access_token present)" "ok" "FAILED: $login_body"
fi

if [ "$must_change" = "False" ] || [ "$must_change" = "false" ]; then
    check "Admin login must_change_password=false (env-var bootstrap)" "ok" "ok"
elif [ "$must_change" = "True" ] || [ "$must_change" = "true" ]; then
    # Task spec: "change password if required". Rotate and re-login
    # for a full-scope token so the subsequent admin calls succeed.
    echo "  INFO: must_change_password=true — rotating admin password"
    rotated_password="rotated-${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}"
    pw_status=$(http_status -X POST "$BASE_URL/auth/password/change" \
        -H "Authorization: Bearer $admin_token" \
        -H "Content-Type: application/json" \
        -d "{\"current_password\": \"${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}\", \"new_password\": \"${rotated_password}\"}")
    check "POST /auth/password/change → 204" "204" "$pw_status"
    DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD="$rotated_password"
    login_body=$(http_body -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\": \"${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL}\", \"password\": \"${rotated_password}\"}")
    admin_token=$(echo "$login_body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null || echo "")
    if [ -n "$admin_token" ]; then
        check "Admin re-login after rotation (access_token present)" "ok" "ok"
    else
        check "Admin re-login after rotation (access_token present)" "ok" "FAILED: $login_body"
    fi
else
    check "Admin login must_change_password resolved" "ok" "FAILED: must_change=$must_change"
fi

# --------------------------------------------------------------------------
# 3. CI test user provisioning (web admin UI, cookie session)
# --------------------------------------------------------------------------
#
# The gateway routes /admin/* to the web service, and auth's JSON admin
# API is not exposed through the gateway at all, so the only supported
# programmatic way to create a user is the web admin UI: a cookie
# session plus the double-submit CSRF token. Bearer JWTs are ignored on
# these routes.
#
# The bootstrap admin cannot stand in for the test user: the W3.6 role
# split bars admins from POST /auth/agent/registration-code (403
# admin_self_service_disabled), so the agent + ingest path below needs a
# real role=user account.
echo ""
echo "--- CI test user provisioning (web admin UI) ---"

login_page=$(curl -s -c "$ADMIN_JAR" -b "$ADMIN_JAR" "$BASE_URL/login")
csrf_token=$(echo "$login_page" | grep -o 'name="csrf_token" value="[^"]*"' \
    | head -1 | sed 's/.*value="//;s/"//')

if [ -n "$csrf_token" ]; then
    check "GET /login (csrf_token present)" "ok" "ok"
else
    check "GET /login (csrf_token present)" "ok" "FAILED: no csrf_token in form"
fi

session_status=$(http_status -c "$ADMIN_JAR" -b "$ADMIN_JAR" \
    -X POST "$BASE_URL/login" \
    --data-urlencode "email=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL}" \
    --data-urlencode "password=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}" \
    --data-urlencode "csrf_token=${csrf_token}")
check "POST /login (admin browser session) → 303" "303" "$session_status"

status=$(http_status -b "$ADMIN_JAR" "$BASE_URL/admin/users")
check "GET /admin/users (admin cookie) → 200" "200" "$status"

# Read the token straight from the cookie jar rather than reusing the
# one scraped off the login page: the double-submit check compares the
# form field against whatever da_csrf the jar currently holds.
csrf_token=$(awk '$6 == "da_csrf" { print $7 }' "$ADMIN_JAR" | tail -1)

# Idempotent: a leftover user from a prior run answers 409.
create_status=$(http_status -b "$ADMIN_JAR" -c "$ADMIN_JAR" \
    -X POST "$BASE_URL/admin/users/create" \
    --data-urlencode "email=${CI_USER_EMAIL}" \
    --data-urlencode "password=${CI_USER_PASSWORD}" \
    --data-urlencode "role=user" \
    --data-urlencode "csrf_token=${csrf_token}")

if [ "$create_status" = "303" ] || [ "$create_status" = "409" ]; then
    check "POST /admin/users/create → 303 or 409 (idempotent)" "ok" "ok"
else
    check "POST /admin/users/create → 303 or 409 (idempotent)" "ok" "FAILED: $create_status"
fi

# 4. User login
# --------------------------------------------------------------------------
echo ""
echo "--- User login ---"

user_login_body=$(http_body -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"${CI_USER_EMAIL}\", \"password\": \"${CI_USER_PASSWORD}\"}")

user_token=$(echo "$user_login_body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null || echo "")

if [ -n "$user_token" ]; then
    check "User login (access_token present)" "ok" "ok"
else
    check "User login (access_token present)" "ok" "FAILED: $user_login_body"
fi

# --------------------------------------------------------------------------
# 5. Agent registration
# --------------------------------------------------------------------------
echo ""
echo "--- Agent registration ---"

code_body=$(http_body -X POST "$BASE_URL/auth/agent/registration-code" \
    -H "Authorization: Bearer $user_token")

reg_code=$(echo "$code_body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('code',''))" 2>/dev/null || echo "")

if [ -n "$reg_code" ]; then
    check "POST /auth/agent/registration-code → code present" "ok" "ok"
else
    check "POST /auth/agent/registration-code → code present" "ok" "FAILED: $code_body"
fi

register_body=$(http_body -X POST "$BASE_URL/auth/agent/register" \
    -H "Content-Type: application/json" \
    -d "{\"code\": \"$reg_code\", \"machine_name\": \"ci-smoke-runner\", \"client_version\": \"${CI_AGENT_VERSION}\"}")

agent_token=$(echo "$register_body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('api_token',''))" 2>/dev/null || echo "")

if [ -n "$agent_token" ]; then
    check "POST /auth/agent/register → api_token present" "ok" "ok"
else
    check "POST /auth/agent/register → api_token present" "ok" "FAILED: $register_body"
fi

# --------------------------------------------------------------------------
# 6. Agent heartbeat
# --------------------------------------------------------------------------
echo ""
echo "--- Agent heartbeat ---"

heartbeat_status=$(http_status -X POST "$BASE_URL/auth/agent/heartbeat" \
    -H "Authorization: Bearer $agent_token" \
    -H "Content-Type: application/json" \
    -d "{\"client_version\": \"${CI_AGENT_VERSION}\"}")
check "POST /auth/agent/heartbeat → 200" "200" "$heartbeat_status"

# --------------------------------------------------------------------------
# 7. Ingest upload
# --------------------------------------------------------------------------
echo ""
echo "--- Ingest upload (POST /ingest/upload) ---"

# Fill the test payload file created (and trapped) at the top of the run.
echo "CI_SMOKE_TEST_PAYLOAD" > "$TEST_FILE"

upload_status=$(http_status -X POST "$BASE_URL/ingest/upload" \
    -H "Authorization: Bearer $agent_token" \
    -F "file=@${TEST_FILE};filename=ci-smoke.dat" \
    -F "original_filename=ci-smoke.dat" \
    -F "content_type=match-log")
check "POST /ingest/upload (agent JWT) → 201" "201" "$upload_status"

# --------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------
echo ""
echo "=== Smoke result: $PASS PASS, $FAIL FAIL ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
