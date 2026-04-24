#!/usr/bin/env bash
# ci/smoke_e2e.sh — End-to-end smoke test against the running compose stack.
#
# Verifies the full happy path: bootstrap admin login → create user →
# user login → mint agent reg code → agent register → heartbeat →
# ingest upload (POST /ingest/upload → 201).
#
# Also probes auth gates for unauthenticated access (expect 401) and
# handler reachability for validation errors (expect 422).
#
# Requires DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL and
# DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD to be set in the environment.
# The bootstrap env-var path creates the admin with must_change_password=false,
# so no password-change step is required in CI.
#
# Usage:
#   DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL=... \
#   DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD=... \
#   bash ci/smoke_e2e.sh https://deepanalysis.local
#
# Exit code 0 = all checks passed.
# Exit code 1 = one or more checks failed.

set -euo pipefail

BASE_URL="${1:-https://deepanalysis.local}"

PASS=0
FAIL=0

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
    curl -sk -o /dev/null -w "%{http_code}" "$@"
}

http_body() {
    curl -sk "$@"
}

echo "=== Deep Analysis E2E smoke — $BASE_URL ==="

# --------------------------------------------------------------------------
# 1. Auth gate checks (no credentials)
# --------------------------------------------------------------------------
echo ""
echo "--- Auth gate probes ---"

status=$(http_status -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{}')
check "POST /auth/login empty body → 422" "422" "$status"

status=$(http_status "$BASE_URL/admin/users" \
    -H "Authorization: Bearer fakejwt")
check "GET /admin/users no real auth → 401" "401" "$status"

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
else
    echo "  WARN: must_change_password=$must_change — password change required before proceeding" >&2
    check "Admin login must_change_password=false (env-var bootstrap)" "ok" "FAILED: must_change=$must_change"
fi

# --------------------------------------------------------------------------
# 3. Admin operations
# --------------------------------------------------------------------------
echo ""
echo "--- Admin operations ---"

status=$(http_status "$BASE_URL/admin/users" \
    -H "Authorization: Bearer $admin_token")
check "GET /admin/users (admin JWT) → 200" "200" "$status"

# Create a CI test user (idempotent: if email already exists from a prior run, 409 is acceptable)
create_status=$(http_status -X POST "$BASE_URL/admin/users" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d '{"email": "ci-smoke@test.local", "password": "CIsmokePass2024!", "role": "user", "must_change_password": false}')

if [ "$create_status" = "201" ] || [ "$create_status" = "409" ]; then
    check "POST /admin/users → 201 or 409 (idempotent)" "ok" "ok"
else
    check "POST /admin/users → 201 or 409 (idempotent)" "ok" "FAILED: $create_status"
fi

# --------------------------------------------------------------------------
# 4. User login
# --------------------------------------------------------------------------
echo ""
echo "--- User login ---"

user_login_body=$(http_body -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "ci-smoke@test.local", "password": "CIsmokePass2024!"}')

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
    -d "{\"code\": \"$reg_code\", \"machine_name\": \"ci-smoke-runner\", \"client_version\": \"0.4.2\"}")

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
    -d '{"client_version": "0.4.2"}')
check "POST /auth/agent/heartbeat → 200" "200" "$heartbeat_status"

# --------------------------------------------------------------------------
# 7. Ingest upload (the critical v0.4.2 fix)
# --------------------------------------------------------------------------
echo ""
echo "--- Ingest upload (POST /ingest/upload) ---"

# Create a tiny test file inline
test_file=$(mktemp --suffix=.dat)
echo "CI_SMOKE_TEST_PAYLOAD_v0.4.2" > "$test_file"
trap 'rm -f "$test_file"' EXIT

upload_status=$(http_status -X POST "$BASE_URL/ingest/upload" \
    -H "Authorization: Bearer $agent_token" \
    -F "file=@${test_file};filename=ci-smoke.dat" \
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
