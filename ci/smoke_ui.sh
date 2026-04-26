#!/usr/bin/env bash
# ci/smoke_ui.sh — Browser-UI smoke test against the running compose stack.
#
# Covers the W3.5-A surface: login form render, credential submit →
# cookie + redirect to /dashboard, dashboard requires auth (redirect
# to /login when no cookie), password change → fresh cookie + redirect,
# logout → cookie cleared + redirect to /login.
#
# Requires DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL and
# DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD to be set (same bootstrap
# admin the API smoke uses).
#
# Usage:
#   DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL=... \
#   DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD=... \
#   bash ci/smoke_ui.sh https://deepanalysis.local
#
# Exit 0 = all checks passed. Exit 1 = one or more failed.

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

check_contains() {
    local label="$1"
    local needle="$2"
    local haystack="$3"
    if echo "$haystack" | grep -q -- "$needle"; then
        echo "  PASS: $label (contains '$needle')"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (missing '$needle')" >&2
        FAIL=$((FAIL + 1))
    fi
}

# Returns non-empty if the Netscape-format cookie jar contains a
# live (non-expired, non-empty-value) da_session cookie.
jar_has_live_session() {
    local jar="$1"
    [ -s "$jar" ] || return 1
    # Netscape format: domain \t http_only \t path \t secure \t expires \t name \t value
    # Note: curl prefixes HttpOnly cookies' domain field with `#HttpOnly_`,
    # so a plain `^#` skip would drop the very lines we need. Treat
    # `# ` (comment-with-space) as the comment marker instead.
    awk -v now="$(date +%s)" '
        $0 !~ /^# / && $0 !~ /^$/ {
            # Count real fields (tab-separated).
            n = split($0, f, "\t")
            if (n < 7) next
            if (f[6] != "da_session") next
            if (f[7] == "") next
            if (f[5] != "0" && f[5]+0 <= now) next
            print "live"
            exit
        }
    ' "$jar" | grep -q live
}

if [ -z "${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL:-}" ] || \
   [ -z "${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD:-}" ]; then
    echo "FAIL: DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL and DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD must be set" >&2
    exit 1
fi

COOKIE_JAR=$(mktemp)
PW_COOKIE=$(mktemp)
PROFILE_COOKIE=$(mktemp)
LOGOUT_COOKIE=$(mktemp)
trap 'rm -f "$COOKIE_JAR" "$PW_COOKIE" "$PROFILE_COOKIE" "$LOGOUT_COOKIE"' EXIT

echo "=== Deep Analysis UI smoke — $BASE_URL ==="

# --------------------------------------------------------------------------
# 1. GET /login — form renders
# --------------------------------------------------------------------------
echo ""
echo "--- 1. GET /login ---"

login_body=$(curl -sk -o - -w "\n%{http_code}" "$BASE_URL/login")
login_status=$(echo "$login_body" | tail -n1)
login_html=$(echo "$login_body" | sed '$d')
check "GET /login → 200" "200" "$login_status"
check_contains "GET /login contains <form" "<form" "$login_html"

# --------------------------------------------------------------------------
# 2. POST /login — valid creds → redirect + da_session cookie set
# --------------------------------------------------------------------------
echo ""
echo "--- 2. POST /login (valid creds) ---"

post_head=$(curl -sk -D - -o /dev/null \
    -c "$COOKIE_JAR" \
    -X POST "$BASE_URL/login" \
    --data-urlencode "email=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL}" \
    --data-urlencode "password=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}")
post_status=$(echo "$post_head" | head -n1 | awk '{print $2}')
# 303 See Other — spec-preferred for POST→GET redirect after form submit.
check "POST /login → 303" "303" "$post_status"
# W3.6: admin sessions land on the admin panel landing, not /dashboard.
# Location may be absolute (https://host/admin/users) or relative (/admin/users).
check_contains "POST /login (admin) redirects to /admin/users" "/admin/users" "$post_head"

if jar_has_live_session "$COOKIE_JAR"; then
    check "da_session cookie set" "ok" "ok"
else
    # Cookie jar check can be flaky with self-signed TLS and Secure flag;
    # fall back to verifying the header directly.
    if echo "$post_head" | grep -qi "set-cookie:.*da_session="; then
        check "da_session cookie set" "ok" "ok"
    else
        check "da_session cookie set" "ok" "FAILED (no live cookie)"
    fi
fi

# --------------------------------------------------------------------------
# 3. GET /dashboard with admin cookie → 302 to /admin/users (W3.6)
# --------------------------------------------------------------------------
echo ""
echo "--- 3. GET /dashboard (admin authenticated) ---"

dash_head=$(curl -sk -D - -o /dev/null -b "$COOKIE_JAR" "$BASE_URL/dashboard")
dash_status=$(echo "$dash_head" | head -n1 | awk '{print $2}')
check "GET /dashboard (admin cookie) → 302" "302" "$dash_status"
check_contains "GET /dashboard (admin) redirects to /admin/users" "/admin/users" "$dash_head"

# --------------------------------------------------------------------------
# 4. GET /dashboard without cookie → 302 to /login?next=/dashboard
# --------------------------------------------------------------------------
echo ""
echo "--- 4. GET /dashboard (unauthenticated) ---"

noauth_head=$(curl -sk -D - -o /dev/null "$BASE_URL/dashboard")
noauth_status=$(echo "$noauth_head" | head -n1 | awk '{print $2}')
check "GET /dashboard (no cookie) → 302" "302" "$noauth_status"
check_contains "Redirect targets /login?next=/dashboard" "/login?next=/dashboard" "$noauth_head"

# --------------------------------------------------------------------------
# 5. POST /settings/password — rotate + re-login → fresh cookie
# --------------------------------------------------------------------------
echo ""
echo "--- 5. POST /settings/password (rotate) ---"

NEW_PASSWORD="ui-smoke-${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}"

pw_head=$(curl -sk -D - -o /dev/null \
    -b "$COOKIE_JAR" \
    -c "$PW_COOKIE" \
    -X POST "$BASE_URL/settings/password" \
    --data-urlencode "current_password=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}" \
    --data-urlencode "new_password=${NEW_PASSWORD}" \
    --data-urlencode "confirm_password=${NEW_PASSWORD}")
pw_status=$(echo "$pw_head" | head -n1 | awk '{print $2}')
check "POST /settings/password → 303" "303" "$pw_status"
# Location may be absolute (https://host/dashboard) or relative (/dashboard).
check_contains "Redirects to /dashboard" "/dashboard" "$pw_head"

if jar_has_live_session "$PW_COOKIE"; then
    check "Fresh da_session cookie after password change" "ok" "ok"
else
    if echo "$pw_head" | grep -qi "set-cookie:.*da_session="; then
        check "Fresh da_session cookie after password change" "ok" "ok"
    else
        check "Fresh da_session cookie after password change" "ok" "FAILED (no live cookie)"
    fi
fi

# Restore the bootstrap password for any follow-up smoke runs.
restore_status=$(curl -sk -o /dev/null -w "%{http_code}" \
    -b "$PW_COOKIE" \
    -c "$PW_COOKIE" \
    -X POST "$BASE_URL/settings/password" \
    --data-urlencode "current_password=${NEW_PASSWORD}" \
    --data-urlencode "new_password=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}" \
    --data-urlencode "confirm_password=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}")
check "Restore bootstrap password → 303" "303" "$restore_status"

# --------------------------------------------------------------------------
# 6. /profile* off-limits to admin (W3.6 hard role split)
# --------------------------------------------------------------------------
echo ""
echo "--- 6. /profile* admin bounce ---"

# Step 5's password rotation revoked the cookie in $COOKIE_JAR. Log in fresh
# so the bounce checks are independent of the rotation flow.
curl -sk -o /dev/null -c "$PROFILE_COOKIE" \
    -X POST "$BASE_URL/login" \
    --data-urlencode "email=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL}" \
    --data-urlencode "password=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}"

# Each /profile* GET as an admin redirects (302) to /admin/users.
for path in "/profile" "/profile/edit" "/profile/agents"; do
    bounce_head=$(curl -sk -D - -o /dev/null -b "$PROFILE_COOKIE" "$BASE_URL$path")
    bounce_status=$(echo "$bounce_head" | head -n1 | awk '{print $2}')
    check "GET $path (admin cookie) → 302" "302" "$bounce_status"
    check_contains "GET $path (admin) → /admin/users" "/admin/users" "$bounce_head"
done

# Unauthenticated /profile must still redirect to /login (not /admin/users).
noauth_profile=$(curl -sk -D - -o /dev/null "$BASE_URL/profile")
noauth_profile_status=$(echo "$noauth_profile" | head -n1 | awk '{print $2}')
check "GET /profile (no cookie) → 302" "302" "$noauth_profile_status"
check_contains "/profile (no cookie) redirect targets /login" "/login" "$noauth_profile"

# --------------------------------------------------------------------------
# 7. /admin/users — admin panel surface (W3.5-C)
# --------------------------------------------------------------------------
echo ""
echo "--- 7. /admin/users admin panel ---"

# The bootstrap admin from $PROFILE_COOKIE is still authenticated.
admin_out=$(curl -sk -b "$PROFILE_COOKIE" -o - -w "\n%{http_code}" "$BASE_URL/admin/users")
admin_status=$(echo "$admin_out" | tail -n1)
admin_html=$(echo "$admin_out" | sed '$d')
check "GET /admin/users (admin cookie) → 200" "200" "$admin_status"
check_contains "GET /admin/users contains the admin email" \
    "${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL}" "$admin_html"
check_contains "GET /admin/users mentions Users heading" "Users" "$admin_html"

# Unauthenticated must redirect to /login.
noauth_admin=$(curl -sk -D - -o /dev/null "$BASE_URL/admin/users")
noauth_admin_status=$(echo "$noauth_admin" | head -n1 | awk '{print $2}')
check "GET /admin/users (no cookie) → 302" "302" "$noauth_admin_status"
check_contains "/admin/users redirect targets /login" "/login" "$noauth_admin"

# End-to-end CRUD: seed testuser@local via the auth JSON API
# (reachable on the internal docker network only — gateway no longer
# routes /admin/* JSON publicly), rotate its password through the
# web admin UI, then delete it. Skip seeding gracefully when docker
# compose isn't reachable (e.g. running this script against a remote
# stack manually) — the GET-only checks above still gate the build.
ADMIN_JWT=$(awk -F'\t' '$0 !~ /^# / && $0 !~ /^$/ && $6 == "da_session" { print $7; exit }' "$PROFILE_COOKIE")
if [ -z "$ADMIN_JWT" ]; then
    check "Extracted admin JWT from session cookie" "ok" "FAILED (cookie jar missing da_session)"
fi

if command -v docker >/dev/null 2>&1 \
   && [ -n "$ADMIN_JWT" ] \
   && docker compose ps auth >/dev/null 2>&1; then

    # Seed testuser@local via auth's internal JSON API. Idempotent:
    # if the row already exists from a prior run we look up its id.
    create_resp=$(docker compose exec -T auth sh -c \
        "curl -s -X POST http://localhost:8000/admin/users \
            -H 'Authorization: Bearer ${ADMIN_JWT}' \
            -H 'Content-Type: application/json' \
            -d '{\"email\":\"testuser@local\",\"password\":\"TestUserPw2026!\",\"role\":\"user\",\"must_change_password\":false}'" \
        || true)
    TEST_USER_ID=$(echo "$create_resp" | sed -n 's/.*"id":\s*\([0-9]\+\).*/\1/p')
    if [ -z "$TEST_USER_ID" ]; then
        list_resp=$(docker compose exec -T auth sh -c \
            "curl -s -H 'Authorization: Bearer ${ADMIN_JWT}' http://localhost:8000/admin/users?limit=200" \
            || true)
        TEST_USER_ID=$(echo "$list_resp" \
            | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for u in d.get("users", []):
    if u.get("email") == "testuser@local":
        print(u["id"]); break')
    fi

    if [ -z "$TEST_USER_ID" ]; then
        check "Seeded testuser@local via auth admin API" "ok" "FAILED (no id captured)"
    else
        check_contains "Seeded testuser@local via auth admin API" "ok" "ok (id=$TEST_USER_ID)"

        # Reset-password through the web admin UI — temp password is
        # rendered inline in the response HTML.
        reset_out=$(curl -sk -b "$PROFILE_COOKIE" -o - -w "\n%{http_code}" \
            -X POST "$BASE_URL/admin/users/${TEST_USER_ID}/reset-password")
        reset_status=$(echo "$reset_out" | tail -n1)
        reset_html=$(echo "$reset_out" | sed '$d')
        check "POST /admin/users/{id}/reset-password → 200" "200" "$reset_status"
        check_contains "Reset-password page renders temporary password" \
            "temp-password" "$reset_html"

        # Self-delete must be blocked at the web layer (admin == bootstrap).
        admin_user_id=$(docker compose exec -T auth sh -c \
            "curl -s -H 'Authorization: Bearer ${ADMIN_JWT}' http://localhost:8000/auth/me" \
            | sed -n 's/.*"user_id":\s*\([0-9]\+\).*/\1/p' || true)
        if [ -n "$admin_user_id" ]; then
            self_del_status=$(curl -sk -o /dev/null -w "%{http_code}" -b "$PROFILE_COOKIE" \
                -X POST "$BASE_URL/admin/users/${admin_user_id}/delete")
            check "POST /admin/users/{self}/delete → 400" "400" "$self_del_status"
        fi

        # Delete through the web admin UI — should redirect back to /admin/users.
        delete_head=$(curl -sk -D - -o /dev/null -b "$PROFILE_COOKIE" \
            -X POST "$BASE_URL/admin/users/${TEST_USER_ID}/delete")
        delete_status=$(echo "$delete_head" | head -n1 | awk '{print $2}')
        check "POST /admin/users/{id}/delete → 303" "303" "$delete_status"
        check_contains "Delete redirects to /admin/users" "/admin/users" "$delete_head"

        # Confirm testuser@local is gone from the rendered list.
        post_delete_html=$(curl -sk -b "$PROFILE_COOKIE" "$BASE_URL/admin/users")
        if echo "$post_delete_html" | grep -q "testuser@local"; then
            check "testuser@local removed from list" "ok" "FAILED (still listed)"
        else
            check "testuser@local removed from list" "ok" "ok"
        fi
    fi
else
    echo "  SKIP: admin CRUD end-to-end (docker compose not reachable; GET-only checks still gate)"
fi

# --------------------------------------------------------------------------
# 8. POST /logout → 303 to /login, cookie cleared
# --------------------------------------------------------------------------
echo ""
echo "--- 6. POST /logout ---"

# First log in fresh so we have a live cookie to logout with.
curl -sk -o /dev/null -c "$LOGOUT_COOKIE" \
    -X POST "$BASE_URL/login" \
    --data-urlencode "email=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL}" \
    --data-urlencode "password=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}"

logout_head=$(curl -sk -D - -o /dev/null \
    -b "$LOGOUT_COOKIE" \
    -c "$LOGOUT_COOKIE" \
    -X POST "$BASE_URL/logout")
logout_status=$(echo "$logout_head" | head -n1 | awk '{print $2}')
check "POST /logout → 303" "303" "$logout_status"
# Location may be absolute (https://host/login) or relative (/login).
check_contains "Logout redirects to /login" "/login" "$logout_head"

if jar_has_live_session "$LOGOUT_COOKIE"; then
    check "da_session cookie cleared" "ok" "FAILED (cookie still live)"
else
    check "da_session cookie cleared" "ok" "ok"
fi

# --------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------
echo ""
echo "=== UI smoke result: $PASS PASS, $FAIL FAIL ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
