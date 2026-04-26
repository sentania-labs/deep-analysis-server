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
    awk -v now="$(date +%s)" '
        $0 !~ /^#/ && $0 !~ /^$/ {
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
# Location may be absolute (https://host/dashboard) or relative (/dashboard).
check_contains "POST /login redirects to /dashboard" "/dashboard" "$post_head"

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
# 3. GET /dashboard with cookie → 200 + "Welcome"
# --------------------------------------------------------------------------
echo ""
echo "--- 3. GET /dashboard (authenticated) ---"

dash_out=$(curl -sk -b "$COOKIE_JAR" -o - -w "\n%{http_code}" "$BASE_URL/dashboard")
dash_status=$(echo "$dash_out" | tail -n1)
dash_html=$(echo "$dash_out" | sed '$d')
check "GET /dashboard (with cookie) → 200" "200" "$dash_status"
check_contains "GET /dashboard contains 'Welcome'" "Welcome" "$dash_html"

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
# 6. Self-service /profile surface (GET/POST)
# --------------------------------------------------------------------------
echo ""
echo "--- 6. /profile self-service ---"

# Step 5's password rotation revoked the cookie in $COOKIE_JAR. Log in fresh
# so /profile checks are independent of the rotation flow.
curl -sk -o /dev/null -c "$PROFILE_COOKIE" \
    -X POST "$BASE_URL/login" \
    --data-urlencode "email=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL}" \
    --data-urlencode "password=${DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD}"

profile_out=$(curl -sk -b "$PROFILE_COOKIE" -o - -w "\n%{http_code}" "$BASE_URL/profile")
profile_status=$(echo "$profile_out" | tail -n1)
profile_html=$(echo "$profile_out" | sed '$d')
check "GET /profile (with cookie) → 200" "200" "$profile_status"
check_contains "GET /profile contains 'Edit email'" "Edit email" "$profile_html"
check_contains "GET /profile links to /profile/agents" "/profile/agents" "$profile_html"

edit_out=$(curl -sk -b "$PROFILE_COOKIE" -o - -w "\n%{http_code}" "$BASE_URL/profile/edit")
edit_status=$(echo "$edit_out" | tail -n1)
edit_html=$(echo "$edit_out" | sed '$d')
check "GET /profile/edit (with cookie) → 200" "200" "$edit_status"
check_contains "GET /profile/edit contains email field" 'name="email"' "$edit_html"

agents_out=$(curl -sk -b "$PROFILE_COOKIE" -o - -w "\n%{http_code}" "$BASE_URL/profile/agents")
agents_status=$(echo "$agents_out" | tail -n1)
check "GET /profile/agents (with cookie) → 200" "200" "$agents_status"

# Unauthenticated must redirect to /login.
noauth_profile=$(curl -sk -D - -o /dev/null "$BASE_URL/profile")
noauth_profile_status=$(echo "$noauth_profile" | head -n1 | awk '{print $2}')
check "GET /profile (no cookie) → 302" "302" "$noauth_profile_status"
check_contains "/profile redirect targets /login" "/login" "$noauth_profile"

# --------------------------------------------------------------------------
# 7. POST /logout → 303 to /login, cookie cleared
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
