#!/usr/bin/env bash
# ci/check-compose-paths.sh — drift guard for JWT key paths.
#
# The stack uses a named volume `auth_secrets` mounted at /data/secrets; the
# /run/secrets/... form is Docker Compose secrets syntax and requires a
# top-level `secrets:` block that this stack deliberately does not have.
# v0.4.0 shipped with /run/secrets/... defaults + a missing
# DA_JWT_PRIVATE_KEY_PATH on the auth service, crashing the operator deploy.
# This guard prevents that regression by failing CI if the wrong path shows
# up in docker-compose.yml or .env.example, or if the auth service is again
# missing DA_JWT_PRIVATE_KEY_PATH.
#
# Additionally, if `docker compose` is available, render the config and
# re-check the rendered output (catches path overrides sneaking in via CI
# override files etc.).

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# Match actual path values like /run/secrets/jwt_private.pem — a letter
# after the trailing slash. Warning comments mentioning `/run/secrets/*`
# are not caught (the `*` is not a word char).
forbidden='/run/secrets/[A-Za-z]'

echo "--> Checking docker-compose.yml for /run/secrets paths..."
if grep -nE "$forbidden" docker-compose.yml; then
    echo "FAIL: docker-compose.yml references /run/secrets. Use /data/secrets (auth_secrets named volume)." >&2
    fail=1
fi

echo "--> Checking .env.example for /run/secrets paths..."
if grep -nE "$forbidden" .env.example; then
    echo "FAIL: .env.example references /run/secrets. Use /data/secrets." >&2
    fail=1
fi

echo "--> Checking auth service has DA_JWT_PRIVATE_KEY_PATH..."
# Extract the auth service's environment block and require the key is listed.
if ! awk '
    /^  auth:/ { in_auth = 1; next }
    in_auth && /^  [a-z]/ && !/^  auth:/ { in_auth = 0 }
    in_auth && /DA_JWT_PRIVATE_KEY_PATH/ { found = 1 }
    END { exit found ? 0 : 1 }
' docker-compose.yml; then
    echo "FAIL: auth service in docker-compose.yml is missing DA_JWT_PRIVATE_KEY_PATH." >&2
    echo "      The auth service signs JWTs and needs the private key path set." >&2
    fail=1
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "--> Rendering docker compose config and re-checking..."
    tmp_env=$(mktemp)
    trap 'rm -f "$tmp_env"' EXIT
    cp .env.example "$tmp_env"
    # docker compose config fails if required substitutions are empty; seed.
    echo 'POSTGRES_PASSWORD=ci' >> "$tmp_env"
    echo 'GATEWAY_DOMAIN=ci.local' >> "$tmp_env"
    echo 'DEEP_ANALYSIS_ACME_EMAIL=ci@example.com' >> "$tmp_env"

    rendered=$(docker compose --env-file "$tmp_env" config 2>/dev/null)
    if echo "$rendered" | grep -qE "$forbidden"; then
        echo "FAIL: rendered compose config contains /run/secrets paths:" >&2
        echo "$rendered" | grep -nE "$forbidden" >&2
        fail=1
    fi
else
    echo "--> docker compose not available; skipped rendered-config check."
fi

if [ "$fail" -ne 0 ]; then
    echo
    echo "JWT key path drift detected. Fix: align compose + .env.example to /data/secrets/..." >&2
    exit 1
fi

echo "OK: JWT key paths consistent."
