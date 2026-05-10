#!/usr/bin/env bash
# First-deploy seed for the deep-analysis-server stack on edge.int.
#
# Idempotency: this script is intended to run ONCE on a fresh slot.
# It generates a Postgres password and a JWT keypair and pushes them to
# the slot dir. Re-running will overwrite the .env and the keys, which
# would break any existing data + tokens. The CI deploy.sh handles
# subsequent rollouts.
#
# Required env:
#   DOCKER_DEPLOY_HOST   ssh target, e.g. deploy@edge.int
#   DOCKER_DEPLOY_KEY    path to the slot deploy private key
# Optional:
#   DEPLOY_PATH          slot dir on host (default /srv/services/deep-analysis-server)
#
# Allowlist constraints on edge.int:
#   - scp -O (legacy mode); SFTP is not allowlisted
#   - docker compose --project-directory $DEPLOY_PATH {pull,up -d,ps}
#   - no raw `docker pull`, no `--force-recreate`, no `compose exec`,
#     no `docker run`, no `docker cp`
#
# JWT key handoff — known limitation:
#   The auth service expects jwt_private.pem and jwt_public.pem at
#   /data/secrets/ inside the container. In docker-compose.yml that path
#   is backed by the `auth_secrets` *named volume*. We cannot compose
#   exec / docker cp / docker run on edge.int, so we cannot populate the
#   named volume from outside the stack.
#
#   What this script does:
#     1. Generate the RSA-4096 keypair locally (auth uses RS256, see
#        services/auth/auth_service/jwt_issue.py — NOT Ed25519).
#     2. Push the .pem files to $DEPLOY_PATH/.secrets/ on the host.
#
#   For the auth service to actually pick the keys up, a follow-up patch
#   to docker-compose.yml is required: change the `auth_secrets` volume
#   from a named volume to a bind mount of `./.secrets`. That follow-up
#   is tracked separately. Until then, the keys land on the host but the
#   auth container will fail to find them and crash-loop.

set -euo pipefail

DEPLOY_HOST="${DOCKER_DEPLOY_HOST:?DOCKER_DEPLOY_HOST not set}"
DEPLOY_KEY="${DOCKER_DEPLOY_KEY:?DOCKER_DEPLOY_KEY not set}"
DEPLOY_PATH="${DEPLOY_PATH:-/srv/services/deep-analysis-server}"

if [[ ! -r "$DEPLOY_KEY" ]]; then
    echo "deploy key not found or unreadable: $DEPLOY_KEY" >&2
    echo "set DOCKER_DEPLOY_KEY to the slot deploy private key path" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/../docker-compose.yml"

if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "missing compose file: $COMPOSE_FILE" >&2
    exit 1
fi

CADDY_SNIPPET="$SCRIPT_DIR/deep-analysis-server.caddy"
CADDY_SLOT_JSON="$SCRIPT_DIR/deep-analysis-server.json"

for f in "$CADDY_SNIPPET" "$CADDY_SLOT_JSON"; do
    if [[ ! -f "$f" ]]; then
        echo "missing fleet-caddy artifact: $f" >&2
        exit 1
    fi
done

SSH_OPTS=(-i "$DEPLOY_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new)
SCP_OPTS=(-O "${SSH_OPTS[@]}")

TMPDIR="$(mktemp -d -t da-seed-XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

echo ">> seeding deep-analysis-server on $DEPLOY_HOST:$DEPLOY_PATH"

echo ">> generating Postgres password"
POSTGRES_PASSWORD="$(openssl rand -hex 32)"

echo ">> generating bootstrap admin password"
BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -hex 16)"

echo ">> generating RS256 JWT keypair (RSA-4096) into $TMPDIR"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
    -out "$TMPDIR/jwt_private.pem" >/dev/null 2>&1
openssl pkey -in "$TMPDIR/jwt_private.pem" -pubout \
    -out "$TMPDIR/jwt_public.pem" >/dev/null 2>&1
chmod 0600 "$TMPDIR/jwt_private.pem"
chmod 0644 "$TMPDIR/jwt_public.pem"

echo ">> writing local .env"
ENV_FILE="$TMPDIR/.env"
cat > "$ENV_FILE" <<EOF
POSTGRES_USER=da
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
DATABASE_URL=postgresql+psycopg://da:$POSTGRES_PASSWORD@postgres:5432/deep_analysis
DA_DATABASE_URL=postgresql+asyncpg://da:$POSTGRES_PASSWORD@postgres:5432/deep_analysis
DA_REDIS_URL=redis://redis:6379/0
DA_JWT_PRIVATE_KEY_PATH=/data/secrets/jwt_private.pem
DA_JWT_PUBLIC_KEY_PATH=/data/secrets/jwt_public.pem
DA_LOG_LEVEL=INFO
DA_ACCESS_TOKEN_TTL_SECONDS=900
DA_REFRESH_TOKEN_TTL_SECONDS=2592000
GATEWAY_DOMAIN=deepanalysis.sentania.net
DEEP_ANALYSIS_ACME_EMAIL=ops@sentania.net
DEPLOY_TAG=latest
DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL=admin@local
DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD=$BOOTSTRAP_ADMIN_PASSWORD
EOF
chmod 0600 "$ENV_FILE"

echo ">> ensuring $DEPLOY_PATH/.secrets/ exists on host"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" "mkdir -p $DEPLOY_PATH/.secrets && chmod 0700 $DEPLOY_PATH/.secrets"

echo ">> pushing compose file to $DEPLOY_HOST:$DEPLOY_PATH/docker-compose.yml"
scp "${SCP_OPTS[@]}" "$COMPOSE_FILE" "$DEPLOY_HOST:$DEPLOY_PATH/docker-compose.yml"

echo ">> pushing .env to $DEPLOY_HOST:$DEPLOY_PATH/.env"
scp "${SCP_OPTS[@]}" "$ENV_FILE" "$DEPLOY_HOST:$DEPLOY_PATH/.env"

echo ">> pushing JWT keypair to $DEPLOY_HOST:$DEPLOY_PATH/.secrets/"
scp "${SCP_OPTS[@]}" "$TMPDIR/jwt_private.pem" "$DEPLOY_HOST:$DEPLOY_PATH/.secrets/jwt_private.pem"
scp "${SCP_OPTS[@]}" "$TMPDIR/jwt_public.pem" "$DEPLOY_HOST:$DEPLOY_PATH/.secrets/jwt_public.pem"

echo ">> pushing fleet-caddy snippets to /srv/fleet-caddy/conf.d/deep-analysis-server/"
scp "${SCP_OPTS[@]}" "$CADDY_SNIPPET" \
    "$DEPLOY_HOST:/srv/fleet-caddy/conf.d/deep-analysis-server/deep-analysis-server.caddy"
scp "${SCP_OPTS[@]}" "$CADDY_SLOT_JSON" \
    "$DEPLOY_HOST:/srv/fleet-caddy/conf.d/deep-analysis-server/deep-analysis-server.json"

echo ">> pulling service images"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" \
    "docker compose --project-directory $DEPLOY_PATH pull"

echo ">> bringing stack up"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" \
    "docker compose --project-directory $DEPLOY_PATH up -d"

echo ">> verifying stack"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" \
    "docker compose --project-directory $DEPLOY_PATH ps"

echo ">> seed complete — deep-analysis-server"
echo ""
echo ">> ADMIN BOOTSTRAP CREDENTIALS (save these now):"
echo "   email:    admin@local"
echo "   password: $BOOTSTRAP_ADMIN_PASSWORD"
echo ""
echo "   The admin user will be created on first 'compose up -d'."
echo "   Change the password immediately after first login."
echo ""
echo "NOTE: JWT keys were pushed to $DEPLOY_PATH/.secrets/ but will not"
echo "be picked up until docker-compose.yml's auth_secrets volume is"
echo "switched from a named volume to a bind mount of ./.secrets."
