#!/usr/bin/env bash
# Deploy the deep-analysis stack to the docker.int slot on a tagged release.
#
# Pushes the repo-root docker-compose.yml to the slot dir on $DEPLOY_HOST,
# pulls the 5 service images at $DEPLOY_TAG via compose, and brings the
# stack up. Verification is via `compose ps` (matches the dashboard slot
# pattern). The deploy-wrapper allowlist on docker.int rejects raw
# `docker pull`, `--force-recreate`, and `compose exec`, so this script
# uses only allowlisted verbs.
#
# Migrations are NOT run from this script. The wrapper does not allow
# `compose exec`, so Alembic migrations must be baked into the compose
# stack (one-shot `auth-migrate` service, or `alembic upgrade head` in
# the auth container's entrypoint gated by an env flag). Until that is
# wired up, the first deploy after a schema change requires a manual
# admin step on docker.int.
#
# Requires DOCKER_DEPLOY_HOST and DOCKER_DEPLOY_KEY env vars, set by the
# deploy workflow from repo variables/secrets. DEPLOY_TAG defaults to
# "latest" but is normally passed the upstream tag (e.g. v0.6.0); the
# tag is consumed by docker-compose.yml via image: ${DEPLOY_TAG} pins.

set -euo pipefail

DEPLOY_HOST="${DOCKER_DEPLOY_HOST:?DOCKER_DEPLOY_HOST not set}"
DEPLOY_KEY="${DOCKER_DEPLOY_KEY:?DOCKER_DEPLOY_KEY not set}"
DEPLOY_TAG="${DEPLOY_TAG:-latest}"
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

SSH_OPTS=(-i "$DEPLOY_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new)
SCP_OPTS=(-O "${SSH_OPTS[@]}")

echo ">> deploying deep-analysis $DEPLOY_TAG to $DEPLOY_HOST:$DEPLOY_PATH"

echo ">> pushing compose file to $DEPLOY_HOST:$DEPLOY_PATH/docker-compose.yml"
scp "${SCP_OPTS[@]}" "$COMPOSE_FILE" "$DEPLOY_HOST:$DEPLOY_PATH/docker-compose.yml"

echo ">> pulling service images at $DEPLOY_TAG"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" \
    "docker compose --project-directory $DEPLOY_PATH pull"

echo ">> bringing stack up"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" \
    "docker compose --project-directory $DEPLOY_PATH up -d"

echo ">> verifying stack"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" \
    "docker compose --project-directory $DEPLOY_PATH ps"

echo ">> deploy complete — deep-analysis $DEPLOY_TAG"
