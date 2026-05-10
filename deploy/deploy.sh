#!/usr/bin/env bash
# Deploy the deep-analysis stack to the docker host on a tagged release.
#
# Pulls the 5 service images at $DEPLOY_TAG, force-recreates the compose
# stack at $DEPLOY_PATH on $DEPLOY_HOST, runs Alembic migrations through
# the auth container, and smoke-checks /healthz on each service.
#
# Requires DOCKER_DEPLOY_HOST and DOCKER_DEPLOY_KEY env vars, set by the
# deploy workflow from repo variables/secrets. DEPLOY_TAG defaults to
# "latest" but is normally passed the upstream tag (e.g. v0.6.0).

set -euo pipefail

DEPLOY_HOST="${DOCKER_DEPLOY_HOST:?DOCKER_DEPLOY_HOST not set}"
DEPLOY_KEY="${DOCKER_DEPLOY_KEY:?DOCKER_DEPLOY_KEY not set}"
DEPLOY_TAG="${DEPLOY_TAG:-latest}"
DEPLOY_PATH="${DEPLOY_PATH:-/opt/deep-analysis}"

if [[ ! -r "$DEPLOY_KEY" ]]; then
    echo "deploy key not found or unreadable: $DEPLOY_KEY" >&2
    echo "set DOCKER_DEPLOY_KEY to the deploy private key path" >&2
    exit 1
fi

SSH_OPTS=(-i "$DEPLOY_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new)

SERVICES=(auth ingest parser analytics web)

echo ">> deploying deep-analysis $DEPLOY_TAG to $DEPLOY_HOST"

echo ">> pulling service images at $DEPLOY_TAG"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" \
    "docker pull ghcr.io/sentania-labs/deep-analysis-auth:${DEPLOY_TAG} && \
     docker pull ghcr.io/sentania-labs/deep-analysis-ingest:${DEPLOY_TAG} && \
     docker pull ghcr.io/sentania-labs/deep-analysis-parser:${DEPLOY_TAG} && \
     docker pull ghcr.io/sentania-labs/deep-analysis-analytics:${DEPLOY_TAG} && \
     docker pull ghcr.io/sentania-labs/deep-analysis-web:${DEPLOY_TAG}"

echo ">> bringing stack up (force-recreate) at $DEPLOY_PATH"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" \
    "docker compose --project-directory $DEPLOY_PATH pull && \
     docker compose --project-directory $DEPLOY_PATH up -d --force-recreate"

echo ">> running alembic migrations via auth container"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" \
    "docker compose --project-directory $DEPLOY_PATH exec -T auth alembic upgrade head"

echo ">> smoke-checking /healthz on all services"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" \
    "for svc in ${SERVICES[*]}; do \
        echo \">> smoke check: \$svc\"; \
        docker compose --project-directory $DEPLOY_PATH exec -T \$svc curl -sf http://localhost:8000/healthz \
            || { echo \"FAIL: \$svc /healthz\" >&2; exit 1; }; \
     done"

echo ">> deploy complete — deep-analysis $DEPLOY_TAG"
