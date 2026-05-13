#!/usr/bin/env bash
# Deploy the deep-analysis stack to the edge.int slot on a tagged release.
#
# The repo-root docker-compose.yml uses `build:` blocks for local dev. The
# slot host has no source checkout, so we rewrite those blocks into
# `image: ghcr.io/sentania-labs/deep-analysis-<svc>:<tag>` references and
# scp the rewritten file. fleet-caddy snippets are scp'd to the per-slot
# conf.d/ dir; compose pull + up -d brings the stack up. Verification is
# via `compose ps`. The deploy-wrapper allowlist on edge.int rejects raw
# `docker pull`, `--force-recreate`, and `compose exec`, so this script
# uses only allowlisted verbs.
#
# Migrations run as one-shot `root-migrate` and `auth-migrate` services
# inside the compose stack, ordered via `service_completed_successfully`
# so they fire on every `compose up -d`.
#
# Requires DOCKER_DEPLOY_HOST and DOCKER_DEPLOY_KEY env vars, set by the
# deploy workflow from repo variables/secrets. DEPLOY_TAG is normally the
# upstream release tag (e.g. v0.6.0); it is baked into the rewritten
# compose file's `image:` tags as a literal value.

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
CADDY_SNIPPET="$SCRIPT_DIR/deep-analysis-server.caddy"
CADDY_SLOT_JSON="$SCRIPT_DIR/deep-analysis-server.json"

if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "missing compose file: $COMPOSE_FILE" >&2
    exit 1
fi

for f in "$CADDY_SNIPPET" "$CADDY_SLOT_JSON"; do
    if [[ ! -f "$f" ]]; then
        echo "missing fleet-caddy artifact: $f" >&2
        exit 1
    fi
done

SSH_OPTS=(-i "$DEPLOY_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new)
SCP_OPTS=(-O "${SSH_OPTS[@]}")

echo ">> deploying deep-analysis $DEPLOY_TAG to $DEPLOY_HOST:$DEPLOY_PATH"

echo ">> generating prod compose with image: refs at $DEPLOY_TAG"
PROD_COMPOSE="$(mktemp -t deep-analysis-compose-prod.XXXXXX.yml)"
trap 'rm -f "$PROD_COMPOSE"' EXIT

DEPLOY_TAG="$DEPLOY_TAG" python3 - "$COMPOSE_FILE" "$PROD_COMPOSE" <<'PY'
import os
import sys

import yaml

src, dst = sys.argv[1], sys.argv[2]
tag = os.environ["DEPLOY_TAG"]

# Service name → GHCR image (without tag). Services not in this map and
# without a `build:` key are left untouched (gateway, postgres, redis).
IMAGES = {
    "root-migrate": "ghcr.io/sentania-labs/deep-analysis-auth",
    "auth-migrate": "ghcr.io/sentania-labs/deep-analysis-auth",
    "auth": "ghcr.io/sentania-labs/deep-analysis-auth",
    "ingest-migrate": "ghcr.io/sentania-labs/deep-analysis-ingest",
    "ingest": "ghcr.io/sentania-labs/deep-analysis-ingest",
    "parser": "ghcr.io/sentania-labs/deep-analysis-parser",
    "analytics": "ghcr.io/sentania-labs/deep-analysis-analytics",
    "web": "ghcr.io/sentania-labs/deep-analysis-web",
}

with open(src) as f:
    compose = yaml.safe_load(f)

for name, svc in compose.get("services", {}).items():
    if "build" in svc:
        if name not in IMAGES:
            sys.exit(f"service {name!r} has build: but no image mapping")
        del svc["build"]
        svc["image"] = f"{IMAGES[name]}:{tag}"

with open(dst, "w") as f:
    yaml.safe_dump(compose, f, sort_keys=False)
PY

echo ">> removing legacy flat fleet-caddy snippet (idempotent)"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" \
    "rm -f /srv/fleet-caddy/conf.d/deep-analysis-server.caddy"

echo ">> pushing compose file to $DEPLOY_HOST:$DEPLOY_PATH/docker-compose.yml"
scp "${SCP_OPTS[@]}" "$PROD_COMPOSE" "$DEPLOY_HOST:$DEPLOY_PATH/docker-compose.yml"

echo ">> pushing gateway Caddyfile to $DEPLOY_HOST:$DEPLOY_PATH/gateway/"
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" "mkdir -p $DEPLOY_PATH/gateway"
scp "${SCP_OPTS[@]}" "$SCRIPT_DIR/../gateway/Caddyfile" \
    "$DEPLOY_HOST:$DEPLOY_PATH/gateway/Caddyfile"

echo ">> pushing fleet-caddy snippets to /srv/fleet-caddy/conf.d/deep-analysis-server/"
scp "${SCP_OPTS[@]}" "$CADDY_SNIPPET" \
    "$DEPLOY_HOST:/srv/fleet-caddy/conf.d/deep-analysis-server/deep-analysis-server.caddy"
scp "${SCP_OPTS[@]}" "$CADDY_SLOT_JSON" \
    "$DEPLOY_HOST:/srv/fleet-caddy/conf.d/deep-analysis-server/deep-analysis-server.json"

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
