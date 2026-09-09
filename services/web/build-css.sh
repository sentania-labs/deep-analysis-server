#!/usr/bin/env bash
# Rebuild the committed Tailwind stylesheet for the web service.
#
# The stylesheet at web_service/static/css/tailwind.css is generated from the
# templates by the Tailwind CLI pinned in package-lock.json, and committed so
# a checkout runs without Node at container build time. Run this after
# changing any template, static JS file, or tailwind.config.js, then commit
# the output. CI (frontend-assets job) rebuilds it and fails on drift.
#
# Needs Node 18+ and npm on PATH. Nothing else.
set -euo pipefail
cd "$(dirname "$0")"
npm ci --no-audit --no-fund --silent
npm run --silent build:css
echo "wrote $(wc -c < web_service/static/css/tailwind.css) bytes to web_service/static/css/tailwind.css"
