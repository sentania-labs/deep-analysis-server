#!/usr/bin/env bash
# Pre-push gate: blocks `git push` unless .review-passed marker
# exists at repo root and its SHA matches HEAD. Generic — no
# repo-specific assumptions.
set -euo pipefail

# Read PreToolUse JSON input from stdin
input="$(cat)"
cmd="$(echo "$input" | jq -r '.tool_input.command // ""')"

# Only gate `git push` invocations. Allow everything else.
if ! echo "$cmd" | grep -qE '(^|;|&&|\|\|)\s*git\s+push'; then
  exit 0
fi

# Find repo root. If we're not in a git repo, fail closed.
if ! repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "self-review hook: not a git repo, blocking push." >&2
  exit 2
fi

marker="$repo_root/.review-passed"

if [[ ! -f "$marker" ]]; then
  echo "Push blocked: no .review-passed marker. Run /self-review before pushing." >&2
  exit 2
fi

marker_sha="$(tr -d '[:space:]' < "$marker")"
head_sha="$(git -C "$repo_root" rev-parse HEAD)"

if [[ "$marker_sha" != "$head_sha" ]]; then
  echo "Push blocked: review marker is stale (marker=$marker_sha, HEAD=$head_sha). Re-run /self-review." >&2
  exit 2
fi

# Push allowed. Audit-log the approval consumption.
mkdir -p "$repo_root/.claude"
audit_log="$repo_root/.claude/.review-audit.log"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) push-allowed sha=$head_sha" >> "$audit_log"

exit 0
