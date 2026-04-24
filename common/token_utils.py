"""Shared token hashing utilities.

Agent API tokens are stored SHA-256-hashed at rest in
``auth.agent_registrations.api_token_hash``. Services that need to
look an agent up by bearer token (auth, ingest) hash the inbound
token with this helper before querying.
"""

from __future__ import annotations

import hashlib


def hash_api_token(token: str) -> str:
    """Return the SHA-256 hex digest of an agent API token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
