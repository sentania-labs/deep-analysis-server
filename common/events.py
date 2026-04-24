"""
Redis pub/sub topic contracts — the AI-subscription seam.

External subscribers (e.g., deep-analysis-ai) rely on these
constants and payload shapes. Any change is a breaking contract
change — bump and coordinate.
"""

from __future__ import annotations

from typing import TypedDict

FILE_INGESTED = "file.ingested"  # producer: ingest (W3)
MATCH_PARSED = "match.parsed"  # producer: parser (W4)
INSIGHT_REQUESTED = "insight.requested"  # reserved for web/AI (W6)


class FileIngestedPayload(TypedDict, total=False):
    """Published by `ingest` when a new upload lands. Producer: W3.

    ``content_type`` is reserved for future upload kinds (decklists);
    v0.4.0 always writes ``"match-log"``. ``agent_registration_id`` is
    the UUID of the registered agent that performed the upload.
    """

    sha256: str
    user_id: int
    agent_registration_id: str  # UUID as str
    uploaded_at: str  # ISO-8601 UTC
    content_type: str  # "match-log" | "decklist" | "unknown"


class MatchParsedPayload(TypedDict, total=False):
    """Published by `parser` after a match file is fully parsed. Producer: W4."""

    match_id: str
    user_id: str
    game_count: int
    parsed_at: str  # ISO-8601 UTC


class InsightRequestedPayload(TypedDict, total=False):
    """Published by `web`/client when an AI insight is requested. Producer: W6."""

    match_id: str
    user_id: str
    request_id: str
