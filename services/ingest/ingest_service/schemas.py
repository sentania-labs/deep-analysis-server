"""Pydantic schemas for the ingest service."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class ContentType(StrEnum):
    MATCH_LOG = "match-log"
    DECKLIST = "decklist"
    REFERENCE_DATA = "reference-data"
    UNKNOWN = "unknown"


class AgentClassification(StrEnum):
    """Agent-side tail-scan verdict for a match log.

    Sent by the agent as the ``agent_classification`` multipart form
    field. Optional: agents older than the field simply omit it, and a
    missing value behaves exactly as it did before the field existed.
    """

    COMPLETE = "complete"
    INCONCLUSIVE = "inconclusive"


class UploadResponse(BaseModel):
    sha256: str
    size_bytes: int
    deduped: bool
    upload_id: int
