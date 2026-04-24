"""Pydantic schemas for the ingest service."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class ContentType(StrEnum):
    MATCH_LOG = "match-log"
    DECKLIST = "decklist"
    UNKNOWN = "unknown"


class UploadResponse(BaseModel):
    sha256: str
    size_bytes: int
    deduped: bool
    upload_id: int
