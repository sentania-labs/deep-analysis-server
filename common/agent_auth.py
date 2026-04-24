"""Shared agent-authentication types.

The :class:`AuthenticatedAgent` dataclass is the lingua franca for
services that accept an agent bearer API token: both ``auth`` (which
owns the table) and ``ingest`` (which cross-schema-reads it) resolve
inbound agents into this shape. The actual dependency function lives
in each service's own ``deps`` module — this module intentionally
carries no SQLAlchemy or FastAPI coupling.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass


@dataclass
class AuthenticatedAgent:
    agent_id: uuid.UUID
    user_id: int
    machine_name: str
    client_version: str | None
