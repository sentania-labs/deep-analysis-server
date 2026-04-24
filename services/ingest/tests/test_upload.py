"""Upload endpoint — end-to-end with real Postgres + Redis."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def _auth_header(api_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_token}"}


async def test_upload_requires_bearer(client: AsyncClient) -> None:
    r = await client.post("/ingest/upload", files={"file": ("x.dat", b"data")})
    assert r.status_code == 401


async def test_upload_rejects_bad_token(client: AsyncClient) -> None:
    r = await client.post(
        "/ingest/upload",
        files={"file": ("x.dat", b"data")},
        headers=_auth_header("not-a-real-token"),
    )
    assert r.status_code == 401


async def test_upload_happy_path(
    client: AsyncClient,
    seed_agent: dict[str, Any],
    db_session: AsyncSession,
) -> None:
    body = b"match log content example"
    sha = hashlib.sha256(body).hexdigest()
    r = await client.post(
        "/ingest/upload",
        files={"file": ("match.dat", body)},
        data={"original_filename": "match.dat", "content_type": "match-log"},
        headers=_auth_header(seed_agent["api_token"]),
    )
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["sha256"] == sha
    assert j["size_bytes"] == len(body)
    assert j["deduped"] is False
    assert isinstance(j["upload_id"], int)

    # game_log_files row written, raw file on disk.
    row = (
        await db_session.execute(
            text(
                "SELECT size_bytes, content_type, storage_path "
                "FROM ingest.game_log_files WHERE sha256 = :s"
            ),
            {"s": sha},
        )
    ).one()
    assert row[0] == len(body)
    assert row[1] == "match-log"
    assert row[2] == f"{sha[0:2]}/{sha[2:4]}/{sha}.dat"

    raw_root = os.environ["DA_INGEST_RAW_PATH"]
    with open(os.path.join(raw_root, row[2]), "rb") as fh:
        assert fh.read() == body


async def test_upload_oversize_returns_413(client: AsyncClient, seed_agent: dict[str, Any]) -> None:
    # DA_INGEST_MAX_FILE_BYTES=1024 in conftest.
    body = b"A" * 2048
    r = await client.post(
        "/ingest/upload",
        files={"file": ("big.dat", body)},
        headers=_auth_header(seed_agent["api_token"]),
    )
    assert r.status_code == 413


async def test_upload_missing_file_returns_400(
    client: AsyncClient, seed_agent: dict[str, Any]
) -> None:
    # FastAPI returns 422 when the required form field is absent, but
    # the *wrong-content-type* (non-multipart) path is also a client
    # error. We accept either shape — both are unambiguously 4xx and
    # both indicate the client failed to supply a file.
    r = await client.post(
        "/ingest/upload",
        headers={
            **_auth_header(seed_agent["api_token"]),
            "content-type": "application/json",
        },
        content=b"{}",
    )
    assert r.status_code in (400, 422)


async def test_upload_dedup_records_attribution_and_skips_event(
    client: AsyncClient,
    seed_agent: dict[str, Any],
    db_session: AsyncSession,
    redis_client: Any,
) -> None:
    body = b"dedup-content"
    sha = hashlib.sha256(body).hexdigest()

    # Subscribe BEFORE the first upload; collect in a background task.
    received: list[dict[str, Any]] = []
    pubsub = redis_client.pubsub()
    await pubsub.subscribe("file.ingested")

    async def _reader() -> None:
        # Drain up to ~1s of messages.
        try:
            async with asyncio.timeout(1.2):
                async for msg in pubsub.listen():
                    if msg.get("type") != "message":
                        continue
                    raw = msg.get("data")
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8")
                    received.append(json.loads(raw))
        except TimeoutError:
            return

    reader_task = asyncio.create_task(_reader())
    # Give subscribe a moment to register.
    await asyncio.sleep(0.05)

    r1 = await client.post(
        "/ingest/upload",
        files={"file": ("a.dat", body)},
        headers=_auth_header(seed_agent["api_token"]),
    )
    assert r1.status_code == 201
    assert r1.json()["deduped"] is False

    r2 = await client.post(
        "/ingest/upload",
        files={"file": ("b.dat", body)},
        headers=_auth_header(seed_agent["api_token"]),
    )
    assert r2.status_code == 201
    j2 = r2.json()
    assert j2["deduped"] is True
    assert j2["sha256"] == sha
    # Fresh attribution id each time.
    assert j2["upload_id"] != r1.json()["upload_id"]

    await reader_task
    await pubsub.unsubscribe("file.ingested")
    await pubsub.aclose()

    # Exactly one file.ingested event for two uploads of the same body.
    assert len(received) == 1, received
    payload = received[0]
    assert payload["sha256"] == sha
    assert payload["user_id"] == seed_agent["user_id"]
    assert payload["agent_registration_id"] == str(seed_agent["agent_id"])
    assert payload["content_type"] == "match-log"
    assert "uploaded_at" in payload

    # Two user_uploads rows attributing the same content.
    n = (
        await db_session.execute(
            text("SELECT count(*) FROM ingest.user_uploads WHERE sha256 = :s"),
            {"s": sha},
        )
    ).scalar_one()
    assert n == 2


@pytest.mark.parametrize("content_type", ["match-log", "unknown"])
async def test_upload_accepts_known_content_types(
    client: AsyncClient, seed_agent: dict[str, Any], content_type: str
) -> None:
    body = f"body-{content_type}".encode()
    r = await client.post(
        "/ingest/upload",
        files={"file": ("x", body)},
        data={"content_type": content_type},
        headers=_auth_header(seed_agent["api_token"]),
    )
    assert r.status_code == 201


async def test_upload_rejects_unknown_content_type_value(
    client: AsyncClient, seed_agent: dict[str, Any]
) -> None:
    r = await client.post(
        "/ingest/upload",
        files={"file": ("x", b"x")},
        data={"content_type": "not-a-valid-type"},
        headers=_auth_header(seed_agent["api_token"]),
    )
    # pydantic enum coercion → 422.
    assert r.status_code == 422
