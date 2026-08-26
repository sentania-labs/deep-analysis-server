"""Upload behaviour when the object archive is unavailable or full.

The old failure mode this replaces: storage goes away, the request
hangs on a `hard` NFS mount, and the service still answers 200 on
/healthz. Both are covered here.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from common.storage import MemoryObjectStore, ObjectStore, ObjectStoreFullError


class _FullStore(MemoryObjectStore):
    async def put(self, key: str, data: bytes, content_type: str = "") -> Any:
        raise ObjectStoreFullError("backend reported quota exceeded")


def _auth_header(api_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_token}"}


def _patch_store(monkeypatch: pytest.MonkeyPatch, store: ObjectStore) -> None:
    from ingest_service import main as _main

    monkeypatch.setattr(_main, "get_store", lambda: store)


async def test_upload_returns_503_when_store_unavailable(
    client: AsyncClient,
    seed_agent: dict[str, Any],
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broken = MemoryObjectStore()
    broken.available = False
    _patch_store(monkeypatch, broken)

    started = time.monotonic()
    r = await client.post(
        "/ingest/upload",
        files={"file": ("match.dat", b"unreachable-store body")},
        data={"original_filename": "match.dat", "content_type": "match-log"},
        headers=_auth_header(seed_agent["api_token"]),
    )
    elapsed = time.monotonic() - started

    assert r.status_code == 503, r.text
    assert r.json()["detail"]["error"] == "storage_unavailable"
    assert elapsed < 15, f"failed upload took {elapsed:.1f}s; must fail fast, not hang"

    # The row is rolled back, so the table never claims content the
    # archive does not have.
    count = (
        await db_session.execute(text("SELECT count(*) FROM ingest.game_log_files"))
    ).scalar_one()
    assert count == 0


async def test_upload_returns_507_when_store_full(
    client: AsyncClient,
    seed_agent: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_store(monkeypatch, _FullStore())

    r = await client.post(
        "/ingest/upload",
        files={"file": ("match.dat", b"full-store body")},
        data={"original_filename": "match.dat", "content_type": "match-log"},
        headers=_auth_header(seed_agent["api_token"]),
    )
    assert r.status_code == 507, r.text
    assert r.json()["detail"]["error"] == "insufficient_storage"


async def test_healthz_degrades_when_store_unreachable(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broken = MemoryObjectStore()
    broken.available = False
    _patch_store(monkeypatch, broken)

    started = time.monotonic()
    r = await client.get("/healthz")
    elapsed = time.monotonic() - started

    assert r.status_code == 503, r.text
    assert r.json()["object_store"] == "error"
    assert elapsed < 10, f"healthz took {elapsed:.1f}s with storage down"


async def test_healthz_reports_object_store_ok(client: AsyncClient) -> None:
    # Only the object_store field is asserted: the shared redis client
    # is cached across tests and its loop is closed by the time this
    # runs, which is a fixture artifact rather than anything to do with
    # storage.
    r = await client.get("/healthz")
    assert r.json()["object_store"] == "ok"


async def test_duplicate_upload_does_not_rewrite_the_object(
    client: AsyncClient,
    seed_agent: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryObjectStore()
    _patch_store(monkeypatch, store)

    for _ in range(2):
        r = await client.post(
            "/ingest/upload",
            files={"file": ("match.dat", b"same content twice")},
            data={"original_filename": "match.dat", "content_type": "match-log"},
            headers=_auth_header(seed_agent["api_token"]),
        )
        assert r.status_code == 201, r.text

    assert store.put_calls == 1
