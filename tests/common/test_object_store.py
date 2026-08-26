"""Object storage adapter: round trip, idempotency, fast failure.

Runs against a real S3 server (moto in server mode) over real HTTP, so
the boto3 client, the path-style addressing and the timeout config are
all exercised the way they are in the stack. No Docker daemon needed,
which matters because the CI runners do not have one.
"""

from __future__ import annotations

import hashlib
import socket
import time
from collections.abc import Iterator

import pytest

from common.health import check_object_store
from common.storage import (
    MemoryObjectStore,
    ObjectNotFoundError,
    ObjectStorageError,
    ObjectStoreUnavailableError,
    S3Config,
    S3ObjectStore,
    get_object_store,
    object_key,
    reset_object_store,
)

BUCKET = "test-raw"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def s3_endpoint() -> Iterator[str]:
    from moto.server import ThreadedMotoServer

    port = _free_port()
    server = ThreadedMotoServer(port=port, verbose=False)
    server.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.stop()


def _config(endpoint: str, **overrides: object) -> S3Config:
    base = {
        "endpoint_url": endpoint,
        "access_key": "test",
        "secret_key": "testsecret",
        "bucket": BUCKET,
        "force_path_style": True,
    }
    base.update(overrides)
    return S3Config(**base)  # type: ignore[arg-type]


@pytest.fixture
async def store(s3_endpoint: str) -> S3ObjectStore:
    st = S3ObjectStore(_config(s3_endpoint))
    await st.ensure_bucket()
    return st


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def test_object_key_is_sharded_by_sha() -> None:
    sha = "ab" + "c" * 62
    assert object_key(sha) == f"raw/ab/cc/{sha}"


def test_object_key_honours_prefix() -> None:
    sha = "0" * 64
    assert object_key(sha, "archive") == f"archive/00/00/{sha}"


@pytest.mark.parametrize("bad", ["", "abc", "z" * 64, "A" * 63])
def test_object_key_rejects_non_sha(bad: str) -> None:
    with pytest.raises(ValueError):
        object_key(bad)


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------


async def test_put_get_head_exists_round_trip(store: S3ObjectStore) -> None:
    content = b"MTGO match log payload\n" * 50
    sha = hashlib.sha256(content).hexdigest()
    key = store.key_for(sha)

    assert await store.exists(key) is False

    info = await store.put(key, content, content_type="application/octet-stream")
    assert info.size_bytes == len(content)

    assert await store.exists(key) is True
    assert await store.get(key) == content

    head = await store.head(key)
    assert head.size_bytes == len(content)
    assert head.content_type == "application/octet-stream"


async def test_get_missing_key_raises_not_found(store: S3ObjectStore) -> None:
    with pytest.raises(ObjectNotFoundError):
        await store.get(store.key_for("f" * 64))


async def test_head_missing_key_raises_not_found(store: S3ObjectStore) -> None:
    with pytest.raises(ObjectNotFoundError):
        await store.head(store.key_for("e" * 64))


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


async def test_put_twice_is_a_no_op(store: S3ObjectStore, monkeypatch: pytest.MonkeyPatch) -> None:
    content = b"identical bytes"
    sha = hashlib.sha256(content).hexdigest()
    key = store.key_for(sha)

    await store.put(key, content)

    calls: list[str] = []
    real_put = store._c.data.put_object

    def _counting_put(**kwargs: object) -> object:
        calls.append(str(kwargs.get("Key")))
        return real_put(**kwargs)

    monkeypatch.setattr(store._c.data, "put_object", _counting_put)

    info = await store.put(key, content)

    assert calls == [], "second put must not re-upload identical content"
    assert info.size_bytes == len(content)
    assert await store.get(key) == content


async def test_ensure_bucket_is_idempotent(s3_endpoint: str) -> None:
    st = S3ObjectStore(_config(s3_endpoint, bucket="ensure-twice"))
    assert await st.ensure_bucket() is True
    assert await st.ensure_bucket() is False


# ---------------------------------------------------------------------------
# Failure behaviour: fast and clear, never a hang
# ---------------------------------------------------------------------------


async def test_unreachable_store_fails_fast() -> None:
    dead = S3ObjectStore(
        _config(
            f"http://127.0.0.1:{_free_port()}",
            connect_timeout_seconds=1.0,
            read_timeout_seconds=1.0,
            max_attempts=1,
        )
    )
    started = time.monotonic()
    with pytest.raises(ObjectStorageError) as exc:
        await dead.get(dead.key_for("a" * 64))
    elapsed = time.monotonic() - started

    assert isinstance(exc.value, ObjectStoreUnavailableError)
    assert elapsed < 10, f"unreachable store took {elapsed:.1f}s to fail"


async def test_unreachable_store_reports_unhealthy_quickly() -> None:
    dead = S3ObjectStore(_config(f"http://127.0.0.1:{_free_port()}"))
    started = time.monotonic()
    result = await check_object_store(dead)
    elapsed = time.monotonic() - started

    assert result.ok is False
    assert result.name == "object_store"
    # common.health caps every probe at 2 seconds.
    assert elapsed < 4, f"healthz probe took {elapsed:.1f}s"


async def test_healthy_store_reports_ok(store: S3ObjectStore) -> None:
    result = await check_object_store(store)
    assert result.ok is True


async def test_ping_on_missing_bucket_fails(s3_endpoint: str) -> None:
    st = S3ObjectStore(_config(s3_endpoint, bucket="never-created"))
    with pytest.raises(ObjectStorageError):
        await st.ping()


# ---------------------------------------------------------------------------
# Process-wide store + the test-only memory implementation
# ---------------------------------------------------------------------------


def test_get_object_store_is_cached(s3_endpoint: str) -> None:
    reset_object_store()
    try:
        first = get_object_store(_config(s3_endpoint))
        second = get_object_store(_config(s3_endpoint))
        assert first is second
    finally:
        reset_object_store()


async def test_memory_store_matches_the_contract() -> None:
    mem = MemoryObjectStore()
    key = object_key("b" * 64)

    assert await mem.exists(key) is False
    await mem.put(key, b"payload")
    await mem.put(key, b"payload")
    assert mem.put_calls == 1
    assert await mem.get(key) == b"payload"
    assert (await mem.head(key)).size_bytes == 7
    await mem.ping()

    mem.available = False
    with pytest.raises(ObjectStorageError):
        await mem.get(key)
