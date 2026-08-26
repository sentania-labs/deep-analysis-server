"""S3-compatible object storage adapter.

The raw game-log archive lives in an object store, not on a shared
filesystem. ``ingest`` writes objects, ``parser`` reads them, and both
go through :class:`ObjectStore` so that moving the archive later (a
shared platform object store, a real cloud bucket) is configuration
rather than code: endpoint, key, secret, bucket.

Keys are content-addressed by sha256, which the application already
computes:

    <prefix>/<sha[0:2]>/<sha[2:4]>/<sha>

That makes the store idempotent. Re-uploading identical content is a
no-op and there is no path-collision question. The two-level shard
prefix keeps object listings navigable for an operator.

Timeouts are deliberate. The failure mode this replaces was an NFS
mount with ``hard,timeo=600`` where a storage outage blocked instead
of failing, so services hung while reporting healthy. Every call here
has a bounded connect and read timeout and a bounded retry count, so
an unreachable store surfaces as a fast error.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

_log = logging.getLogger("common.storage")

DEFAULT_KEY_PREFIX = "raw"
DEFAULT_CONTENT_TYPE = "application/octet-stream"

# Probe calls (health checks) use their own short budget: /healthz must
# answer quickly even when the store is gone, so it never inherits the
# data path's retry budget.
_PROBE_CONNECT_TIMEOUT = 1.0
_PROBE_READ_TIMEOUT = 1.5


class ObjectStorageError(RuntimeError):
    """Base class for every object-store failure."""


class ObjectNotFoundError(ObjectStorageError):
    """The requested key does not exist in the bucket."""


class ObjectStoreFullError(ObjectStorageError):
    """The backing store reported it is out of space."""


class ObjectStoreUnavailableError(ObjectStorageError):
    """The store could not be reached, or answered an unexpected error."""


@dataclass(frozen=True)
class ObjectInfo:
    """Metadata for a stored object."""

    key: str
    size_bytes: int
    content_type: str = DEFAULT_CONTENT_TYPE


@dataclass(frozen=True)
class S3Config:
    """Everything needed to place the archive. All of it is config."""

    endpoint_url: str
    access_key: str
    secret_key: str
    bucket: str
    region: str = "us-east-1"
    # MinIO and most self-hosted S3 implementations need path-style
    # addressing; AWS does not. Hence a flag rather than a hard-code.
    force_path_style: bool = True
    connect_timeout_seconds: float = 3.0
    read_timeout_seconds: float = 10.0
    max_attempts: int = 3
    key_prefix: str = DEFAULT_KEY_PREFIX


def object_key(sha256: str, prefix: str = DEFAULT_KEY_PREFIX) -> str:
    """Return the content-addressed object key for ``sha256``.

    This is the value stored in ``ingest.game_log_files.storage_path``.
    It is derivable from the sha alone, so a lost or stale column
    value is recoverable rather than fatal.
    """
    sha = sha256.strip().lower()
    if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        raise ValueError(f"not a sha256 hex digest: {sha256!r}")
    return f"{prefix}/{sha[0:2]}/{sha[2:4]}/{sha}"


class ObjectStore(ABC):
    """The storage seam. Two implementations: S3, and memory for tests."""

    @abstractmethod
    async def put(
        self,
        key: str,
        data: bytes,
        content_type: str = DEFAULT_CONTENT_TYPE,
    ) -> ObjectInfo:
        """Store ``data`` at ``key``, or no-op if the key already exists.

        Keys are content-addressed, so an existing key already holds
        the same bytes and rewriting it would be pure cost.
        """

    @abstractmethod
    async def get(self, key: str) -> bytes:
        """Return the object's bytes, or raise :class:`ObjectNotFoundError`."""

    @abstractmethod
    async def head(self, key: str) -> ObjectInfo:
        """Return object metadata without transferring the body."""

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """True if ``key`` is present."""

    @abstractmethod
    async def ping(self) -> None:
        """Cheap reachability probe. Raises on failure, returns None on success."""

    async def aclose(self) -> None:
        """Release any client resources. Safe to call more than once."""
        return None


class MemoryObjectStore(ObjectStore):
    """In-memory store. TEST FIXTURE ONLY.

    Deliberately not reachable from any production code path: no
    setting selects it and no service constructs it. Services build an
    :class:`S3ObjectStore` unconditionally.
    """

    def __init__(self) -> None:
        self._objects: dict[str, tuple[bytes, str]] = {}
        self.put_calls = 0
        self.available = True

    def _guard(self) -> None:
        if not self.available:
            raise ObjectStoreUnavailableError("memory object store marked unavailable")

    async def put(
        self,
        key: str,
        data: bytes,
        content_type: str = DEFAULT_CONTENT_TYPE,
    ) -> ObjectInfo:
        self._guard()
        existing = self._objects.get(key)
        if existing is not None:
            return ObjectInfo(key=key, size_bytes=len(existing[0]), content_type=existing[1])
        self.put_calls += 1
        self._objects[key] = (data, content_type)
        return ObjectInfo(key=key, size_bytes=len(data), content_type=content_type)

    async def get(self, key: str) -> bytes:
        self._guard()
        try:
            return self._objects[key][0]
        except KeyError as exc:
            raise ObjectNotFoundError(key) from exc

    async def head(self, key: str) -> ObjectInfo:
        self._guard()
        try:
            data, ct = self._objects[key]
        except KeyError as exc:
            raise ObjectNotFoundError(key) from exc
        return ObjectInfo(key=key, size_bytes=len(data), content_type=ct)

    async def exists(self, key: str) -> bool:
        self._guard()
        return key in self._objects

    async def ping(self) -> None:
        self._guard()

    def seed(
        self,
        key: str,
        data: bytes,
        content_type: str = DEFAULT_CONTENT_TYPE,
    ) -> None:
        """Pre-populate an object without counting it as a write."""
        self._objects[key] = (data, content_type)


@dataclass
class _ClientPair:
    """Data client plus a short-budget probe client."""

    data: Any
    probe: Any


class S3ObjectStore(ObjectStore):
    """S3-compatible implementation, backed by boto3.

    boto3 is synchronous, so every call is offloaded to a worker
    thread. That matches how this codebase already treats blocking
    archive I/O and keeps the event loop free under concurrent load.
    """

    def __init__(self, config: S3Config) -> None:
        self._config = config
        self._clients: _ClientPair | None = None

    # -- client construction ------------------------------------------------

    def _build_clients(self) -> _ClientPair:
        import boto3
        from botocore.config import Config as BotoConfig

        common: dict[str, Any] = {
            "aws_access_key_id": self._config.access_key,
            "aws_secret_access_key": self._config.secret_key,
            "region_name": self._config.region,
            "endpoint_url": self._config.endpoint_url or None,
        }
        addressing = "path" if self._config.force_path_style else "virtual"
        data = boto3.client(
            "s3",
            config=BotoConfig(
                connect_timeout=self._config.connect_timeout_seconds,
                read_timeout=self._config.read_timeout_seconds,
                retries={"max_attempts": self._config.max_attempts, "mode": "standard"},
                s3={"addressing_style": addressing},
            ),
            **common,
        )
        probe = boto3.client(
            "s3",
            config=BotoConfig(
                connect_timeout=_PROBE_CONNECT_TIMEOUT,
                read_timeout=_PROBE_READ_TIMEOUT,
                retries={"max_attempts": 1, "mode": "standard"},
                s3={"addressing_style": addressing},
            ),
            **common,
        )
        return _ClientPair(data=data, probe=probe)

    @property
    def _c(self) -> _ClientPair:
        if self._clients is None:
            self._clients = self._build_clients()
        return self._clients

    @property
    def bucket(self) -> str:
        return self._config.bucket

    @property
    def key_prefix(self) -> str:
        return self._config.key_prefix

    def key_for(self, sha256: str) -> str:
        return object_key(sha256, self._config.key_prefix)

    # -- error translation --------------------------------------------------

    @staticmethod
    def _error_code(exc: Exception) -> str:
        response = getattr(exc, "response", None) or {}
        error = response.get("Error") or {}
        return str(error.get("Code") or "")

    def _translate(self, exc: Exception, key: str | None = None) -> ObjectStorageError:
        from botocore.exceptions import ClientError

        if isinstance(exc, ClientError):
            code = self._error_code(exc)
            if code in {"NoSuchKey", "NotFound", "404"}:
                return ObjectNotFoundError(key or "unknown key")
            if code in {"XMinioStorageFull", "InsufficientStorage", "QuotaExceeded"}:
                return ObjectStoreFullError(str(exc))
            return ObjectStoreUnavailableError(f"s3 error {code or 'unknown'}: {exc}")
        return ObjectStoreUnavailableError(f"s3 unreachable: {exc}")

    # -- operations ---------------------------------------------------------

    def _head_sync(self, key: str) -> ObjectInfo:
        resp = self._c.data.head_object(Bucket=self._config.bucket, Key=key)
        return ObjectInfo(
            key=key,
            size_bytes=int(resp.get("ContentLength", 0)),
            content_type=str(resp.get("ContentType") or DEFAULT_CONTENT_TYPE),
        )

    def _put_sync(self, key: str, data: bytes, content_type: str) -> ObjectInfo:
        # Content-addressed: a present key already holds these bytes.
        try:
            return self._head_sync(key)
        except Exception as exc:  # noqa: BLE001 - translated below
            translated = self._translate(exc, key)
            if not isinstance(translated, ObjectNotFoundError):
                raise translated from exc
        try:
            self._c.data.put_object(
                Bucket=self._config.bucket,
                Key=key,
                Body=data,
                ContentType=content_type,
            )
        except Exception as exc:  # noqa: BLE001 - translated below
            raise self._translate(exc, key) from exc
        return ObjectInfo(key=key, size_bytes=len(data), content_type=content_type)

    async def put(
        self,
        key: str,
        data: bytes,
        content_type: str = DEFAULT_CONTENT_TYPE,
    ) -> ObjectInfo:
        return await asyncio.to_thread(self._put_sync, key, data, content_type)

    async def get(self, key: str) -> bytes:
        def _sync() -> bytes:
            try:
                resp = self._c.data.get_object(Bucket=self._config.bucket, Key=key)
                body: bytes = resp["Body"].read()
                return body
            except Exception as exc:  # noqa: BLE001 - translated below
                raise self._translate(exc, key) from exc

        return await asyncio.to_thread(_sync)

    async def head(self, key: str) -> ObjectInfo:
        def _sync() -> ObjectInfo:
            try:
                return self._head_sync(key)
            except Exception as exc:  # noqa: BLE001 - translated below
                raise self._translate(exc, key) from exc

        return await asyncio.to_thread(_sync)

    async def exists(self, key: str) -> bool:
        try:
            await self.head(key)
        except ObjectNotFoundError:
            return False
        return True

    async def ping(self) -> None:
        def _sync() -> None:
            try:
                self._c.probe.head_bucket(Bucket=self._config.bucket)
            except Exception as exc:  # noqa: BLE001 - translated below
                raise self._translate(exc) from exc

        await asyncio.to_thread(_sync)

    async def ensure_bucket(self) -> bool:
        """Create the bucket if it is missing. Returns True if created.

        The compose stack creates the bucket in a one-shot init
        container before any service starts. This exists for the
        backfill tool and the test suite, which may point at a store
        that has never been initialised.
        """

        def _sync() -> bool:
            from botocore.exceptions import ClientError

            try:
                self._c.data.head_bucket(Bucket=self._config.bucket)
                return False
            except ClientError as exc:
                code = self._error_code(exc)
                if code not in {"404", "NoSuchBucket", "NotFound"}:
                    raise self._translate(exc) from exc
            except Exception as exc:  # noqa: BLE001 - translated below
                raise self._translate(exc) from exc
            try:
                self._c.data.create_bucket(Bucket=self._config.bucket)
            except ClientError as exc:
                code = self._error_code(exc)
                if code in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
                    return False
                raise self._translate(exc) from exc
            return True

        return await asyncio.to_thread(_sync)

    async def aclose(self) -> None:
        clients = self._clients
        self._clients = None
        if clients is None:
            return
        for client in (clients.data, clients.probe):
            try:
                client.close()
            except Exception:  # noqa: BLE001 - best effort
                _log.debug("s3 client close failed", exc_info=True)


@dataclass
class _StoreRegistry:
    """Process-wide store, built once per service."""

    store: ObjectStore | None = field(default=None)


_registry = _StoreRegistry()


def get_object_store(config: S3Config) -> ObjectStore:
    """Return the process-wide object store, building it on first use."""
    if _registry.store is None:
        _registry.store = S3ObjectStore(config)
    return _registry.store


def reset_object_store() -> None:
    """Test hook: drop the cached store."""
    _registry.store = None
