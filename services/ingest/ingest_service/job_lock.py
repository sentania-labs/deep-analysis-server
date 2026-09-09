"""Ingest's binding of the shared job lock (``common.job_lock``).

Ingest can run more than one replica. The raw-archive backfill reads
thousands of files and writes thousands of objects; two replicas doing
it at once would double the work and the load for no benefit. The lock
row lives in ``ingest.job_runs`` because the ingest database role has
no rights in the analytics schema where the original scraper lock
lives.
"""

from __future__ import annotations

from common.job_lock import LockStore, PostgresJobLockStore

#: Schema-qualified lock table owned by the ingest service.
JOB_RUNS_TABLE = "ingest.job_runs"

_store: LockStore | None = None


def get_store() -> LockStore:
    """Process-wide lock store. Lazily bound to the ingest engine."""
    global _store
    if _store is None:
        from ingest_service.db import get_sessionmaker

        _store = PostgresJobLockStore(get_sessionmaker(), table=JOB_RUNS_TABLE)
    return _store


def set_store(store: LockStore | None) -> None:
    """Swap the store (tests) or reset it to the Postgres default."""
    global _store
    _store = store
