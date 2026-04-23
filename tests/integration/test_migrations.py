"""Placeholder integration test.

The real assertion is that the CI job successfully ran `alembic upgrade
head` against a live Postgres before invoking pytest. This test exists
to give the harness something to collect so the pytest invocation
itself exits 0. W2+ will add real migration/query tests here.
"""

from __future__ import annotations


def test_harness_collects() -> None:
    assert True
