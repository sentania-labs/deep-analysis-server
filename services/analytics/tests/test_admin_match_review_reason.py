"""The admin match list must surface ``review_reason`` (#132).

The admin UI puts the recorded review reason into the confirmation
dialog for the visibility-changing review actions, so a reviewer can see
*why* a row is in the holding pen before accepting or rejecting it. That
only works if the list endpoint actually returns the column: it used to
select ``review_status`` alone, so every list row arrived with a null
reason.

These are source/model level checks in the style of
``test_review_status_filter.py`` -- no database is stood up here; the
composed stack covers the query end to end.
"""

from __future__ import annotations

import inspect
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session", autouse=True)
def _env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    out = tmp_path_factory.mktemp("analytics-jwt-keys-review-reason")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path = out / "jwt_public.pem"
    pub_path.write_bytes(pub_pem)
    os.environ["DA_JWT_PUBLIC_KEY_PATH"] = str(pub_path)
    os.environ.setdefault("DA_DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")
    yield pub_path


def test_admin_match_item_carries_review_reason() -> None:
    from analytics_service.schemas import AdminMatchItem

    item = AdminMatchItem(
        match_id="00000000-0000-0000-0000-000000000001",
        user_id=1,
        review_status="pending_review",
        review_reason="winner ambiguous",
    )
    assert item.review_reason == "winner ambiguous"
    assert item.model_dump(by_alias=True)["review_reason"] == "winner ambiguous"


def test_admin_match_item_review_reason_defaults_to_none() -> None:
    from analytics_service.schemas import AdminMatchItem

    item = AdminMatchItem(match_id="x", user_id=1)
    assert item.review_reason is None


def test_admin_list_matches_selects_review_reason() -> None:
    """The list query must select the column, not just the status."""
    from analytics_service import main as _main

    src = inspect.getsource(_main.admin_list_matches)
    assert "m.review_status," in src
    assert "m.review_reason," in src
    assert "review_reason=row_review_reason" in src


def test_admin_update_review_status_returns_review_reason() -> None:
    """The POST response re-reads the row; it must include the reason so
    the caller's post-update view matches the list view."""
    from analytics_service import main as _main

    src = inspect.getsource(_main.admin_update_match_review_status)
    assert "m.review_reason," in src
    assert "review_reason=row[10]" in src
