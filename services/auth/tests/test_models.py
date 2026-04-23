"""Integration tests for auth SQLAlchemy models.

Run with a real PostgreSQL (per project convention — no mocks for
infra). The compose stack's postgres is fine:

    DATABASE_URL=postgresql+psycopg://da:changeme@localhost:5432/deep_analysis \\
        uv run pytest services/auth/tests/test_models.py -v

The fixture runs the root Alembic head first (creates auth schema + role)
and then the auth service head (creates tables). We use Alembic here
rather than Base.metadata.create_all() because the real upgrade path —
including pgcrypto and the functional unique index on lower(email) — is
exactly what these tests need to exercise.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic.config import Config
from auth_service.models import AgentRegistration, Session, User
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import sessionmaker

from alembic import command

REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT_ALEMBIC_INI = REPO_ROOT / "alembic.ini"
AUTH_ALEMBIC_INI = REPO_ROOT / "services" / "auth" / "alembic.ini"


def _require_db() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.skip("DATABASE_URL not set; skipping auth model integration tests")
    return url


@pytest.fixture(scope="module")
def db_url() -> str:
    return _require_db()


@pytest.fixture(scope="module")
def engine(db_url: str) -> Iterator[Any]:
    eng = create_engine(db_url, future=True)
    yield eng
    eng.dispose()


@pytest.fixture(scope="module")
def migrated(engine: Any, db_url: str) -> Iterator[None]:
    # Root head first (schemas + roles), then auth head (tables).
    root_cfg = Config(str(ROOT_ALEMBIC_INI))
    root_cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    root_cfg.set_main_option("sqlalchemy.url", db_url)

    auth_cfg = Config(str(AUTH_ALEMBIC_INI))
    auth_cfg.set_main_option(
        "script_location", str(REPO_ROOT / "services" / "auth" / "alembic")
    )
    auth_cfg.set_main_option("sqlalchemy.url", db_url)

    command.upgrade(root_cfg, "head")
    command.upgrade(auth_cfg, "head")
    try:
        yield
    finally:
        command.downgrade(auth_cfg, "base")
        # Leave root head in place — other service tests may need it.


@pytest.fixture()
def session(engine: Any, migrated: None) -> Iterator[OrmSession]:
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    s = factory()
    try:
        # Clean slate per test.
        s.execute(
            text(
                "TRUNCATE auth.agent_registrations, auth.sessions, auth.users "
                "RESTART IDENTITY CASCADE"
            )
        )
        s.commit()
        yield s
    finally:
        s.rollback()
        s.close()


def _make_user(email: str = "alice@example.com") -> User:
    return User(email=email, password_hash="argon2-placeholder")


def test_user_roundtrip(session: OrmSession) -> None:
    u = _make_user()
    session.add(u)
    session.commit()
    session.refresh(u)
    assert u.id is not None
    assert u.email == "alice@example.com"
    assert u.role == "user"
    assert u.disabled is False
    assert u.must_change_password is False


def test_user_email_unique(session: OrmSession) -> None:
    session.add(_make_user("dup@example.com"))
    session.commit()
    session.add(_make_user("dup@example.com"))
    with pytest.raises(IntegrityError):
        session.commit()


def test_user_role_check(session: OrmSession) -> None:
    u = _make_user("bad-role@example.com")
    u.role = "superuser"
    session.add(u)
    with pytest.raises(IntegrityError):
        session.commit()


def test_session_fk_cascade(session: OrmSession) -> None:
    u = _make_user("fk@example.com")
    session.add(u)
    session.commit()
    session.refresh(u)

    now = datetime.now(UTC)
    s = Session(
        user_id=u.id,
        refresh_token_hash=f"hash-{uuid.uuid4()}",
        issued_at=now,
        expires_at=now + timedelta(days=1),
    )
    session.add(s)
    session.commit()
    session.refresh(s)
    sid = s.id

    session.delete(u)
    session.commit()

    remaining = session.execute(
        text("SELECT count(*) FROM auth.sessions WHERE id = :id"), {"id": sid}
    ).scalar_one()
    assert remaining == 0


def test_agent_registration_token_unique(session: OrmSession) -> None:
    u = _make_user("agent-owner@example.com")
    session.add(u)
    session.commit()
    session.refresh(u)

    token = f"token-{uuid.uuid4()}"
    session.add(
        AgentRegistration(user_id=u.id, machine_name="box-a", api_token_hash=token)
    )
    session.commit()

    session.add(
        AgentRegistration(user_id=u.id, machine_name="box-b", api_token_hash=token)
    )
    with pytest.raises(IntegrityError):
        session.commit()
