"""Migration round-trip: 002 reassign-admin-agents.

Verifies the W3.6 sub-item 1 reassign-not-delete migration:

    upgrade   → admin-owned agents transferred to the configured target
    downgrade → prior ownership restored from the inverse log table

Runs against a real Postgres (no mocks for infra). Drives Alembic
directly so we get the same upgrade path as production.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from alembic import command

REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT_ALEMBIC_INI = REPO_ROOT / "alembic.ini"
AUTH_ALEMBIC_INI = REPO_ROOT / "services" / "auth" / "alembic.ini"


def _require_db() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.skip("DATABASE_URL not set; skipping migration integration tests")
    return url


def _auth_cfg(db_url: str) -> Config:
    cfg = Config(str(AUTH_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(REPO_ROOT / "services" / "auth" / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def _root_cfg(db_url: str) -> Config:
    cfg = Config(str(ROOT_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@pytest.fixture(scope="module")
def db_url() -> str:
    return _require_db()


@pytest.fixture(scope="module")
def engine(db_url: str) -> Iterator[Engine]:
    eng = create_engine(db_url, future=True)
    yield eng
    eng.dispose()


def _truncate(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE auth.agent_registrations, auth.sessions, auth.users "
                "RESTART IDENTITY CASCADE"
            )
        )


@pytest.fixture()
def at_001(engine: Engine, db_url: str) -> Iterator[Engine]:
    """Bring the auth head down to 001 with empty tables for the test.

    The auth-service test session leaves migrations in place at module
    teardown (see services/auth/tests/conftest.py); we re-anchor at
    001 here so each test in this module sees a clean pre-002 state.
    Truncating BEFORE the up-then-down dance keeps any residue from a
    prior test (admin users with agents but no reassignment target)
    from tripping the 002 upgrade pre-condition during setup.
    """
    # Ensure root head (auth schema + role) so subsequent ALTERs work.
    command.upgrade(_root_cfg(db_url), "head")
    # Make sure auth tables exist before truncating, then wipe them
    # before the up-then-down cycle so old state can't blow up 002.
    command.upgrade(_auth_cfg(db_url), "001")
    _truncate(engine)
    command.upgrade(_auth_cfg(db_url), "head")
    command.downgrade(_auth_cfg(db_url), "001")
    yield engine
    # Wipe and re-upgrade so the DB lands at head with empty tables —
    # leaves a known-good state for any subsequent tests in this session.
    _truncate(engine)
    command.upgrade(_auth_cfg(db_url), "head")


def _seed_user(engine: Engine, email: str, role: str) -> int:
    with engine.begin() as conn:
        row = conn.execute(
            text(
                "INSERT INTO auth.users (email, password_hash, role) "
                "VALUES (:email, 'placeholder', :role) RETURNING id"
            ),
            {"email": email, "role": role},
        ).fetchone()
    assert row is not None
    return int(row.id)


def _seed_agent(engine: Engine, user_id: int, machine_name: str) -> uuid.UUID:
    token = f"token-{uuid.uuid4()}"
    with engine.begin() as conn:
        row = conn.execute(
            text(
                "INSERT INTO auth.agent_registrations "
                "(user_id, machine_name, api_token_hash) "
                "VALUES (:uid, :mn, :tok) RETURNING id"
            ),
            {"uid": user_id, "mn": machine_name, "tok": token},
        ).fetchone()
    assert row is not None
    return uuid.UUID(str(row.id))


def _agent_owner(engine: Engine, agent_id: uuid.UUID) -> int | None:
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT user_id FROM auth.agent_registrations WHERE id = :aid"),
            {"aid": agent_id},
        ).fetchone()
    return None if row is None else int(row.user_id)


def _log_rows(engine: Engine) -> list[dict[str, Any]]:
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                "SELECT agent_id, prior_user_id, new_user_id "
                "FROM auth._agent_reassignment_log ORDER BY id"
            )
        ).fetchall()
    return [dict(r._mapping) for r in rows]


def _log_table_exists(engine: Engine) -> bool:
    with engine.begin() as conn:
        row = conn.execute(
            text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = 'auth' AND table_name = '_agent_reassignment_log'"
            )
        ).fetchone()
    return row is not None


def test_upgrade_reassigns_admin_agents_and_downgrade_restores(
    at_001: Engine,
    db_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round-trip: admin-owned agents move to the env-configured target,
    then on downgrade the inverse log replays prior ownership.
    """
    admin_id = _seed_user(at_001, email="admin@local", role="admin")
    target_id = _seed_user(at_001, email="testuser@local", role="user")
    bystander_id = _seed_user(at_001, email="bystander@example.com", role="user")

    admin_agent_a = _seed_agent(at_001, admin_id, "admin-laptop")
    admin_agent_b = _seed_agent(at_001, admin_id, "admin-workstation")
    bystander_agent = _seed_agent(at_001, bystander_id, "bystander-box")

    # Default target email (no env override).
    monkeypatch.delenv("DA_AGENT_REASSIGN_TARGET_EMAIL", raising=False)

    command.upgrade(_auth_cfg(db_url), "head")

    assert _agent_owner(at_001, admin_agent_a) == target_id
    assert _agent_owner(at_001, admin_agent_b) == target_id
    assert _agent_owner(at_001, bystander_agent) == bystander_id

    log = _log_rows(at_001)
    moved = {(uuid.UUID(str(r["agent_id"])), int(r["prior_user_id"])) for r in log}
    assert moved == {(admin_agent_a, admin_id), (admin_agent_b, admin_id)}
    assert all(int(r["new_user_id"]) == target_id for r in log)

    command.downgrade(_auth_cfg(db_url), "001")

    assert _agent_owner(at_001, admin_agent_a) == admin_id
    assert _agent_owner(at_001, admin_agent_b) == admin_id
    assert _agent_owner(at_001, bystander_agent) == bystander_id
    assert not _log_table_exists(at_001)


def test_upgrade_no_admin_agents_is_noop(
    at_001: Engine,
    db_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No admin-owned agents → empty log table created; user agents
    stay put. Target user need not exist in this case.
    """
    user_id = _seed_user(at_001, email="member@example.com", role="user")
    user_agent = _seed_agent(at_001, user_id, "member-laptop")

    monkeypatch.setenv("DA_AGENT_REASSIGN_TARGET_EMAIL", "ghost@nowhere.local")

    command.upgrade(_auth_cfg(db_url), "head")

    assert _agent_owner(at_001, user_agent) == user_id
    assert _log_rows(at_001) == []
    assert _log_table_exists(at_001)


def test_upgrade_uses_env_var_target(
    at_001: Engine,
    db_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DA_AGENT_REASSIGN_TARGET_EMAIL overrides the testuser@local
    default. Confirms the env var actually wires through.
    """
    admin_id = _seed_user(at_001, email="admin@local", role="admin")
    _seed_user(at_001, email="testuser@local", role="user")
    custom_target = _seed_user(at_001, email="custom@example.com", role="user")
    admin_agent = _seed_agent(at_001, admin_id, "admin-laptop")

    monkeypatch.setenv("DA_AGENT_REASSIGN_TARGET_EMAIL", "custom@example.com")

    command.upgrade(_auth_cfg(db_url), "head")

    assert _agent_owner(at_001, admin_agent) == custom_target


def test_downgrade_skips_restore_when_prior_owner_deleted(
    at_001: Engine,
    db_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the prior admin owner is deleted between upgrade and downgrade,
    the restore for that row is skipped (warned), and the rest of the
    downgrade — including other agents and dropping the log table —
    completes cleanly.
    """
    admin_id = _seed_user(at_001, email="admin@local", role="admin")
    survivor_admin_id = _seed_user(at_001, email="boss@local", role="admin")
    target_id = _seed_user(at_001, email="testuser@local", role="user")

    orphaned_agent = _seed_agent(at_001, admin_id, "doomed-admin-laptop")
    survivor_agent = _seed_agent(at_001, survivor_admin_id, "boss-laptop")

    monkeypatch.delenv("DA_AGENT_REASSIGN_TARGET_EMAIL", raising=False)
    command.upgrade(_auth_cfg(db_url), "head")

    assert _agent_owner(at_001, orphaned_agent) == target_id
    assert _agent_owner(at_001, survivor_agent) == target_id

    # Delete the prior owner of `orphaned_agent` — simulates an admin
    # account purge between upgrade and downgrade.
    with at_001.begin() as conn:
        conn.execute(text("DELETE FROM auth.users WHERE id = :uid"), {"uid": admin_id})

    # Downgrade must not raise even though one prior owner is gone.
    command.downgrade(_auth_cfg(db_url), "001")

    # The orphaned agent stays with the post-reassignment owner (target),
    # because restoring it would have violated the FK. The survivor's
    # prior ownership is restored normally. Log table is dropped either way.
    assert _agent_owner(at_001, orphaned_agent) == target_id
    assert _agent_owner(at_001, survivor_agent) == survivor_admin_id
    assert not _log_table_exists(at_001)


def test_upgrade_fails_when_target_missing(
    at_001: Engine,
    db_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If admin-owned agents exist but the target is absent, fail loud.
    Don't silently swallow the data movement.
    """
    admin_id = _seed_user(at_001, email="admin@local", role="admin")
    _seed_agent(at_001, admin_id, "admin-laptop")

    monkeypatch.setenv("DA_AGENT_REASSIGN_TARGET_EMAIL", "definitely-absent@example.com")

    with pytest.raises(RuntimeError, match="reassignment target"):
        command.upgrade(_auth_cfg(db_url), "head")


def test_upgrade_fails_when_target_is_admin(
    at_001: Engine,
    db_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the resolved target user is itself an admin, fail loud rather
    than reassigning admin-owned agents to another admin (which would
    leave the data in violation of the W3.6 admin-owns-no-agents rule).
    """
    admin_id = _seed_user(at_001, email="admin@local", role="admin")
    _seed_agent(at_001, admin_id, "admin-laptop")
    _seed_user(at_001, email="target-admin@example.com", role="admin")

    monkeypatch.setenv("DA_AGENT_REASSIGN_TARGET_EMAIL", "target-admin@example.com")

    with pytest.raises(RuntimeError, match="admin user"):
        command.upgrade(_auth_cfg(db_url), "head")
