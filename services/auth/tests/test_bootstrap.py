"""First-boot admin bootstrap tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from auth_service.bootstrap import bootstrap_admin, force_reset_admin, reclaim_uid1
from auth_service.models import User
from auth_service.passwords import hash_password, verify_password
from auth_service.settings import AuthSettings
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession


def _fresh_settings(
    tmp_path: Path,
    email: str | None = None,
    pw: str | None = None,
    force_admin_reset: bool = False,
) -> AuthSettings:
    return AuthSettings(
        service_name="auth",
        database_url=os.environ["DA_DATABASE_URL"],
        redis_url=os.environ.get("DA_REDIS_URL", "redis://localhost:6379/0"),
        jwt_public_key_path=Path(os.environ["DA_JWT_PUBLIC_KEY_PATH"]),
        jwt_private_key_path=Path(os.environ["DA_JWT_PRIVATE_KEY_PATH"]),
        bootstrap_admin_email=email,
        bootstrap_admin_password=pw,
        force_admin_reset=force_admin_reset,
        initial_admin_secret_path=tmp_path / "initial_admin.txt",
    )


@pytest.mark.asyncio
async def test_bootstrap_creates_admin_and_writes_file(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    settings = _fresh_settings(tmp_path)
    await bootstrap_admin(db_session, settings)

    users = (await db_session.execute(select(User))).scalars().all()
    assert len(users) == 1
    admin = users[0]
    assert admin.email == "admin@local"
    assert admin.role == "admin"
    assert admin.disabled is False
    assert admin.must_change_password is True

    secret = settings.initial_admin_secret_path
    assert secret.exists()
    password = secret.read_text().strip()
    assert len(password) >= 20
    assert verify_password(password, admin.password_hash)


@pytest.mark.asyncio
async def test_bootstrap_file_permissions_are_0600(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    settings = _fresh_settings(tmp_path)
    await bootstrap_admin(db_session, settings)
    mode = settings.initial_admin_secret_path.stat().st_mode & 0o777
    assert mode == 0o600


@pytest.mark.asyncio
async def test_bootstrap_is_idempotent(db_session: AsyncSession, tmp_path: Path) -> None:
    settings = _fresh_settings(tmp_path)
    await bootstrap_admin(db_session, settings)
    await bootstrap_admin(db_session, settings)

    count = (await db_session.execute(select(func.count()).select_from(User))).scalar_one()
    assert count == 1


@pytest.mark.asyncio
async def test_bootstrap_noop_when_admin_exists(db_session: AsyncSession, tmp_path: Path) -> None:
    existing = User(
        email="someone@example.com",
        password_hash=hash_password("pw"),
        role="admin",
    )
    db_session.add(existing)
    await db_session.commit()

    settings = _fresh_settings(tmp_path)
    await bootstrap_admin(db_session, settings)

    count = (await db_session.execute(select(func.count()).select_from(User))).scalar_one()
    assert count == 1
    assert not settings.initial_admin_secret_path.exists()


@pytest.mark.asyncio
async def test_bootstrap_noop_when_disabled_admin_has_other_active(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    # Pin the disabled admin to id=2 so UID 1 stays free for the
    # admin@local bootstrap insert (which pins to id=1).
    disabled_admin = User(
        id=2,
        email="old-admin@example.com",
        password_hash=hash_password("pw"),
        role="admin",
        disabled=True,
    )
    db_session.add(disabled_admin)
    await db_session.commit()

    settings = _fresh_settings(tmp_path)
    await bootstrap_admin(db_session, settings)

    # disabled admin doesn't count — a new one should be created
    admins = (
        (
            await db_session.execute(
                select(User).where(User.role == "admin", User.disabled.is_(False))
            )
        )
        .scalars()
        .all()
    )
    assert len(admins) == 1
    assert admins[0].email == "admin@local"


@pytest.mark.asyncio
async def test_bootstrap_env_var_path_no_file_written(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    settings = _fresh_settings(tmp_path, email="scripted@example.com", pw="scripted-password-xyz")
    await bootstrap_admin(db_session, settings)

    admin = (
        await db_session.execute(select(User).where(User.email == "scripted@example.com"))
    ).scalar_one()
    assert admin.role == "admin"
    assert admin.must_change_password is False
    assert verify_password("scripted-password-xyz", admin.password_hash)
    assert not settings.initial_admin_secret_path.exists()


@pytest.mark.asyncio
async def test_bootstrap_env_var_path_idempotent_on_restart(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    """Simulate container restart: env vars present, user already exists.
    Bootstrap must not create a second admin."""
    settings = _fresh_settings(tmp_path, email="admin@local", pw="strongpassword123x")
    # First startup: creates the user
    await bootstrap_admin(db_session, settings)
    # Second startup (restart): must be a no-op
    await bootstrap_admin(db_session, settings)

    count = (await db_session.execute(select(func.count()).select_from(User))).scalar_one()
    assert count == 1


@pytest.mark.asyncio
async def test_force_reset_updates_password_in_place(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    """force_admin_reset=True with valid env credentials updates the
    existing user's password hash in place — preserving their id."""
    existing = User(
        email="admin@local",
        password_hash=hash_password("garbled-old-hash"),
        role="admin",
        disabled=False,
    )
    db_session.add(existing)
    await db_session.commit()
    old_id = existing.id

    settings = _fresh_settings(
        tmp_path,
        email="admin@local",
        pw="freshpassword456y",
        force_admin_reset=True,
    )
    result = await force_reset_admin(db_session, settings)
    assert result is True

    admins = (
        (await db_session.execute(select(User).where(User.email == "admin@local"))).scalars().all()
    )
    assert len(admins) == 1
    admin = admins[0]
    assert admin.id == old_id
    assert admin.role == "admin"
    assert admin.disabled is False
    assert admin.must_change_password is False
    assert verify_password("freshpassword456y", admin.password_hash)


@pytest.mark.asyncio
async def test_force_reset_creates_admin_when_none_exists(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    """force_admin_reset=True with no pre-existing user still creates the admin."""
    settings = _fresh_settings(
        tmp_path,
        email="admin@local",
        pw="brandnewpassword789z",
        force_admin_reset=True,
    )
    result = await force_reset_admin(db_session, settings)
    assert result is True

    admin = (await db_session.execute(select(User).where(User.email == "admin@local"))).scalar_one()
    assert admin.role == "admin"
    assert verify_password("brandnewpassword789z", admin.password_hash)


@pytest.mark.asyncio
async def test_force_reset_skips_when_credentials_missing(
    db_session: AsyncSession,
    tmp_path: Path,
) -> None:
    """force_admin_reset=True without bootstrap email/password returns False
    without touching any users.

    Note: the implementation also logs an ERROR, but we don't assert on caplog
    here — structlog's ``configure_logging(force=True)`` can wipe pytest's
    caplog handler depending on test-module import order, making such
    assertions non-deterministically flaky. The two assertions below fully
    prove the guard path ran: False return + untouched password hash.
    """
    existing = User(
        email="admin@local",
        password_hash=hash_password("untouched"),
        role="admin",
        disabled=False,
    )
    db_session.add(existing)
    await db_session.commit()

    settings = _fresh_settings(tmp_path, email=None, pw=None, force_admin_reset=True)
    result = await force_reset_admin(db_session, settings)
    assert result is False

    admin = (await db_session.execute(select(User).where(User.email == "admin@local"))).scalar_one()
    assert verify_password("untouched", admin.password_hash)


@pytest.mark.asyncio
async def test_force_reset_disabled_by_default(db_session: AsyncSession, tmp_path: Path) -> None:
    """force_admin_reset defaults to False; force_reset_admin returns False
    and bootstrap_admin falls through to the normal idempotent path."""
    settings = _fresh_settings(tmp_path, email="admin@local", pw="somepassword123x")
    assert settings.force_admin_reset is False

    result = await force_reset_admin(db_session, settings)
    assert result is False

    count = (await db_session.execute(select(func.count()).select_from(User))).scalar_one()
    assert count == 0


@pytest.mark.asyncio
async def test_bootstrap_admin_invokes_force_reset_first(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    """When force_admin_reset is set, bootstrap_admin updates the existing
    admin's password instead of treating it as already-bootstrapped."""
    existing = User(
        email="admin@local",
        password_hash=hash_password("garbled"),
        role="admin",
        disabled=False,
    )
    db_session.add(existing)
    await db_session.commit()
    old_id = existing.id

    settings = _fresh_settings(
        tmp_path,
        email="admin@local",
        pw="resetviabootstrap",
        force_admin_reset=True,
    )
    await bootstrap_admin(db_session, settings)

    admin = (await db_session.execute(select(User).where(User.email == "admin@local"))).scalar_one()
    assert admin.id == old_id
    assert verify_password("resetviabootstrap", admin.password_hash)
    assert not settings.initial_admin_secret_path.exists()


@pytest.mark.asyncio
async def test_bootstrap_creates_admin_at_id_1(db_session: AsyncSession, tmp_path: Path) -> None:
    """Empty-table bootstrap pins the admin to UID 1, not the next
    sequence value."""
    settings = _fresh_settings(tmp_path)
    await bootstrap_admin(db_session, settings)

    admin = (await db_session.execute(select(User).where(User.email == "admin@local"))).scalar_one()
    assert admin.id == 1


@pytest.mark.asyncio
async def test_bootstrap_id_1_pin_does_not_break_next_insert(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    """After explicit-id=1 insert, the users sequence is resynced so the
    next user-driven insert does not collide on id=1."""
    settings = _fresh_settings(tmp_path)
    await bootstrap_admin(db_session, settings)

    other = User(
        email="someone-else@example.com",
        password_hash=hash_password("pw"),
        role="user",
    )
    db_session.add(other)
    await db_session.commit()
    await db_session.refresh(other)
    assert other.id > 1


@pytest.mark.asyncio
async def test_reclaim_uid1_moves_admin_when_id_1_is_free(
    db_session: AsyncSession,
) -> None:
    """admin@local sitting at id != 1 with UID 1 free is reclaimed to id=1."""
    placeholder = User(
        email="placeholder@example.com",
        password_hash=hash_password("pw"),
        role="user",
    )
    db_session.add(placeholder)
    await db_session.commit()

    admin = User(
        email="admin@local",
        password_hash=hash_password("pw"),
        role="admin",
    )
    db_session.add(admin)
    await db_session.commit()
    assert admin.id != 1

    await db_session.execute(text("DELETE FROM auth.users WHERE email = 'placeholder@example.com'"))
    await db_session.commit()

    await reclaim_uid1(db_session)

    reclaimed = (
        await db_session.execute(select(User).where(User.email == "admin@local"))
    ).scalar_one()
    assert reclaimed.id == 1


@pytest.mark.asyncio
async def test_reclaim_uid1_cascades_to_sessions_and_agents(
    db_session: AsyncSession,
) -> None:
    """When admin@local has child rows pointing at the old id, the
    ON UPDATE CASCADE FK propagates the new id=1 to sessions and
    agent_registrations. No FK violation, no data loss."""
    from datetime import UTC, datetime, timedelta

    from auth_service.models import AgentRegistration, Session

    placeholder = User(
        email="placeholder@example.com",
        password_hash=hash_password("pw"),
        role="user",
    )
    db_session.add(placeholder)
    await db_session.commit()

    admin = User(
        email="admin@local",
        password_hash=hash_password("pw"),
        role="admin",
    )
    db_session.add(admin)
    await db_session.commit()
    old_admin_id = admin.id
    assert old_admin_id != 1

    session = Session(
        user_id=old_admin_id,
        refresh_token_hash="hash-for-reclaim-test",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    agent = AgentRegistration(
        user_id=old_admin_id,
        machine_name="reclaim-test-host",
        api_token_hash="agent-hash-for-reclaim-test",
    )
    db_session.add(session)
    db_session.add(agent)
    await db_session.commit()

    await db_session.execute(text("DELETE FROM auth.users WHERE email = 'placeholder@example.com'"))
    await db_session.commit()

    await reclaim_uid1(db_session)

    # CASCADE happens in the database; clear the ORM identity map so the
    # next selects re-read user_id from the DB rather than returning the
    # cached pre-update objects.
    db_session.expire_all()

    reclaimed = (
        await db_session.execute(select(User).where(User.email == "admin@local"))
    ).scalar_one()
    assert reclaimed.id == 1

    refreshed_session = (
        await db_session.execute(
            select(Session).where(Session.refresh_token_hash == "hash-for-reclaim-test")
        )
    ).scalar_one()
    refreshed_agent = (
        await db_session.execute(
            select(AgentRegistration).where(
                AgentRegistration.api_token_hash == "agent-hash-for-reclaim-test"
            )
        )
    ).scalar_one()
    assert refreshed_session.user_id == 1
    assert refreshed_agent.user_id == 1


@pytest.mark.asyncio
async def test_reclaim_uid1_noop_when_admin_already_at_id_1(
    db_session: AsyncSession,
) -> None:
    """admin@local already at id=1 — reclaim is a no-op."""
    admin = User(
        id=1,
        email="admin@local",
        password_hash=hash_password("pw"),
        role="admin",
    )
    db_session.add(admin)
    await db_session.commit()

    await reclaim_uid1(db_session)

    fetched = (
        await db_session.execute(select(User).where(User.email == "admin@local"))
    ).scalar_one()
    assert fetched.id == 1


@pytest.mark.asyncio
async def test_reclaim_uid1_noop_when_admin_missing(db_session: AsyncSession) -> None:
    """No admin@local user — reclaim is a no-op (no rows touched)."""
    other = User(
        email="someone@example.com",
        password_hash=hash_password("pw"),
        role="user",
    )
    db_session.add(other)
    await db_session.commit()
    other_id = other.id

    await reclaim_uid1(db_session)

    fetched = (
        await db_session.execute(select(User).where(User.email == "someone@example.com"))
    ).scalar_one()
    assert fetched.id == other_id


@pytest.mark.asyncio
async def test_reclaim_uid1_refuses_when_id_1_taken(db_session: AsyncSession) -> None:
    """admin@local at id != 1 with UID 1 held by another account — refuse
    to clobber. Both rows remain at their original ids."""
    squatter = User(
        id=1,
        email="squatter@example.com",
        password_hash=hash_password("pw"),
        role="user",
    )
    db_session.add(squatter)
    await db_session.commit()

    admin = User(
        id=42,
        email="admin@local",
        password_hash=hash_password("pw"),
        role="admin",
    )
    db_session.add(admin)
    await db_session.commit()

    await reclaim_uid1(db_session)

    fetched_admin = (
        await db_session.execute(select(User).where(User.email == "admin@local"))
    ).scalar_one()
    fetched_squatter = (
        await db_session.execute(select(User).where(User.email == "squatter@example.com"))
    ).scalar_one()
    assert fetched_admin.id == 42
    assert fetched_squatter.id == 1


@pytest.mark.asyncio
async def test_force_reset_refuses_when_id_1_held_by_other(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    """force_admin_reset with no env_email user and UID 1 held by someone
    else: return False, no modifications."""
    squatter = User(
        id=1,
        email="squatter@example.com",
        password_hash=hash_password("untouched"),
        role="user",
    )
    db_session.add(squatter)
    await db_session.commit()

    settings = _fresh_settings(
        tmp_path,
        email="admin@local",
        pw="ignored",
        force_admin_reset=True,
    )
    result = await force_reset_admin(db_session, settings)
    assert result is False

    fetched = (
        await db_session.execute(select(User).where(User.email == "squatter@example.com"))
    ).scalar_one()
    assert verify_password("untouched", fetched.password_hash)
    assert fetched.id == 1
    count = (await db_session.execute(select(func.count()).select_from(User))).scalar_one()
    assert count == 1


@pytest.mark.asyncio
async def test_force_reset_inserts_at_id_1_when_free(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    """force_admin_reset with no env_email user and UID 1 free: insert
    with explicit id=1."""
    settings = _fresh_settings(
        tmp_path,
        email="admin@local",
        pw="freshpw1234567",
        force_admin_reset=True,
    )
    result = await force_reset_admin(db_session, settings)
    assert result is True

    admin = (await db_session.execute(select(User).where(User.email == "admin@local"))).scalar_one()
    assert admin.id == 1
