"""First-boot admin bootstrap tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from auth_service.bootstrap import bootstrap_admin, force_reset_admin
from auth_service.models import User
from auth_service.passwords import hash_password, verify_password
from auth_service.settings import AuthSettings
from sqlalchemy import func, select
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
    disabled_admin = User(
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
async def test_force_reset_replaces_existing_admin(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    """force_admin_reset=True with valid env credentials deletes the existing
    user with that email and recreates from env."""
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
    assert admin.id != old_id
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
    """When force_admin_reset is set, bootstrap_admin replaces the existing
    admin instead of treating it as already-bootstrapped."""
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
    assert admin.id != old_id
    assert verify_password("resetviabootstrap", admin.password_hash)
    assert not settings.initial_admin_secret_path.exists()
