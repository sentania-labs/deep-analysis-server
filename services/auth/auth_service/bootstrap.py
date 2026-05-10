"""First-boot admin bootstrap.

Runs at auth-service startup. Idempotent: if any enabled admin
already exists, it is a no-op. Otherwise creates an admin account and
(for the auto-generate path) writes the plaintext password to
``/data/secrets/initial_admin.txt`` on the ``auth_secrets`` volume.
"""

from __future__ import annotations

import contextlib
import logging
import os
import secrets
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.models import User
from auth_service.passwords import hash_password
from auth_service.settings import AuthSettings

logger = logging.getLogger("auth.bootstrap")

_DEFAULT_ADMIN_EMAIL = "admin@local"


async def _resync_users_id_sequence(db: AsyncSession) -> None:
    """Resync auth.users id sequence to MAX(id) after an explicit-id insert.

    PostgreSQL serial sequences are not advanced by inserts with explicit
    values; without this, the next sequence-driven insert collides.
    """
    await db.execute(
        text(
            "SELECT setval(pg_get_serial_sequence('auth.users', 'id'), "
            "GREATEST(1, (SELECT COALESCE(MAX(id), 1) FROM auth.users)), true)"
        )
    )
    await db.commit()


async def reclaim_uid1(db: AsyncSession) -> None:
    """Reclaim UID 1 for admin@local if it has drifted to another id.

    Runs on every startup before any other admin bootstrap step. No-op
    unless admin@local exists at id != 1 AND UID 1 is currently free.
    If UID 1 is held by a different account, logs an error and leaves
    state untouched — manual intervention required.
    """
    admin = (
        await db.execute(select(User).where(User.email == _DEFAULT_ADMIN_EMAIL))
    ).scalar_one_or_none()
    if admin is None or admin.id == 1:
        return

    uid1_holder = (await db.execute(select(User).where(User.id == 1))).scalar_one_or_none()
    if uid1_holder is None:
        old_id = admin.id
        await db.execute(
            text("UPDATE auth.users SET id = 1 WHERE email = :email"),
            {"email": _DEFAULT_ADMIN_EMAIL},
        )
        await db.commit()
        await _resync_users_id_sequence(db)
        logger.warning("admin@local was at id=%s; reclaimed id=1", old_id)
        return

    logger.error(
        "admin@local has id=%s but id=1 is taken — manual intervention required",
        admin.id,
    )


def _write_initial_password(path: Path, password: str) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):  # pragma: no cover — non-POSIX fallback
        os.chmod(parent, 0o700)
    # Open with O_CREAT|O_WRONLY|O_TRUNC at mode 0600 so permissions are
    # set atomically at file creation.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(password + "\n")
    os.chmod(path, 0o600)


async def force_reset_admin(db: AsyncSession, settings: AuthSettings) -> bool:
    """Reset the admin password when DEEP_ANALYSIS_FORCE_ADMIN_RESET is set.

    Behavior depends on current state:
    - If a user with ``env_email`` already exists, update their
      ``password_hash`` in place. Their id is preserved.
    - Else if UID 1 is held by a different account, log an error and
      return False — refuse to clobber UID 1.
    - Else insert a fresh admin with explicit ``id=1``.

    Returns True if a reset was performed, False otherwise.
    """
    if not settings.force_admin_reset:
        return False

    env_email = settings.bootstrap_admin_email
    env_password = settings.bootstrap_admin_password
    if not env_email or not env_password:
        logger.error(
            "DEEP_ANALYSIS_FORCE_ADMIN_RESET is set but "
            "DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL or "
            "DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD is missing — skipping reset"
        )
        return False

    existing = (await db.execute(select(User).where(User.email == env_email))).scalar_one_or_none()
    if existing is not None:
        existing.password_hash = hash_password(env_password)
        existing.must_change_password = False
        existing.disabled = False
        existing.role = "admin"
        existing.updated_at = datetime.now(UTC)
        await db.commit()
        logger.warning(
            "Admin password reset in place for %s (DEEP_ANALYSIS_FORCE_ADMIN_RESET was set — "
            "remove this env var after verifying login)",
            env_email,
        )
        return True

    uid1_holder = (await db.execute(select(User).where(User.id == 1))).scalar_one_or_none()
    if uid1_holder is not None:
        logger.error(
            "DEEP_ANALYSIS_FORCE_ADMIN_RESET: no user with email=%s but id=1 is "
            "held by %s — refusing to clobber UID 1",
            env_email,
            uid1_holder.email,
        )
        return False

    user = User(
        id=1,
        email=env_email,
        password_hash=hash_password(env_password),
        role="admin",
        must_change_password=False,
        disabled=False,
    )
    db.add(user)
    await db.commit()
    await _resync_users_id_sequence(db)

    logger.warning(
        "Admin user created at id=1: %s (DEEP_ANALYSIS_FORCE_ADMIN_RESET was set — "
        "remove this env var after verifying login)",
        env_email,
    )
    return True


async def bootstrap_admin(db: AsyncSession, settings: AuthSettings) -> None:
    await reclaim_uid1(db)

    if await force_reset_admin(db, settings):
        return

    existing = (
        await db.execute(
            select(User.id).where(User.role == "admin", User.disabled.is_(False)).limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return

    env_email = settings.bootstrap_admin_email
    env_password = settings.bootstrap_admin_password
    scripted = bool(env_email) and bool(env_password)

    if scripted:
        assert env_email is not None
        assert env_password is not None
        email = env_email
        password = env_password
        must_change = False
    else:
        email = _DEFAULT_ADMIN_EMAIL
        password = secrets.token_urlsafe(18)
        must_change = True

    user = User(
        id=1,
        email=email,
        password_hash=hash_password(password),
        role="admin",
        must_change_password=must_change,
        disabled=False,
    )
    db.add(user)
    await db.commit()
    await _resync_users_id_sequence(db)

    if scripted:
        logger.warning(
            "Bootstrap admin created from DEEP_ANALYSIS_BOOTSTRAP_ADMIN_* env vars",
            extra={"email": email},
        )
        return

    try:
        _write_initial_password(settings.initial_admin_secret_path, password)
    except OSError as exc:  # pragma: no cover — logged + re-raised
        logger.error("Failed to write initial admin password file: %s", exc)
        raise

    logger.warning(
        "INITIAL ADMIN PASSWORD written to %s — rotate on first login",
        settings.initial_admin_secret_path,
    )
