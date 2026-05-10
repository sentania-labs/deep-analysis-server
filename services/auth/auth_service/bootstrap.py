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
from pathlib import Path

from sqlalchemy import select
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.models import User
from auth_service.passwords import hash_password
from auth_service.settings import AuthSettings

logger = logging.getLogger("auth.bootstrap")

_DEFAULT_ADMIN_EMAIL = "admin@local"


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


async def _ensure_admin_is_uid1(db: AsyncSession) -> None:
    """If admin@local exists at id != 1 and id=1 is free, move it to id=1."""
    result = await db.execute(
        sa_text("SELECT id FROM auth.users WHERE email = :email"),
        {"email": _DEFAULT_ADMIN_EMAIL},
    )
    row = result.fetchone()
    if row is None or row[0] == 1:
        return  # already correct or doesn't exist

    current_id = row[0]

    # Check if id=1 is free
    conflict = await db.execute(
        sa_text("SELECT id FROM auth.users WHERE id = 1"),
    )
    if conflict.fetchone() is not None:
        logger.warning(
            "Cannot move admin@local from id=%s to id=1: id=1 is occupied by another user",
            current_id,
        )
        return

    # Move the admin user to id=1
    await db.execute(
        sa_text("UPDATE auth.users SET id = 1 WHERE id = :old_id"),
        {"old_id": current_id},
    )
    # Reset the sequence so future INSERTs don't collide
    await db.execute(
        sa_text(
            "SELECT setval(pg_get_serial_sequence('auth.users', 'id'),"
            " (SELECT COALESCE(MAX(id), 0) FROM auth.users), true)"
        )
    )
    await db.commit()
    logger.warning(
        "Moved admin@local from id=%s to id=1 and reset sequence",
        current_id,
    )


async def force_reset_admin(db: AsyncSession, settings: AuthSettings) -> bool:
    """Reset the admin user's credentials when DEEP_ANALYSIS_FORCE_ADMIN_RESET is set.

    UPDATEs in place when the user exists (preserving id); otherwise INSERTs
    via the ORM. After the operation, ``_ensure_admin_is_uid1`` moves the row
    to id=1 if id=1 is free.

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

    pw_hash = hash_password(env_password)

    existing = (await db.execute(select(User).where(User.email == env_email))).scalar_one_or_none()
    if existing is not None:
        # UPDATE in place via ORM so the user's id is preserved.
        existing.password_hash = pw_hash
        existing.role = "admin"
        existing.must_change_password = False
        existing.disabled = False
        await db.commit()
    else:
        user = User(
            email=env_email,
            password_hash=pw_hash,
            role="admin",
            must_change_password=False,
            disabled=False,
        )
        db.add(user)
        await db.commit()

    await _ensure_admin_is_uid1(db)

    logger.warning(
        "Admin user reset: %s (DEEP_ANALYSIS_FORCE_ADMIN_RESET was set — "
        "remove this env var after verifying login)",
        env_email,
    )
    return True


async def bootstrap_admin(db: AsyncSession, settings: AuthSettings) -> None:
    if await force_reset_admin(db, settings):
        return

    existing = (
        await db.execute(
            select(User.id).where(User.role == "admin", User.disabled.is_(False)).limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        # Admin already present; still run the drift correction in case
        # admin@local landed at id != 1 in a prior boot.
        await _ensure_admin_is_uid1(db)
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
        email=email,
        password_hash=hash_password(password),
        role="admin",
        must_change_password=must_change,
        disabled=False,
    )
    db.add(user)
    await db.commit()

    await _ensure_admin_is_uid1(db)

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
