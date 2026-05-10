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


async def force_reset_admin(db: AsyncSession, settings: AuthSettings) -> bool:
    """Delete and recreate the admin user when DEEP_ANALYSIS_FORCE_ADMIN_RESET is set.

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
        await db.delete(existing)
        await db.commit()

    user = User(
        email=env_email,
        password_hash=hash_password(env_password),
        role="admin",
        must_change_password=False,
        disabled=False,
    )
    db.add(user)
    await db.commit()

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
