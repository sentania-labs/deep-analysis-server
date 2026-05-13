# Dispatch: admin force-reset on startup

## Context

The admin user on edge.int has a garbled password hash caused by shell
escaping mangling special characters when the `.env` was written. Login
fails. The bootstrap code only fires when `auth.users` is empty, so
restarting won't fix it — the broken user already exists.

## Task

Implement admin force-reset logic. Branch from main, open a PR, merge
it with `--admin`, then tag v0.7.8.

### 1. Add `force_admin_reset` field to AuthSettings

File: `services/auth/auth_service/settings.py`

Add a field following the same AliasChoices pattern as the existing
bootstrap fields:

```python
force_admin_reset: bool = Field(
    default=False,
    validation_alias=AliasChoices(
        "force_admin_reset",
        "DA_FORCE_ADMIN_RESET",
        "DEEP_ANALYSIS_FORCE_ADMIN_RESET",
    ),
)
```

### 2. Implement force-reset in bootstrap.py

File: `services/auth/auth_service/bootstrap.py`

Add a `force_reset_admin` async function that runs BEFORE the normal
`bootstrap_admin` check:

```
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

    # Delete the existing user with that email (if any)
    existing = (
        await db.execute(select(User).where(User.email == env_email))
    ).scalar_one_or_none()
    if existing is not None:
        await db.delete(existing)
        await db.commit()

    # Re-create with the env password
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
```

Then update `bootstrap_admin` to be a no-op if `force_reset_admin`
already ran:

```python
async def bootstrap_admin(db: AsyncSession, settings: AuthSettings) -> None:
    # Force-reset takes priority; if it ran, normal bootstrap is skipped.
    if await force_reset_admin(db, settings):
        return
    # ... rest of existing logic unchanged ...
```

### 3. Update deploy/seed.sh

Add `DEEP_ANALYSIS_FORCE_ADMIN_RESET=true` to the generated `.env`
block (after the `DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD` line):

```
DEEP_ANALYSIS_FORCE_ADMIN_RESET=true
```

Also update the trailing echo section to be clearer about the
force-reset:

```
echo ">> ADMIN BOOTSTRAP CREDENTIALS (save these now):"
echo "   email:    admin@local"
echo "   password: $BOOTSTRAP_ADMIN_PASSWORD"
echo ""
echo "   DEEP_ANALYSIS_FORCE_ADMIN_RESET=true is set in .env."
echo "   On first 'compose up -d', the auth service will delete any"
echo "   existing admin@local user and recreate it with the password above."
echo "   Remove DEEP_ANALYSIS_FORCE_ADMIN_RESET from .env after verifying login."
```

### 4. PR and ship

1. Branch from main: `fix/admin-force-reset`
2. Commit all changes with message: `fix(auth): add DEEP_ANALYSIS_FORCE_ADMIN_RESET startup reset`
3. Run ruff + mypy on the auth service before committing.
4. Open PR with title: `fix(auth): add DEEP_ANALYSIS_FORCE_ADMIN_RESET startup reset`
5. Merge the PR with `gh pr merge --admin --squash --delete-branch`
6. Tag v0.7.8: `git tag v0.7.8 && git push origin v0.7.8`
7. Run `/self-review` and write `.review-passed` with HEAD SHA.

## Self-review protocol

At the end of the session, run `/self-review` to verify the work:
- bootstrap.py: force_reset_admin runs before bootstrap_admin
- settings.py: force_admin_reset field with correct AliasChoices
- seed.sh: DEEP_ANALYSIS_FORCE_ADMIN_RESET=true in .env block
- PR merged, v0.7.8 tag pushed
- Write HEAD SHA to `.review-passed`
