"""Alembic environment for the root (schema + roles) migration head.

DATABASE_URL is read directly from the process environment rather than
pydantic-settings to keep the migration entrypoint simple and free of
service-specific dependencies.

Use the sync psycopg driver (`postgresql+psycopg://...`) — Alembic does
not need asyncpg; the sync path is more predictable for migrations.

Starting W2, each service adds its own Alembic head under
`alembic/<service>/` (multi-head layout). This root head owns only the
logical schemas and the unprivileged service roles; per-service tables
live in per-service heads.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Override the placeholder in alembic.ini with the real URL from env.
config.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])

# No ORM metadata at the root head — services register their own.
target_metadata = None


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
