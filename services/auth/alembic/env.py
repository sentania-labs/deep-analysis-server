"""Alembic environment for the auth service head.

Owns only auth.* tables — the auth schema itself is created by the
root head (alembic/versions/001_initial_schema.py). This head uses
its own version table (auth.auth_alembic_version) so service heads
can migrate independently without stepping on each other.
"""

from __future__ import annotations

import os
from logging.config import fileConfig
from typing import Any

from auth_service.models import Base
from sqlalchemy import engine_from_config, pool

from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])

target_metadata = Base.metadata


def include_name(name: str | None, type_: Any, parent_names: Any) -> bool:
    # Only autogenerate/compare objects in the auth schema. Keeps this head
    # from racing with root-head schemas or other service heads.
    if type_ == "schema":
        return name in (None, "auth")
    if type_ == "table":
        return parent_names.get("schema_name") in (None, "auth")
    return True


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
        include_name=include_name,
        version_table="auth_alembic_version",
        version_table_schema="auth",
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
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            include_name=include_name,
            version_table="auth_alembic_version",
            version_table_schema="auth",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
