"""initial schema — four logical schemas and four unprivileged service roles.

Revision ID: 001
Revises:
Create Date: 2026-04-23

Design notes
------------
- The four service roles are created NOLOGIN intentionally. Credential
  assignment (``ALTER ROLE ... PASSWORD ...``) is performed at bootstrap /
  deploy time from env-provided secrets, not in migrations. This keeps
  secrets out of migration history and out of the repo.
- A later slice (W1b-iii or a deploy bootstrap step) will own the
  password-assignment path. Migrations only define the role shape and
  privilege surface.
- ``CREATE ROLE IF NOT EXISTS`` is not valid SQL in PostgreSQL, so each
  role is wrapped in a DO block that swallows ``duplicate_object`` to
  keep the migration idempotent.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


SCHEMAS = ("auth", "ingest", "parser", "analytics")

ROLES = (
    "deep_analysis_auth",
    "deep_analysis_ingest",
    "deep_analysis_parser",
    "deep_analysis_analytics",
)


def _create_role(role: str) -> None:
    op.execute(
        f"""
        DO $$
        BEGIN
            CREATE ROLE {role} NOLOGIN NOCREATEDB NOSUPERUSER;
        EXCEPTION WHEN duplicate_object THEN NULL;
        END
        $$;
        """
    )


def upgrade() -> None:
    for schema in SCHEMAS:
        op.execute(f"CREATE SCHEMA IF NOT EXISTS {schema};")

    for role in ROLES:
        _create_role(role)

    # auth: full ownership of its own schema.
    op.execute("GRANT USAGE ON SCHEMA auth TO deep_analysis_auth;")
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA auth TO deep_analysis_auth;")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA auth "
        "GRANT ALL PRIVILEGES ON TABLES TO deep_analysis_auth;"
    )

    # ingest: full ownership of ingest; SELECT on auth (FK lookups validate user_id).
    op.execute("GRANT USAGE ON SCHEMA ingest TO deep_analysis_ingest;")
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA ingest TO deep_analysis_ingest;")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA ingest "
        "GRANT ALL PRIVILEGES ON TABLES TO deep_analysis_ingest;"
    )
    # ingest needs SELECT on auth.users to validate user_id foreign keys.
    op.execute("GRANT USAGE ON SCHEMA auth TO deep_analysis_ingest;")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA auth TO deep_analysis_ingest;")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT SELECT ON TABLES TO deep_analysis_ingest;"
    )

    # parser: full ownership of parser; SELECT on ingest for game_log_files/user_uploads.
    op.execute("GRANT USAGE ON SCHEMA parser TO deep_analysis_parser;")
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA parser TO deep_analysis_parser;")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA parser "
        "GRANT ALL PRIVILEGES ON TABLES TO deep_analysis_parser;"
    )
    # parser reads ingest.game_log_files and ingest.user_uploads to drive parsing.
    op.execute("GRANT USAGE ON SCHEMA ingest TO deep_analysis_parser;")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA ingest TO deep_analysis_parser;")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA ingest GRANT SELECT ON TABLES TO deep_analysis_parser;"
    )

    # analytics: read-only across parser, ingest, auth (user attribution joins).
    op.execute("GRANT USAGE ON SCHEMA parser TO deep_analysis_analytics;")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA parser TO deep_analysis_analytics;")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA parser "
        "GRANT SELECT ON TABLES TO deep_analysis_analytics;"
    )
    op.execute("GRANT USAGE ON SCHEMA ingest TO deep_analysis_analytics;")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA ingest TO deep_analysis_analytics;")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA ingest "
        "GRANT SELECT ON TABLES TO deep_analysis_analytics;"
    )
    # analytics reads auth for user-attribution cuts (e.g., join user_id → username).
    op.execute("GRANT USAGE ON SCHEMA auth TO deep_analysis_analytics;")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA auth TO deep_analysis_analytics;")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT SELECT ON TABLES TO deep_analysis_analytics;"
    )


def downgrade() -> None:
    # DROP OWNED clears the default-privilege grants that would otherwise
    # block DROP ROLE with "role cannot be dropped because some objects
    # depend on it".
    for role in reversed(ROLES):
        op.execute(
            f"""
            DO $$
            BEGIN
                EXECUTE 'DROP OWNED BY {role}';
            EXCEPTION WHEN undefined_object THEN NULL;
            END
            $$;
            """
        )
        op.execute(f"DROP ROLE IF EXISTS {role};")

    op.execute("DROP SCHEMA IF EXISTS analytics CASCADE;")
    op.execute("DROP SCHEMA IF EXISTS parser CASCADE;")
    op.execute("DROP SCHEMA IF EXISTS ingest CASCADE;")
    op.execute("DROP SCHEMA IF EXISTS auth CASCADE;")
