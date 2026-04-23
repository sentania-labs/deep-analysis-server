# Database migrations

Deep Analysis uses Alembic with a **multi-head** layout. The root head
(this repo's `alembic/` directory) owns only the cross-cutting
infrastructure — the four logical schemas (`auth`, `ingest`, `parser`,
`analytics`) and the four unprivileged service roles
(`deep_analysis_auth`, `deep_analysis_ingest`, `deep_analysis_parser`,
`deep_analysis_analytics`).

Starting in W2, each service adds its own Alembic head under
`services/<name>/alembic/` and manages only its own schema's tables. This
keeps services independently migratable: the `parser` service can ship
a schema change without coordinating with `analytics`, and vice-versa.
Each service's README documents its migration head.

## Role credentials

The service roles are created `NOLOGIN` on purpose. Password
assignment (`ALTER ROLE ... PASSWORD ...`) happens at bootstrap /
deploy time from env-provided secrets — **not** in migrations. This
keeps credentials out of migration history and out of the repo.

## Common commands

Root head (schemas + roles):

```
uv run alembic upgrade head       # apply all pending migrations
uv run alembic current            # show current revision
uv run alembic downgrade -1       # roll back one step
uv run alembic history            # list all revisions
```

Service head (e.g. auth) — point `-c` at the service's `alembic.ini`:

```
uv run alembic -c services/auth/alembic.ini upgrade head
uv run alembic -c services/auth/alembic.ini current
uv run alembic -c services/auth/alembic.ini downgrade base
```

## Running against the compose Postgres

The compose stack binds postgres to `localhost:5432` on the host by
default. Point Alembic at it via `DATABASE_URL`:

```
DATABASE_URL=postgresql+psycopg://da:changeme@localhost:5432/deep_analysis \
  uv run alembic upgrade head
```

Use whatever `POSTGRES_USER` / `POSTGRES_PASSWORD` you put in your
`.env`. The driver prefix is `postgresql+psycopg://` — we use the
sync psycopg driver for migrations, not asyncpg.

## Service-scoped heads

Each service owns its own Alembic config under
`services/<name>/alembic/` with its own `alembic.ini`. Per-service
heads:

- use their own `version_table` (e.g. `auth_alembic_version`) inside
  their own schema, so they can be applied and rolled back
  independently of the root head and each other;
- set `include_name` / `include_schemas` in `env.py` to scope
  autogenerate to their own schema — no cross-service proposals.

Run them from the repo root by pointing `-c` at the service's
`alembic.ini`. The root head must be applied first, since it owns the
schemas and service roles.

### auth

```
DATABASE_URL=postgresql+psycopg://da:changeme@localhost:5432/deep_analysis \
  uv run alembic upgrade head                              # root head

DATABASE_URL=postgresql+psycopg://da:changeme@localhost:5432/deep_analysis \
  uv run alembic -c services/auth/alembic.ini upgrade head # auth head
```

The auth head creates `auth.users`, `auth.sessions`, and
`auth.agent_registrations`, plus the `pgcrypto` extension (for
`gen_random_uuid()`). `pgcrypto` is left in place on downgrade — it
is a cluster-wide extension with potentially other consumers.
