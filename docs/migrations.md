# Database migrations

Deep Analysis uses Alembic with a **multi-head** layout. The root head
(this repo's `alembic/` directory) owns the logical schemas, service roles,
and the parser and analytics tables. Auth and ingest have separate heads
under `services/<name>/alembic/`. Apply the root head before service heads;
Docker Compose runs these as migration jobs before the dependent services start.

Root revision `032` creates the durable match review verdict table and copies
existing rejected matches and admin-set `pending_review` flags into it.
Automatic parser holds, identified by the `No game winners resolved (...)`
reason written by the parser consumer, are left out so a later complete
snapshot can resolve them normally. Apply the revision before running the
updated services or force-reparse. Prior accept/restore decisions cannot be
backfilled because the old normal status did not distinguish an admin decision
from a normal parse. Downgrading below `032` drops the durable records and
removes force-reparse verdict protection. See
[match review usage](../README.md#match-review-and-force-reparse).

## Role credentials

The service roles are created `NOLOGIN` on purpose. Password
assignment (`ALTER ROLE ... PASSWORD ...`) happens at bootstrap /
deploy time from env-provided secrets — **not** in migrations. This
keeps credentials out of migration history and out of the repo.

## Common commands

Root head:

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

Auth and ingest own separate Alembic configs under
`services/<name>/alembic/`, each with its own `alembic.ini`. Per-service
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
