# Database migrations

Deep Analysis uses Alembic with a **multi-head** layout. The root head
(this repo's `alembic/` directory) owns only the cross-cutting
infrastructure — the four logical schemas (`auth`, `ingest`, `parser`,
`analytics`) and the four unprivileged service roles
(`deep_analysis_auth`, `deep_analysis_ingest`, `deep_analysis_parser`,
`deep_analysis_analytics`).

Starting in W2, each service adds its own Alembic head under
`alembic/<service>/` and manages only its own schema's tables. This
keeps services independently migratable: the `parser` service can ship
a schema change without coordinating with `analytics`, and vice-versa.
Each service's README documents its migration head.

## Role credentials

The service roles are created `NOLOGIN` on purpose. Password
assignment (`ALTER ROLE ... PASSWORD ...`) happens at bootstrap /
deploy time from env-provided secrets — **not** in migrations. This
keeps credentials out of migration history and out of the repo.

## Common commands

```
uv run alembic upgrade head       # apply all pending migrations
uv run alembic current            # show current revision
uv run alembic downgrade -1       # roll back one step
uv run alembic history            # list all revisions
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

## Service-specific migrations

Once a service adds its head (W2+), run it with a different script
location:

```
uv run alembic -c alembic.ini -x head=auth upgrade head     # example; TBD in W2
```

The exact invocation will be pinned in each service's README when its
head lands.
