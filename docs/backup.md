# Backup

> **Not yet implemented** — target is post-W1, tracked as a follow-up.

## Intent

Nightly `pg_dump` of the full database to a host-mounted volume, run via compose-managed cron or a small sidecar container. 30-day retention, oldest dumps rolled off automatically.

Scope: full-DB dumps only. No per-schema or per-service splits — the single Postgres instance is the unit of backup.

## Restore (sketch)

```bash
docker compose down
# drop + recreate the DB (psql against the postgres container)
pg_restore -d <db> <dump-file>
uv run alembic upgrade head   # no-op if the dump was taken on head schema
docker compose up -d
```

If the dump was taken on an older schema, `alembic upgrade head` will bring it forward; verify migrations apply cleanly before putting the stack back into service.
