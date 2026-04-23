# ingest

The ingest service accepts `.dat` and `.log` uploads from Windows agents. It deduplicates on sha256 (canonical record in `ingest.game_log_files`), associates the upload to a user via `ingest.user_uploads` for multi-user attribution, stores the raw file in an archive volume shared with the parser, and publishes a `file.ingested` event to Redis for downstream async processing. FastAPI application backed by the `ingest.*` Postgres schema.
