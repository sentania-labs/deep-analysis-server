# parser

The parser is an async worker that subscribes to `file.ingested` Redis events, reads the raw files from the shared archive volume (read-only), parses MTGO `.dat`/`.log` payloads, and populates match, game, play, and deck records in the `parser.*` Postgres schema. It exposes minimal HTTP endpoints for `/healthz` and `/metrics`, but has no public API. Python worker application.
