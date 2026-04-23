# Redis event topics

The server publishes a small set of Redis pub/sub topics for cross-service and add-on consumption. Topic names and payload dataclasses live in `common/events.py` — **that file is the source of truth**; this doc describes the contract.

> **Load-bearing contract.** These topic names and payload schemas are consumed by the future `deep-analysis-ai` add-on. Changes require coordinated updates across `common/events.py`, this doc, and any subscriber/producer services. Treat as a public contract.

Subscribers must tolerate extra fields — producers may add keys without bumping the contract. Renames and removals are breaking.

## `file.ingested`

- **Producer:** `ingest` service (W3)
- **Consumers:** `parser` (W4), `deep-analysis-ai` (future)
- **Payload:**
  ```json
  {
    "sha": "str",
    "user_id": "int",
    "agent_registration_id": "int",
    "uploaded_at": "ISO8601 string"
  }
  ```

## `match.parsed`

- **Producer:** `parser` service (W4)
- **Consumers:** `deep-analysis-ai` (future)
- **Payload:**
  ```json
  {
    "match_id": "int",
    "user_id": "int",
    "agent_registration_id": "int",
    "parsed_at": "ISO8601 string"
  }
  ```

## `insight.requested`

- **Producer:** `web` service or direct client (W6 — reserved slot, no producer yet)
- **Consumers:** `deep-analysis-ai` (future)
- **Payload:**
  ```json
  {
    "user_id": "int",
    "trigger": "manual | auto",
    "context": {}
  }
  ```
