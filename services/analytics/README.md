# analytics

The analytics service is a read-only query API. It owns no tables but reads across the `parser.*`, `ingest.*`, and `auth.*` schemas to produce stats, win-rate cuts, and device-attribution views (via `agent_registration_id` on ingest uploads). Consumers include the `web` dashboard and the proprietary Deep Analysis AI add-on. Short-lived Redis cache for repeat queries. FastAPI application.
