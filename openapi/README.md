# openapi/

OpenAPI specification for the Deep Analysis server API.

The spec lives here and is the **source of truth** for the external API contract.

- The `deep-analysis-agent` (Windows client) vendors generated types from this spec.
- The `deep-analysis-ai` add-on uses this spec for its analytics service calls.
- Server implementation must match the spec; PRs that drift the implementation from the spec need a spec update alongside.

## Status

Spec will be drafted during Phase 2 once service boundaries are fully implemented.
File(s) will appear here as `openapi.yaml` (or split per-service if the surface grows).
