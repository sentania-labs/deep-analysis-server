# auth

The auth service owns user accounts, sessions, and agent registrations. It issues short-lived JWTs that every other service verifies for service-to-service and user authentication. Backed by the `auth.*` Postgres schema with Redis for session TTL and rotation. Admin endpoints handle listing and revoking agent registrations, managing users, and key rotation. FastAPI application.
