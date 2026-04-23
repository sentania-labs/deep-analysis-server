# Agent protocol

How a Deep Analysis agent (the Windows client) authenticates with the
server and stays attributable to a user.

## Lifecycle

1. **Register** — one-time, on first launch. User obtains a
   registration code from the web UI; agent exchanges it for a
   long-lived `api_token`.
2. **Heartbeat** — every 5 minutes. Agent pings the server so
   `last_seen_at` stays fresh and the agent can learn if it's been
   revoked.
3. **Upload** — the agent posts `.dat`/`.log` files to ingest
   (W3; forward reference).

## Registration code flow

The logged-in user mints a code:

```
POST /auth/agent/registration-code
Authorization: Bearer <user access JWT>
```

Response:

```json
{"code": "AB34-XY78", "expires_at": "2026-04-23T15:10:00Z"}
```

Codes are 8 alphanumeric characters (formatted XXXX-XXXX), backed by
Redis with a 10-minute TTL. No audit trail is kept — codes are
one-shot and expire cleanly. If the user mis-types or the code
expires, they mint a fresh one.

The user types the code into the agent at first launch. The agent
calls:

```
POST /auth/agent/register
Content-Type: application/json

{
  "code": "AB34-XY78",
  "machine_name": "scott-laptop",
  "client_version": "0.4.0"
}
```

The code is consumed atomically (Redis `GETDEL`) — two agents racing
the same code will see exactly one success; the loser gets 401
`{"error": "invalid_registration_code"}`.

On success the server returns:

```json
{
  "agent_id": "8b1f…",
  "api_token": "k4_3z…",
  "user_id": 42
}
```

**The `api_token` is displayed exactly once.** The agent stores it
locally (DPAPI-protected on Windows — see W8b); only a SHA-256 hash
is kept server-side.

## Heartbeat

Every 5 minutes:

```
POST /auth/agent/heartbeat
Authorization: Bearer <api_token>
Content-Type: application/json

{"client_version": "0.4.0"}
```

The body is optional — when `client_version` is present the server
updates the stored value so admins can see which build a given
machine is running.

Response:

```json
{
  "status": "ok",
  "registered_at": "2026-04-23T14:55:00Z",
  "revoked": false
}
```

## Revocation

Admin revocation sets `revoked_at` on the `auth.agent_registrations`
row. A revoked token fails authentication on the next request (401);
the agent should stop uploading and surface an alert to the user.
The `revoked` field in the heartbeat response is kept for forward
compatibility — today, revoked agents can't reach it because
`get_current_agent` rejects them first.

## Related specs

- Event bus topics: see `docs/events.md`
- Admin bootstrap: see `docs/admin-bootstrap.md`
- Deploy / env vars: see `docs/deploy.md`
