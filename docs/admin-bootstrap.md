# Initial admin bootstrap

## JWT signing keys

The `auth` service issues short-lived RS256 access tokens signed with a
private key; every other service verifies them with the public key.
Generate the keypair once at deploy time:

```bash
uv run python -m auth_service.keygen --out ./secrets/
```

This writes `secrets/jwt_private.pem` (mode `0600`) and
`secrets/jwt_public.pem` (mode `0644`). Mount the files into the stack:

- `auth` container: both, with `DA_JWT_PRIVATE_KEY_PATH` pointing at the
  private key and `DA_JWT_PUBLIC_KEY_PATH` at the public key.
- Every other service: public key only, via `DA_JWT_PUBLIC_KEY_PATH`.

Use Docker Compose `secrets:` or a read-only bind mount; the private
key must never reach non-auth containers. Rotate by generating a fresh
keypair, redeploying `auth` with the new private key, then rolling the
other services with the new public key.

## Initial admin account

On first boot, the `auth` service checks whether any enabled user holds
the `admin` role. Bootstrap is idempotent — on subsequent boots (or
after a compose restart) the check finds an existing admin and exits
without touching state.

### Auto-generate path (default)

If **no enabled admin exists** and no bootstrap env vars are set:

1. Generate a 24-character random password via
   `secrets.token_urlsafe(18)`.
2. Create `admin@local` with the password hashed via argon2id and
   `must_change_password=true`.
3. Write the plaintext password to `/data/secrets/initial_admin.txt`
   (file mode `0600`, directory mode `0700`, on the `auth_secrets`
   named volume).
4. Emit a `WARN` log line:
   `INITIAL ADMIN PASSWORD written to /data/secrets/initial_admin.txt — rotate on first login`.

### First login + forced password change

1. `POST /auth/login` with `admin@local` + the retrieved password.
2. The response carries `must_change_password: true`, `expires_in: 300`,
   and a JWT whose `scope` claim is `password-change-only`. That token
   is usable for **one** endpoint:
3. `POST /auth/password/change` with
   `{"current_password": "...", "new_password": "..."}` (body), bearer
   token in the `Authorization` header.
4. On success (204):
   - Password is re-hashed with argon2id.
   - `must_change_password` is cleared.
   - All existing sessions for the user are revoked (including the
     password-change session itself).
   - If the user is `admin@local` and `/data/secrets/initial_admin.txt`
     exists, it is deleted.
5. The client must then `POST /auth/login` again with the new password
   to obtain a normal full-scope access token.

Any attempt to call a normal endpoint (e.g. `GET /auth/me`, any
`/admin/*` route) with a password-change-only token returns
`403 {"error": "password_change_required"}`.

### Password policy

Stub policy: `len(new_password) >= 12`. Weaker inputs are rejected with
`400 {"error": "weak_password"}`. Full policy TBD.

### Environment override (scripted installs)

For unattended provisioning set **both**:

- `DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL`
- `DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD`

When both are present at first boot, the admin account is created with
those credentials, `must_change_password=false`, and **no plaintext
file is written**. Neither value is ever logged.

### Retrieving the initial password (auto-generate path)

```bash
docker compose exec auth cat /data/secrets/initial_admin.txt
```

If the file is absent, either the password has already been changed
(good — use the new credential) or the `auth_secrets` volume was
recreated (in which case: admin already exists in Postgres, so
bootstrap will not re-run; reset via another admin or by rolling the
Postgres volume).

### Rotating / resetting later

Any admin can reset any user's password via

```
POST /admin/users/{id}/reset-password
```

The response body carries a fresh 24-char temporary password and
`must_change_password` is set back to `true` on the target user — they
are forced through the same password-change flow on next login.

### Auth JWT flow (summary)

```
  ┌──────────┐   login (must_change=true)   ┌───────────┐
  │ client   │ ───────────────────────────▶│  auth     │
  │          │ ◀───────────────────────────│           │
  └──────────┘   JWT scope=password-change  └───────────┘
        │       (5-min TTL)                      │
        │                                        │
        │  POST /auth/password/change            │
        │   Bearer <scoped JWT>                  │
        ├───────────────────────────────────────▶│
        │  204 (sessions revoked)                │
        │◀───────────────────────────────────────┤
        │                                        │
        │  POST /auth/login (new password)       │
        ├───────────────────────────────────────▶│
        │  JWT (no scope, 15-min TTL)            │
        │◀───────────────────────────────────────┤
```

A rendered diagram lives under `docs/diagrams/` (stub — to be added).

## Generating a registration code

Once logged in as any user, mint a one-shot code that an agent can
exchange for a long-lived `api_token`:

```bash
curl -k -X POST https://deepanalysis.local/auth/agent/registration-code \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

Response (201):

```json
{"code": "AB34-XY78", "expires_at": "2026-04-23T15:10:00Z"}
```

Codes are stored in Redis with a 10-minute TTL and are consumed
atomically — a code can only be used once. **No audit trail** is
kept for minted codes (Option A: keeps v0.4.0 simple with no
extra table or migration). If the code expires or is mis-typed,
re-mint a new one. Full protocol in `docs/agent-protocol.md`.

## Admin operations

Use these endpoints to bootstrap the first user, mint registration
codes, revoke compromised agents, and reset forgotten passwords. All
live under `/admin/*` and require a JWT whose `role` claim is
`admin` — non-admin callers get `403 forbidden`.

Placeholder: `${ADMIN_JWT}` below is the access token from a
`POST /auth/login` call by an admin user.

### Users

List users (paginated, max `limit=200`):

```bash
curl -k https://deepanalysis.local/admin/users?limit=50&offset=0 \
  -H "Authorization: Bearer ${ADMIN_JWT}"
```

Create a user:

```bash
curl -k -X POST https://deepanalysis.local/admin/users \
  -H "Authorization: Bearer ${ADMIN_JWT}" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"initialpw","role":"user","must_change_password":true}'
```

Patch a user (at least one field; cannot change email). Guards:
cannot disable yourself (`400 cannot_disable_self`), cannot demote
the last active admin (`400 cannot_demote_last_admin`):

```bash
curl -k -X PATCH https://deepanalysis.local/admin/users/42 \
  -H "Authorization: Bearer ${ADMIN_JWT}" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","disabled":false,"must_change_password":true}'
```

Delete a user (hard delete; sessions and agent registrations
cascade). Guards: cannot delete yourself, cannot delete the last
active admin:

```bash
curl -k -X DELETE https://deepanalysis.local/admin/users/42 \
  -H "Authorization: Bearer ${ADMIN_JWT}"
```

Reset a user's password. Returns a fresh 24-char temporary
password and sets `must_change_password=true`. The plaintext is
shown **once** — capture it:

```bash
curl -k -X POST https://deepanalysis.local/admin/users/42/reset-password \
  -H "Authorization: Bearer ${ADMIN_JWT}"
```

Revoke all active sessions for a user (forces them to re-login on
every active device). Returns `{revoked_count: N}`:

```bash
curl -k -X POST https://deepanalysis.local/admin/users/42/revoke-sessions \
  -H "Authorization: Bearer ${ADMIN_JWT}"
```

### Agents

List agents across all users (paginated, joined with user email):

```bash
curl -k https://deepanalysis.local/admin/agents?limit=50&offset=0 \
  -H "Authorization: Bearer ${ADMIN_JWT}"
```

Revoke a compromised agent (idempotent — always `204`):

```bash
curl -k -X POST https://deepanalysis.local/admin/agents/<agent-uuid>/revoke \
  -H "Authorization: Bearer ${ADMIN_JWT}"
```

Bulk-revoke stale agents (default `stale_days=90` — anything whose
`last_seen_at` is older than the cutoff gets revoked):

```bash
curl -k -X POST "https://deepanalysis.local/admin/agents/cleanup-stale?stale_days=90" \
  -H "Authorization: Bearer ${ADMIN_JWT}"
```
