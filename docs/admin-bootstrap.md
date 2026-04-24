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

> **W2e STUB** — the first-boot admin bootstrap flow is implemented in
> W2e. The shape below is the plan; do not expect it to be live until
> that slice lands.

On first boot, the `auth` service checks whether any user holds the `admin` role.

If **no admin exists**:

1. Generate a 24-character random password (cryptographically strong).
2. Create `admin@local` with the password hashed via argon2id and `must_change_password=true`.
3. Write the plaintext password to `/data/secrets/initial_admin.txt` (file mode `0600`, on the `auth_secrets` named volume).
4. Emit a `WARN` log line announcing the bootstrap and where to read the password.

On first login with `admin@local`, the user is forced through a password-change flow. The server hands out a **short-lived password-change token**, not a session JWT — it can only be used to set a new password. Once the change succeeds, `/data/secrets/initial_admin.txt` is deleted.

### Environment override

For unattended provisioning, set both:

- `DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL`
- `DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD`

The bootstrap uses these instead of generating a random password. Neither value is ever logged.

### Retrieving the initial password

```bash
docker compose exec auth cat /data/secrets/initial_admin.txt
```

If the file is gone, either the password has already been changed (good — use the new credential) or the `auth_secrets` volume was recreated.

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
