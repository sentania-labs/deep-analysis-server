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
