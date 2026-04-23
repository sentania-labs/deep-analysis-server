# Initial admin bootstrap

> **W2 STUB** — this flow is implemented by the `auth` service in W2. This doc exists now as a placeholder so the bootstrap shape is visible.

## Shape

On first boot, the `auth` service checks whether any user holds the `admin` role.

If **no admin exists**:

1. Generate a 24-character random password (cryptographically strong).
2. Create `admin@local` with the password hashed via argon2id and `must_change_password=true`.
3. Write the plaintext password to `/data/secrets/initial_admin.txt` (file mode `0600`, on the `auth_secrets` named volume).
4. Emit a `WARN` log line announcing the bootstrap and where to read the password.

On first login with `admin@local`, the user is forced through a password-change flow. The server hands out a **short-lived password-change token**, not a session JWT — it can only be used to set a new password. Once the change succeeds, `/data/secrets/initial_admin.txt` is deleted.

## Environment override

For unattended provisioning, set both:

- `DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL`
- `DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD`

The bootstrap uses these instead of generating a random password. Neither value is ever logged.

## Retrieving the initial password

```bash
docker compose exec auth cat /data/secrets/initial_admin.txt
```

If the file is gone, either the password has already been changed (good — use the new credential) or the `auth_secrets` volume was recreated.
