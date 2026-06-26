---
description: Launch pps_auth (Rust/Axum OIDC server) locally and verify it's up
---

# Run pps_auth

## Prerequisites

- PostgreSQL running and accessible at `DATABASE_URL` (default: `postgres://shawila@localhost:5432/portfolio_chatbot`)
- `.env` file present (copy from `.env.example` and fill in `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`)
- RS256 keypair at `private.pem` / `public.pem` (generated via `openssl genrsa` — already present in repo for local dev)

## Migration gotcha

sqlx runs migrations on startup and tracks them in `_sqlx_migrations` (public schema). If a migration was applied manually the tracking table will be out of sync and startup will fail with:

```
Error: while executing migration N: column "X" already exists
```

Fix: insert the missing record manually. Calculate the SHA-384 of the migration file and insert:

```bash
python3 -c "
import hashlib
sql = open('migrations/008_add_allow_signups_to_oauth_clients.sql','rb').read()
print(hashlib.sha384(sql).digest().hex())
"
# then insert into _sqlx_migrations with that checksum
psql $DATABASE_URL -c "
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time)
VALUES (<N>, '<description>', NOW(), true, decode('<hex>', 'hex'), 0)
ON CONFLICT DO NOTHING;
"
```

## Run

Start the server in the background:

```bash
cargo run > /tmp/pps_auth.log 2>&1 &
```

`cargo run` defaults to the `pps_auth` binary (set via `default-run` in `Cargo.toml`). Migrations run automatically on startup.

Wait for readiness then verify:

```bash
for i in {1..30}; do
  curl -sf http://localhost:4000/.well-known/openid-configuration > /dev/null && break
  sleep 1
done
curl -s http://localhost:4000/.well-known/openid-configuration
# → {"issuer":"http://localhost:4000","authorization_endpoint":...}
```

Logs are at `/tmp/pps_auth.log`. Stop with:

```bash
pkill -f "target/debug/pps_auth"
```

## Smoke test

```bash
# OIDC discovery
curl -s http://localhost:4000/.well-known/openid-configuration | python3 -m json.tool

# JWKS (RS256 public key)
curl -s http://localhost:4000/.well-known/jwks.json

# /authorize without credentials → 401
curl -s -o /dev/null -w "%{http_code}" "http://localhost:4000/authorize?client_id=x&redirect_uri=http://localhost:3000/cb&response_type=code&state=s&code_challenge=c&code_challenge_method=S256"

# /userinfo without token → 401
curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/userinfo
```

Expected: discovery and jwks return 200; authorize and userinfo return 401.

## Seed OAuth clients (first-time only)

```bash
cargo run --bin seed
```

## Environment

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | Yes | — | Postgres connection string |
| `JWT_PRIVATE_KEY_PATH` | Yes | `private.pem` | RS256 private key |
| `JWT_PUBLIC_KEY_PATH` | Yes | `public.pem` | RS256 public key |
| `JWKS_PATH` | Yes | `jwks.json` | Pre-generated JWKS file |
| `PPS_AUTH_BASE_URL` | Yes | `http://localhost:4000` | Used as `iss` in JWTs |
| `SERVER_PORT` | No | `4000` | |
| `WEBAUTHN_RP_ID` | Yes | `localhost` | WebAuthn relying party ID |
| `WEBAUTHN_RP_ORIGIN` | Yes | `http://localhost:4000` | WebAuthn origin |
| `GOOGLE_CLIENT_ID` | Yes | — | Google OAuth app credential |
| `GOOGLE_CLIENT_SECRET` | Yes | — | Google OAuth app credential |
