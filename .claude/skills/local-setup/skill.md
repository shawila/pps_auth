---
name: local-setup
description: Complete guide to set up pps_auth (Rust OIDC server) for local development from scratch, including keypair generation, database, and seeding OAuth clients.
---

# Local Dev Setup: pps_auth

pps_auth is a Rust OIDC server shared by portfolio_chatbot and trading_bot. It runs on
port 4000 and must be set up before either sister app can handle logins.

## Prerequisites

```bash
# Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# PostgreSQL 17
brew install postgresql@17 && brew services start postgresql@17
```

## 1. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:
- `DATABASE_URL` — point to your local Postgres (e.g. `postgres://your-user@localhost:5432/hatan`)
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` — from [console.cloud.google.com](https://console.cloud.google.com); create an OAuth 2.0 client, add `http://localhost:4000/auth/google/callback` as an authorized redirect URI

## 2. Generate RS256 keypair (one-time only)

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

Skip this step if `private.pem` already exists.

## 3. Start the server

```bash
cargo run
```

Migrations run automatically on first boot. Ready when logs show `Server listening on 0.0.0.0:4000`.

### Migration conflict

If startup fails with `column "X" already exists`, a migration was applied manually and
the tracking table is out of sync. See the `run` skill for the fix.

## 4. Seed OAuth clients and users

With the server running, open a second terminal:

```bash
cargo run --bin seed
```

This registers `portfolio_chatbot` and `trading_bot` as OIDC clients and prints a
`client_secret` for each new client:

```
client_id=portfolio_chatbot  client_secret=<copy to portfolio_chatbot/.env>
client_id=trading_bot        client_secret=<copy to trading_bot/.env>
```

Secrets are printed only on first run. Re-running seed updates redirect URIs but does
not rotate existing secrets.

## 5. Verify

```bash
curl -s http://localhost:4000/.well-known/openid-configuration | python3 -m json.tool
curl -s http://localhost:4000/.well-known/jwks.json
```

Both should return JSON. See the `run` skill for a full smoke-test suite.
