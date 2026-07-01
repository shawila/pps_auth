# pps_auth — Authentication Microservice Design

**Date:** 2026-06-16
**Status:** Approved

---

## Overview

`pps_auth` is a centralized OIDC Authorization Server (AS) / Identity Provider (IdP) built in Rust (Axum). It issues RS256-signed JWTs to sister applications acting as OIDC Relying Parties. A single superuser identity with role-based access spans all sister projects.

**Sister apps:**
- `portfolio_chatbot` — Rails 7.2, PostgreSQL, Devise (roles: `manager`, `superuser`)
- `trading_bot` — Rust (Axum), currently x-api-key auth (role: `superuser`)

---

## Architecture

`pps_auth` hosts a login page. Sister apps redirect to it, receive tokens, and validate them locally using the RS256 public key fetched from the JWKS endpoint. No per-request network call to `pps_auth` is needed for validation.

```
Browser / API caller
      │
      │ 1. redirect to /authorize
      ▼
  pps_auth  ──── Google OAuth ────► Google
  (OIDC AS)  ──── WebAuthn ────────► Browser (Passkey)
      │
      │ 2. code → tokens (RS256 JWT)
      ▼
Sister app (Relying Party)
      │
      │ 3. validates id_token locally
      │    using JWKS public key (fetched once at startup)
      ▼
  Grants access
```

### OIDC Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery document |
| `GET /.well-known/jwks.json` | RS256 public key |
| `GET /authorize` | Starts login (shows hosted login page) |
| `POST /token` | Code → `id_token` + `access_token` + `refresh_token` |
| `GET /userinfo` | Returns claims for a valid access token |
| `POST /revoke` | Revokes a refresh token |

All clients use **Authorization Code Flow + PKCE** (mandatory; `S256` only).

### Auth Methods

- **Google OAuth** — now
- **Passkeys (WebAuthn/FIDO2)** — now
- **WhatsApp, Messenger, LINE** — later

---

## Stack

| Concern | Choice |
|---|---|
| Language / framework | Rust (Axum + Tokio) |
| Database | PostgreSQL (shared instance with `portfolio_chatbot`) |
| JWT signing | RS256 (private key on disk, public key in JWKS) |
| Token verification | RS256; sister apps cache public key from JWKS at startup |
| Login UI | Minijinja templates |

**Key crates:** `axum`, `tokio`, `sqlx`, `jsonwebtoken`, `webauthn-rs`, `oauth2`, `minijinja`, `uuid`, `argon2`, `base64ct`, `rand`, `wiremock` (tests)

---

## Database Schema

Separate `pps_auth` schema in the shared PostgreSQL instance to avoid collisions with `portfolio_chatbot`.

```sql
users
  id UUID PK
  email TEXT UNIQUE NOT NULL
  name TEXT
  created_at TIMESTAMPTZ

credentials
  id UUID PK
  user_id UUID FK → users
  type TEXT                   -- 'google' | 'passkey'
  provider_id TEXT            -- Google sub or passkey credential_id
  credential_data JSONB       -- Google: token metadata | Passkey: CBOR public key + counter
  created_at TIMESTAMPTZ

oauth_clients
  id UUID PK
  client_id TEXT UNIQUE NOT NULL   -- e.g. "portfolio_chatbot"
  client_secret_hash TEXT NOT NULL
  redirect_uris TEXT[]
  name TEXT
  created_at TIMESTAMPTZ

authorization_codes
  id UUID PK
  client_id TEXT FK → oauth_clients
  user_id UUID FK → users
  code_hash TEXT UNIQUE       -- hashed; plaintext sent to client once
  pkce_challenge TEXT NOT NULL
  pkce_method TEXT            -- 'S256'
  scopes TEXT[]
  expires_at TIMESTAMPTZ      -- 5 minutes
  used_at TIMESTAMPTZ         -- single-use enforcement

refresh_tokens
  id UUID PK
  user_id UUID FK → users
  client_id TEXT FK → oauth_clients
  token_hash TEXT UNIQUE
  expires_at TIMESTAMPTZ      -- 30 days, rotating
  revoked_at TIMESTAMPTZ

roles
  id UUID PK
  user_id UUID FK → users
  client_id TEXT FK → oauth_clients   -- NULL = global role
  role TEXT                           -- 'superuser' | 'admin' | 'manager'
```

The `roles` table supports both global roles (`client_id IS NULL`) and app-scoped roles (e.g. `manager` only for `portfolio_chatbot`).

---

## Token Structure

### id_token (RS256 JWT, 15-minute lifetime)

```json
{
  "iss": "https://auth.yourdomain.com",
  "sub": "uuid-of-user",
  "aud": "portfolio_chatbot",
  "exp": 1234567890,
  "iat": 1234567890,
  "nonce": "client-provided-nonce",
  "email": "salah@tripla.jp",
  "name": "Salah Hawila",
  "roles": ["superuser"]
}
```

- **access_token:** opaque or same JWT; 15-minute lifetime; used for `GET /userinfo`
- **refresh_token:** opaque, stored hashed; 30-day lifetime; **rotating** (old token revoked on each use)

### Sister App Validation Flow

1. On startup: fetch `/.well-known/jwks.json`, cache RS256 public key
2. On each request: validate signature → `iss` → `aud` matches own `client_id` → `exp`
3. Extract `roles` claim to gate access

---

## Module Layout

```
pps_auth/
├── Cargo.toml
├── Dockerfile
├── migrations/
│   ├── 001_create_users.sql
│   ├── 002_create_credentials.sql
│   ├── 003_create_oauth_clients.sql
│   ├── 004_create_authorization_codes.sql
│   ├── 005_create_refresh_tokens.sql
│   └── 006_create_roles.sql
├── src/
│   ├── main.rs               -- Axum router wiring + startup
│   ├── config.rs             -- Env config (PORT, DATABASE_URL, JWT key paths, Google creds)
│   ├── state.rs              -- AppState (DB pool, RS256 keypair, Google OAuth client)
│   ├── db/
│   │   └── mod.rs            -- sqlx pool init
│   ├── models/
│   │   ├── user.rs
│   │   ├── credential.rs
│   │   ├── oauth_client.rs
│   │   ├── authorization_code.rs
│   │   ├── refresh_token.rs
│   │   └── role.rs
│   ├── oidc/
│   │   ├── discovery.rs      -- GET /.well-known/openid-configuration
│   │   ├── jwks.rs           -- GET /.well-known/jwks.json
│   │   ├── authorize.rs      -- GET /authorize (validate client, store code, redirect)
│   │   ├── token.rs          -- POST /token (code exchange + refresh)
│   │   ├── userinfo.rs       -- GET /userinfo
│   │   └── revoke.rs         -- POST /revoke
│   ├── auth/
│   │   ├── google.rs         -- Google OAuth callback + credential upsert
│   │   └── passkey.rs        -- WebAuthn registration + authentication (webauthn-rs)
│   ├── ui/
│   │   ├── login.rs          -- GET /login (renders login page)
│   │   └── templates/
│   │       └── login.html    -- Minijinja template (Google button + Passkey button)
│   └── middleware/
│       └── bearer.rs         -- Reusable JWT validation extractor (for /userinfo, /revoke)
└── tests/
    ├── oidc_flow_test.rs     -- Full authorization code + PKCE integration test
    ├── token_test.rs         -- JWT issuance + validation
    └── google_auth_test.rs   -- Google callback (wiremock)
```

---

## Sister App Integrations

### portfolio_chatbot (Rails)

Add `omniauth-openid-connect` gem. OmniAuth handles the OIDC redirect flow; Devise manages sessions. Gate routes by `roles` claim in session.

```ruby
# config/initializers/omniauth.rb
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :openid_connect, {
    name: :pps_auth,
    discovery: true,
    issuer: ENV["PPS_AUTH_URL"],
    client_id: "portfolio_chatbot",
    client_secret: ENV["PPS_AUTH_CLIENT_SECRET"],
    redirect_uri: "#{ENV['APP_URL']}/auth/pps_auth/callback",
    scope: [:openid, :email, :profile]
  }
end
```

### trading_bot (Rust)

Remove `x-api-key` middleware. Add JWT validation layer: fetch JWKS at startup, cache public key, validate `Authorization: Bearer <token>` on all `/api/v1/*` routes. Check `superuser` role claim.

### Registered Clients (seeded at startup)

| client_id | redirect_uri | roles checked |
|---|---|---|
| `portfolio_chatbot` | `https://chat.ppsoftsolutions.com/users/auth/pps_auth/callback` | `manager`, `superuser` |
| `trading_bot` | `https://trading.ppsoftsolutions.com/auth/callback` | `superuser` |

---

## Error Handling

All OIDC errors return JSON with `error` + `error_description`:

```json
{ "error": "invalid_grant", "error_description": "Authorization code expired or already used" }
```

| Scenario | Error code | HTTP |
|---|---|---|
| Unknown `client_id` | `unauthorized_client` | 401 |
| Bad PKCE verifier | `invalid_grant` | 400 |
| Expired/used code | `invalid_grant` | 400 |
| Revoked refresh token | `invalid_grant` | 400 |
| Bad redirect URI | `redirect_uri_mismatch` | 400 |
| Invalid access token on `/userinfo` | `invalid_token` | 401 |
| Wrong `client_secret` on `/token` | `invalid_client` | 401 |

---

## Security

- **PKCE mandatory** — `S256` only; mitigates authorization code interception
- **Authorization codes single-use** — `used_at` set atomically; replayed codes return `invalid_grant`
- **Refresh token rotation** — old token revoked on each use; theft detected on next legitimate use
- **Redirect URI exact match** — no wildcards; registered at client creation
- **Google OAuth state param** — CSRF protection on upstream Google callback
- **Secrets hashed at rest** — `client_secret` and token hashes use Argon2; plaintext never stored
- **RS256 private key on disk** — loaded from file path in config; never in DB or env var
- **Short code TTL** — authorization codes expire after 5 minutes

---

## Testing

**Integration tests** (primary) run against a real PostgreSQL test database. Google OAuth callbacks use `wiremock`.

| Area | What's tested |
|---|---|
| Authorization Code + PKCE flow | Full redirect → code → token → userinfo round trip |
| PKCE enforcement | Rejects `plain` method; rejects wrong verifier |
| Code single-use | Second use of same code returns `invalid_grant` |
| Code expiry | Expired code returns `invalid_grant` |
| Refresh token rotation | New token issued, old token revoked |
| Stolen refresh token | Revoked token returns `invalid_grant` |
| JWKS endpoint | Returns valid RS256 public key; verifiable against issued JWT |
| Discovery document | All required OIDC fields present and correct |
| Google callback | Upserts user + credential; issues tokens (wiremock) |
| Role claims | `roles` array in JWT matches DB; scoped and global roles |
| Redirect URI mismatch | Returns `redirect_uri_mismatch` |
| Client auth | Wrong `client_secret` rejected on `/token` |

**Unit tests:**
- JWT RS256 sign + verify roundtrip
- PKCE `S256` challenge/verifier computation
- Authorization code expiry logic
- Argon2 hash/verify for secrets and tokens

---

## Future Scope

- **WhatsApp, Messenger, LINE** login methods
- **Chatbot user-side login** in `portfolio_chatbot`
- **PostgreSQL migration** for `trading_bot` (replacing SQLite)
- **RS256 key rotation** (JWKS supports multiple keys; clients cache by `kid`)
- **Multi-user support** (currently single superuser)
