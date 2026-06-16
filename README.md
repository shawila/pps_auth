# pps_auth

Centralized OIDC Authorization Server for the pps project. Issues RS256-signed JWTs consumed by sister applications.

## Sister Apps

| App | Stack | Integration |
|---|---|---|
| `portfolio_chatbot` | Rails 7.2 | `omniauth-openid-connect` |
| `trading_bot` | Rust (Axum) | Bearer JWT, JWKS validation |
| `scheduler-python` | Flask | `authlib` OIDC client |

## Auth Methods

- Google OAuth 2.0
- Passkeys (WebAuthn / FIDO2)
- WhatsApp, Messenger, LINE *(planned)*

## OIDC Endpoints

| Endpoint | Description |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery document |
| `GET /.well-known/jwks.json` | RS256 public key |
| `GET /authorize` | Starts login — shows hosted login page |
| `POST /token` | Exchanges authorization code for tokens |
| `GET /userinfo` | Returns claims for a valid access token |
| `POST /revoke` | Revokes a refresh token |

All clients use **Authorization Code Flow + PKCE** (`S256` only).

## Tokens

| Token | Algorithm | Lifetime |
|---|---|---|
| `id_token` | RS256 JWT | 15 minutes |
| `access_token` | RS256 JWT | 15 minutes |
| `refresh_token` | Opaque (hashed in DB) | 30 days, rotating |

## Authorization Flow

See [`docs/auth-flow.html`](docs/auth-flow.html) for a visual sequence diagram of the full OIDC Authorization Code + PKCE flow.

## Stack

- **Runtime:** Rust (Axum + Tokio)
- **Database:** PostgreSQL (shared with `portfolio_chatbot`, separate `pps_auth` schema)
- **JWT:** `jsonwebtoken` crate, RS256
- **Passkeys:** `webauthn-rs`
- **Google OAuth:** `oauth2` crate
- **Templates:** `minijinja`
- **Migrations:** `sqlx`

## Setup

```bash
# Copy and configure environment
cp .env.example .env

# Generate RS256 keypair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Run database migrations
cargo run --bin migrate

# Start the server
cargo run
```

## Environment Variables

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_PRIVATE_KEY_PATH` | Path to RS256 private key PEM file |
| `JWT_PUBLIC_KEY_PATH` | Path to RS256 public key PEM file |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `PPS_AUTH_BASE_URL` | Public base URL of this service (used as `iss` in JWTs) |
| `SERVER_PORT` | Port to listen on (default: `4000`) |

## Development

```bash
cargo build          # Build
cargo run            # Start server on localhost:4000
cargo test           # Run test suite
cargo clippy         # Lint
cargo fmt            # Format
```

Tests require a running PostgreSQL instance. Set `TEST_DATABASE_URL` in your environment.

## Design

Full design spec: [`docs/superpowers/specs/2026-06-16-auth-microservice-design.md`](docs/superpowers/specs/2026-06-16-auth-microservice-design.md)
