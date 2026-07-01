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

# Start the server (migrations run automatically on startup)
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
cargo build              # Build
cargo run                # Start server on localhost:4000
cargo run --bin seed     # Seed OAuth clients (run once after first setup)
cargo test               # Run test suite
cargo clippy             # Lint
cargo fmt                # Format
```

Tests require a running PostgreSQL instance. Set `TEST_DATABASE_URL` in your environment.

## Deployment

Live at **https://auth.ppsoftsolutions.com**

Deployments are automatic on every push to `main`:

1. CI runs tests against a PostgreSQL service container
2. Docker image is built and pushed to [GitHub Container Registry](https://ghcr.io/shawila/pps_auth)
3. Server pulls the new image and restarts via `docker compose`

Infrastructure (docker-compose, Caddyfile, environment): **[shawila/infra](https://github.com/shawila/infra)**

### First-time server setup

```bash
# Generate RS256 keypair on the server
mkdir -p /opt/infra/keys
openssl genrsa -out /opt/infra/keys/private.pem 2048
openssl rsa -in /opt/infra/keys/private.pem -pubout -out /opt/infra/keys/public.pem
python3 scripts/gen_jwks.py /opt/infra/keys/public.pem /opt/infra/keys/jwks.json

# Seed OAuth clients for sister apps (run once after first deploy)
docker compose -f /opt/infra/docker-compose.yml exec pps_auth ./seed
```

Required secrets in GitHub Actions (`Settings → Secrets`):

| Secret | Description |
|---|---|
| `DEPLOY_HOST` | `159.69.119.167` |
| `DEPLOY_USER` | `root` |
| `DEPLOY_SSH_KEY` | contents of `~/.ssh/github_deploy` (passphrase-less key, must be authorized on the server) |

## Design

Full design spec: [`docs/superpowers/specs/2026-06-16-auth-microservice-design.md`](docs/superpowers/specs/2026-06-16-auth-microservice-design.md)
