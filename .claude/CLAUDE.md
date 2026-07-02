# pps_auth — Claude Code Notes

## Seeded Data

| Entity | Value |
|---|---|
| Salah user UUID | `27c5efca-908e-45eb-b1b5-03949a5d7f48` |
| Salah email | `salah.hawila@gmail.com` |

This UUID is stable across DB recreations and can be hardcoded in sister projects.

## After Deploying

Run seed on the server to update OAuth client redirect URIs (safe to re-run — never rotates existing secrets):

```bash
docker compose exec pps_auth ./seed
```

## sqlx Query Cache

`sqlx::query!` macros validate against a live DB at compile time. When adding or changing a query:

1. Ensure local DB exists and is migrated: `cargo sqlx migrate run`
2. Regenerate cache: `cargo sqlx prepare`
3. Commit the updated `.sqlx/` directory

Local DB is `hatan` (`DATABASE_URL` in `.env`).

## Database Connection

`DATABASE_URL` is built automatically from `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_HOST` / `POSTGRES_PORT` / `POSTGRES_DB` when not set directly. Special characters in passwords (e.g. `#`) are percent-encoded automatically — no manual escaping needed.

## OAuth Clients

| client_id | Dev redirect | Prod redirect |
|---|---|---|
| `portfolio_chatbot` | `http://localhost:3002/users/auth/pps_auth/callback` | `https://chat.ppsoftsolutions.com/users/auth/pps_auth/callback` |
| `trading_bot` | `http://localhost:3003/auth/callback` | `https://trading.ppsoftsolutions.com/auth/callback` |
