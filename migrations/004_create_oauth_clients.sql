CREATE TABLE pps_auth.oauth_clients (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           TEXT        NOT NULL UNIQUE,
    client_secret_hash  TEXT        NOT NULL,
    redirect_uris       TEXT[]      NOT NULL DEFAULT '{}',
    name                TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
