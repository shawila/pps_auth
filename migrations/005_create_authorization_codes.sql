CREATE TABLE pps_auth.authorization_codes (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       TEXT        NOT NULL REFERENCES pps_auth.oauth_clients(client_id),
    user_id         UUID        NOT NULL REFERENCES pps_auth.users(id) ON DELETE CASCADE,
    code_hash       TEXT        NOT NULL UNIQUE,
    pkce_challenge  TEXT        NOT NULL,
    pkce_method     TEXT        NOT NULL DEFAULT 'S256',
    scopes          TEXT[]      NOT NULL DEFAULT '{}',
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ
);
