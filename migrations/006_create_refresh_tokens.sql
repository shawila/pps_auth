CREATE TABLE pps_auth.refresh_tokens (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES pps_auth.users(id),
    client_id   TEXT        NOT NULL REFERENCES pps_auth.oauth_clients(client_id),
    token_hash  TEXT        NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX ON pps_auth.refresh_tokens (token_hash);
