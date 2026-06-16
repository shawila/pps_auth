CREATE TABLE pps_auth.credentials (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES pps_auth.users(id) ON DELETE CASCADE,
    type            TEXT        NOT NULL,
    provider_id     TEXT        NOT NULL,
    credential_data JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (type, provider_id)
);
