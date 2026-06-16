CREATE TABLE pps_auth.roles (
    id          UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID    NOT NULL REFERENCES pps_auth.users(id) ON DELETE CASCADE,
    client_id   TEXT    REFERENCES pps_auth.oauth_clients(client_id),
    role        TEXT    NOT NULL,
    UNIQUE (user_id, client_id, role)
);
