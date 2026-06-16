CREATE TABLE pps_auth.roles (
    id          UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID    NOT NULL REFERENCES pps_auth.users(id) ON DELETE CASCADE,
    client_id   TEXT    REFERENCES pps_auth.oauth_clients(client_id),
    role        TEXT    NOT NULL
);

CREATE UNIQUE INDEX roles_global_unique ON pps_auth.roles (user_id, role)
    WHERE client_id IS NULL;

CREATE UNIQUE INDEX roles_client_unique ON pps_auth.roles (user_id, client_id, role)
    WHERE client_id IS NOT NULL;
