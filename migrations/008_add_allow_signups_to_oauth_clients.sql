ALTER TABLE pps_auth.oauth_clients
    ADD COLUMN allow_signups BOOLEAN NOT NULL DEFAULT true;
