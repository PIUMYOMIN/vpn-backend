CREATE TABLE anonymous_installs (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    install_id         VARCHAR(64) NOT NULL UNIQUE,
    device_fingerprint TEXT,
    device_name        VARCHAR(100),
    platform           VARCHAR(20),
    app_version        VARCHAR(20),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX anonymous_installs_last_seen_idx ON anonymous_installs(last_seen_at DESC);
