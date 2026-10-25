CREATE TABLE devices (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint TEXT NOT NULL,
    device_name        VARCHAR(100),
    platform           VARCHAR(20),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT devices_user_fp_uniq UNIQUE (user_id, device_fingerprint)
);

CREATE INDEX devices_user_idx ON devices(user_id);
