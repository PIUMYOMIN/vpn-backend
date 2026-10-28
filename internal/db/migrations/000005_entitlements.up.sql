CREATE TABLE entitlements (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID REFERENCES users(id) ON DELETE CASCADE,
    install_id         UUID REFERENCES anonymous_installs(id) ON DELETE CASCADE,
    granted_by         VARCHAR(20) NOT NULL,
    ad_transaction_id  TEXT UNIQUE,
    duration_hours     INT NOT NULL DEFAULT 24,
    expires_at         TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT entitlements_owner_check CHECK (
        (user_id IS NOT NULL AND install_id IS NULL) OR
        (user_id IS NULL AND install_id IS NOT NULL)
    ),
    CONSTRAINT entitlements_granted_by_check CHECK (
        granted_by IN ('rewarded_ad', 'manual', 'promo', 'fallback_free')
    )
);

CREATE INDEX entitlements_user_expires_idx
    ON entitlements(user_id, expires_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX entitlements_install_expires_idx
    ON entitlements(install_id, expires_at DESC) WHERE install_id IS NOT NULL;
CREATE INDEX entitlements_expires_idx ON entitlements(expires_at DESC);
