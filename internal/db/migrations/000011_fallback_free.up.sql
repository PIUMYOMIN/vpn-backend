-- Add the server-only free-fallback entitlement source.
ALTER TABLE entitlements DROP CONSTRAINT IF EXISTS entitlements_granted_by_check;
ALTER TABLE entitlements ADD CONSTRAINT entitlements_granted_by_check
    CHECK (granted_by IN ('rewarded_ad', 'manual', 'promo', 'fallback_free'));

-- Persist fallback attempts so installs and accounts have a 24-hour cooldown.
CREATE TABLE fallback_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    install_id UUID REFERENCES anonymous_installs(id) ON DELETE CASCADE,
    granted BOOLEAN NOT NULL DEFAULT FALSE,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fallback_attempts_owner_check CHECK (
        (user_id IS NOT NULL AND install_id IS NULL)
        OR (user_id IS NULL AND install_id IS NOT NULL)
    )
);

CREATE INDEX fallback_attempts_user_attempted_idx
    ON fallback_attempts(user_id, attempted_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX fallback_attempts_install_attempted_idx
    ON fallback_attempts(install_id, attempted_at DESC) WHERE install_id IS NOT NULL;
