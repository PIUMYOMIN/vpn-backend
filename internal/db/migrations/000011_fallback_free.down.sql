-- Remove fallback attempt state and restore the entitlement source constraint.
DROP TABLE IF EXISTS fallback_attempts;

ALTER TABLE entitlements DROP CONSTRAINT IF EXISTS entitlements_granted_by_check;
ALTER TABLE entitlements ADD CONSTRAINT entitlements_granted_by_check
    CHECK (granted_by IN ('rewarded_ad', 'manual', 'promo'));
