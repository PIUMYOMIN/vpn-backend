CREATE TABLE email_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    purpose     VARCHAR(20) NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT email_tokens_purpose_check CHECK (
        purpose IN ('verify', 'reset')
    )
);

CREATE INDEX email_tokens_user_purpose_idx
    ON email_tokens(user_id, purpose) WHERE used_at IS NULL;
