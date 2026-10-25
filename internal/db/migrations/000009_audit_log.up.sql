CREATE TABLE audit_log (
    id            BIGSERIAL PRIMARY KEY,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_type    VARCHAR(20) NOT NULL DEFAULT 'user',
    action        VARCHAR(50) NOT NULL,
    target_type   VARCHAR(30),
    target_id     TEXT,
    metadata      JSONB,
    ip_address    INET,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_log_created_idx ON audit_log(created_at DESC);
CREATE INDEX audit_log_actor_idx ON audit_log(actor_user_id);
CREATE INDEX audit_log_target_idx ON audit_log(target_type, target_id);
