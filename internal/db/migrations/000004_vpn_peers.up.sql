CREATE TABLE vpn_peers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES users(id) ON DELETE CASCADE,
    install_id      UUID REFERENCES anonymous_installs(id) ON DELETE CASCADE,
    device_id       UUID REFERENCES devices(id) ON DELETE SET NULL,
    public_key      TEXT NOT NULL UNIQUE,
    preshared_key   TEXT,
    allowed_ip      VARCHAR(20) NOT NULL UNIQUE,
    server_endpoint VARCHAR(255),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_handshake  TIMESTAMPTZ,
    bytes_rx        BIGINT NOT NULL DEFAULT 0,
    bytes_tx        BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT vpn_peers_owner_check CHECK (
        (user_id IS NOT NULL AND install_id IS NULL) OR
        (user_id IS NULL AND install_id IS NOT NULL)
    )
);

CREATE INDEX vpn_peers_user_idx ON vpn_peers(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX vpn_peers_install_idx ON vpn_peers(install_id) WHERE install_id IS NOT NULL;
CREATE INDEX vpn_peers_active_idx ON vpn_peers(is_active) WHERE is_active = TRUE;

CREATE TRIGGER vpn_peers_set_updated_at
    BEFORE UPDATE ON vpn_peers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
