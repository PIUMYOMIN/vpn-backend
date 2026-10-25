CREATE TABLE ad_config (
    id                          INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    ads_enabled                 BOOLEAN NOT NULL DEFAULT TRUE,
    admob_app_id                TEXT,
    rewarded_ad_unit_id         TEXT,
    banner_ad_unit_id           TEXT,
    app_open_ad_unit_id         TEXT,
    reward_hours                INT NOT NULL DEFAULT 24,
    banner_refresh_seconds      INT NOT NULL DEFAULT 60,
    banner_max_per_session      INT NOT NULL DEFAULT 5,
    banner_max_per_day          INT NOT NULL DEFAULT 20,
    app_open_min_interval_hours INT NOT NULL DEFAULT 24,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO ad_config (id) VALUES (1);

CREATE TRIGGER ad_config_set_updated_at
    BEFORE UPDATE ON ad_config
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
