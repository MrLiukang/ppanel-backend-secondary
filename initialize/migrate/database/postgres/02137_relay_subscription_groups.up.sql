CREATE TABLE IF NOT EXISTS relay_subscription_groups
(
    id BIGSERIAL PRIMARY KEY,
    server_id BIGINT NOT NULL,
    name VARCHAR(120) NOT NULL,
    url VARCHAR(1024) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    auto_update BOOLEAN NOT NULL DEFAULT FALSE,
    update_interval INTEGER NOT NULL DEFAULT 86400,
    listen_port_start INTEGER NOT NULL DEFAULT 643,
    listen_port_step INTEGER NOT NULL DEFAULT 100,
    rules TEXT NOT NULL DEFAULT '[]',
    last_status VARCHAR(20) NOT NULL DEFAULT 'never',
    last_error TEXT,
    last_updated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_relay_subscription_groups_server_id ON relay_subscription_groups(server_id);
