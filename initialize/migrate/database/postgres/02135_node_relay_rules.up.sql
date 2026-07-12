INSERT INTO "system" ("category", "key", "value", "type", "desc", "created_at", "updated_at")
VALUES ('server', 'RelayRules', '', 'string', 'Node relay rules', NOW(), NOW()) ON CONFLICT DO NOTHING;

ALTER TABLE "server_config_overrides"
    ADD COLUMN IF NOT EXISTS "relay_rules" TEXT NULL;
