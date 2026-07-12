INSERT INTO "system" ("category", "key", "value", "type", "desc", "created_at", "updated_at")
VALUES ('server', 'RoutingRules', '', 'string', 'Node routing rules', NOW(), NOW()) ON CONFLICT DO NOTHING;

ALTER TABLE "server_config_overrides"
    ADD COLUMN "routing_mode" varchar(20) DEFAULT NULL,
    ADD COLUMN "routing_rules" text DEFAULT NULL;
