DELETE FROM "system" WHERE "category" = 'server' AND "key" = 'RoutingRules';

ALTER TABLE "server_config_overrides"
    DROP COLUMN "routing_rules",
    DROP COLUMN "routing_mode";
