DELETE FROM "system" WHERE "category" = 'server' AND "key" = 'RelayRules';

ALTER TABLE "server_config_overrides"
    DROP COLUMN IF EXISTS "relay_rules";
