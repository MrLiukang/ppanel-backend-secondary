INSERT IGNORE INTO `system` (`category`, `key`, `value`, `type`, `desc`, `created_at`, `updated_at`)
VALUE ('server', 'RelayRules', '', 'string', 'Node relay rules', NOW(3), NOW(3));

ALTER TABLE `server_config_overrides`
    ADD COLUMN `relay_rules` TEXT NULL COMMENT 'Relay rules override, NULL means inherit' AFTER `routing_rules`;
