INSERT IGNORE INTO `system` (`category`, `key`, `value`, `type`, `desc`, `created_at`, `updated_at`)
VALUE ('server', 'RoutingRules', '', 'string', 'Node routing rules', NOW(3), NOW(3));

ALTER TABLE `server_config_overrides`
    ADD COLUMN `routing_mode` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT 'Routing merge mode override, NULL means inherit',
    ADD COLUMN `routing_rules` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci COMMENT 'Routing rules override, NULL means inherit';
