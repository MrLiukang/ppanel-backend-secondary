CREATE TABLE IF NOT EXISTS `relay_subscription_groups`
(
    `id` BIGINT NOT NULL AUTO_INCREMENT,
    `server_id` BIGINT NOT NULL,
    `name` VARCHAR(120) NOT NULL,
    `url` VARCHAR(1024) NOT NULL,
    `enabled` TINYINT(1) NOT NULL DEFAULT 1,
    `auto_update` TINYINT(1) NOT NULL DEFAULT 0,
    `update_interval` INT NOT NULL DEFAULT 86400,
    `listen_port_start` INT NOT NULL DEFAULT 643,
    `listen_port_step` INT NOT NULL DEFAULT 100,
    `rules` LONGTEXT NOT NULL,
    `last_status` VARCHAR(20) NOT NULL DEFAULT 'never',
    `last_error` TEXT NULL,
    `last_updated_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NULL,
    `updated_at` DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    KEY `idx_relay_subscription_groups_server_id` (`server_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
