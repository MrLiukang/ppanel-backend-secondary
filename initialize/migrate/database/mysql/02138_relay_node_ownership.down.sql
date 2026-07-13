DROP INDEX `idx_nodes_relay_rule_id` ON `nodes`;
DROP INDEX `idx_nodes_relay_group_id` ON `nodes`;
ALTER TABLE `nodes` DROP COLUMN `relay_rule_id`;
ALTER TABLE `nodes` DROP COLUMN `relay_group_id`;
