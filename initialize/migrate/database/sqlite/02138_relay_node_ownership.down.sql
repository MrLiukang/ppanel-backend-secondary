DROP INDEX IF EXISTS idx_nodes_relay_rule_id;
DROP INDEX IF EXISTS idx_nodes_relay_group_id;
ALTER TABLE nodes DROP COLUMN relay_rule_id;
ALTER TABLE nodes DROP COLUMN relay_group_id;
