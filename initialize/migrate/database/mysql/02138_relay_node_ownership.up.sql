ALTER TABLE `nodes` ADD COLUMN `relay_group_id` BIGINT NULL;
ALTER TABLE `nodes` ADD COLUMN `relay_rule_id` VARCHAR(128) NOT NULL DEFAULT '';
CREATE INDEX `idx_nodes_relay_group_id` ON `nodes` (`relay_group_id`);
CREATE INDEX `idx_nodes_relay_rule_id` ON `nodes` (`relay_rule_id`);

WITH RECURSIVE split AS (
    SELECT id, CONCAT(tags, ',') AS rest, CAST('' AS CHAR(255)) AS tag
    FROM nodes
    UNION ALL
    SELECT id,
           SUBSTRING(rest, LOCATE(',', rest) + 1),
           TRIM(SUBSTRING(rest, 1, LOCATE(',', rest) - 1))
    FROM split
    WHERE rest <> ''
), parsed AS (
    SELECT id,
           MAX(CASE WHEN tag REGEXP '^relay-group:[1-9][0-9]*$' THEN SUBSTRING(tag, 13) END) AS group_id,
           MAX(CASE WHEN tag REGEXP '^relay-rule:[^[:space:],]+$' THEN SUBSTRING(tag, 12) END) AS rule_id,
           SUM(tag LIKE 'relay-group:%') AS group_tags,
           SUM(tag REGEXP '^relay-group:[1-9][0-9]*$') AS valid_group_tags,
           SUM(tag LIKE 'relay-rule:%') AS rule_tags,
           SUM(tag REGEXP '^relay-rule:[^[:space:],]+$') AS valid_rule_tags
    FROM split
    WHERE tag <> ''
    GROUP BY id
)
UPDATE nodes
JOIN parsed ON parsed.id = nodes.id
SET nodes.relay_group_id = CAST(parsed.group_id AS UNSIGNED),
    nodes.relay_rule_id = parsed.rule_id
WHERE parsed.group_tags = 1
  AND parsed.valid_group_tags = 1
  AND parsed.rule_tags = 1
  AND parsed.valid_rule_tags = 1;
