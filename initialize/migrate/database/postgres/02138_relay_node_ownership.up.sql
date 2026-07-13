ALTER TABLE nodes ADD COLUMN relay_group_id BIGINT NULL;
ALTER TABLE nodes ADD COLUMN relay_rule_id VARCHAR(128) NOT NULL DEFAULT '';
CREATE INDEX idx_nodes_relay_group_id ON nodes(relay_group_id);
CREATE INDEX idx_nodes_relay_rule_id ON nodes(relay_rule_id);

WITH split AS (
    SELECT nodes.id, btrim(tag) AS tag
    FROM nodes
    CROSS JOIN LATERAL regexp_split_to_table(nodes.tags, ',') AS tag
), parsed AS (
    SELECT id,
           MAX(substring(tag FROM '^relay-group:([1-9][0-9]*)$')) AS group_id,
           MAX(substring(tag FROM '^relay-rule:([^[:space:],]+)$')) AS rule_id,
           COUNT(*) FILTER (WHERE tag LIKE 'relay-group:%') AS group_tags,
           COUNT(*) FILTER (WHERE tag ~ '^relay-group:[1-9][0-9]*$') AS valid_group_tags,
           COUNT(*) FILTER (WHERE tag LIKE 'relay-rule:%') AS rule_tags,
           COUNT(*) FILTER (WHERE tag ~ '^relay-rule:[^[:space:],]+$') AS valid_rule_tags
    FROM split
    GROUP BY id
)
UPDATE nodes
SET relay_group_id = parsed.group_id::BIGINT,
    relay_rule_id = parsed.rule_id
FROM parsed
WHERE nodes.id = parsed.id
  AND parsed.group_tags = 1
  AND parsed.valid_group_tags = 1
  AND parsed.rule_tags = 1
  AND parsed.valid_rule_tags = 1;
