ALTER TABLE nodes ADD COLUMN relay_group_id INTEGER NULL;
ALTER TABLE nodes ADD COLUMN relay_rule_id TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_nodes_relay_group_id ON nodes(relay_group_id);
CREATE INDEX idx_nodes_relay_rule_id ON nodes(relay_rule_id);

WITH RECURSIVE split(id, rest, tag) AS (
    SELECT id, tags || ',', '' FROM nodes
    UNION ALL
    SELECT id,
           substr(rest, instr(rest, ',') + 1),
           trim(substr(rest, 1, instr(rest, ',') - 1))
    FROM split
    WHERE rest <> ''
), parsed AS (
    SELECT id,
           MAX(CASE WHEN tag GLOB 'relay-group:[1-9]*' AND substr(tag, 13) NOT GLOB '*[^0-9]*'
                    THEN CAST(substr(tag, 13) AS INTEGER) END) AS group_id,
           MAX(CASE WHEN tag GLOB 'relay-rule:?*'
                         AND instr(substr(tag, 12), ' ') = 0
                         AND instr(substr(tag, 12), char(9)) = 0
                         AND instr(substr(tag, 12), char(10)) = 0
                         AND instr(substr(tag, 12), char(13)) = 0
                    THEN substr(tag, 12) END) AS rule_id,
           SUM(CASE WHEN tag LIKE 'relay-group:%' THEN 1 ELSE 0 END) AS group_tags,
           SUM(CASE WHEN tag GLOB 'relay-group:[1-9]*' AND substr(tag, 13) NOT GLOB '*[^0-9]*' THEN 1 ELSE 0 END) AS valid_group_tags,
           SUM(CASE WHEN tag LIKE 'relay-rule:%' THEN 1 ELSE 0 END) AS rule_tags,
           SUM(CASE WHEN tag GLOB 'relay-rule:?*'
                          AND instr(substr(tag, 12), ' ') = 0
                          AND instr(substr(tag, 12), char(9)) = 0
                          AND instr(substr(tag, 12), char(10)) = 0
                          AND instr(substr(tag, 12), char(13)) = 0
                    THEN 1 ELSE 0 END) AS valid_rule_tags
    FROM split
    WHERE tag <> ''
    GROUP BY id
), valid AS (
    SELECT id, group_id, rule_id
    FROM parsed
    WHERE group_tags = 1 AND valid_group_tags = 1 AND rule_tags = 1 AND valid_rule_tags = 1
)
UPDATE nodes
SET relay_group_id = (SELECT group_id FROM valid WHERE valid.id = nodes.id),
    relay_rule_id = (SELECT rule_id FROM valid WHERE valid.id = nodes.id)
WHERE id IN (SELECT id FROM valid);
