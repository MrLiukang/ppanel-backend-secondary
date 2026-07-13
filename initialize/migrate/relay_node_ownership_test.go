package migrate

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestRelayNodeOwnershipMigrationsCoverSupportedDialects(t *testing.T) {
	for _, dialect := range []string{"mysql", "postgres", "sqlite"} {
		data, err := sqlFiles.ReadFile("database/" + dialect + "/02138_relay_node_ownership.up.sql")
		if err != nil {
			t.Fatalf("read %s migration: %v", dialect, err)
		}
		sql := strings.ToLower(string(data))
		for _, column := range []string{"relay_group_id", "relay_rule_id"} {
			if !strings.Contains(sql, column) {
				t.Fatalf("%s migration missing %s", dialect, column)
			}
		}
	}
}

func TestRelayNodeOwnershipMigrationRunsOnSQLite(t *testing.T) {
	path := filepath.ToSlash(filepath.Join(t.TempDir(), "relay.db"))
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec("CREATE TABLE nodes (id INTEGER PRIMARY KEY, tags TEXT NOT NULL DEFAULT '')"); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		id   int
		tags string
	}{
		{1, "user, relay-group:7, relay-rule:rule-1"},
		{2, "relay-group:8"},
		{3, "relay-group:9x,relay-rule:rule-3"},
		{4, "relay-group:10,relay-group:11,relay-rule:rule-4"},
		{5, "relay-group:12,relay-rule:rule-5,relay-rule:other"},
		{6, "relay-group:13,relay-rule:"},
		{7, "relay-group:14,relay-rule:bad rule"},
		{8, "relay-group:015,relay-rule:rule-8"},
	}
	for _, row := range rows {
		if _, err := db.Exec("INSERT INTO nodes (id, tags) VALUES (?, ?)", row.id, row.tags); err != nil {
			t.Fatal(err)
		}
	}

	migration := Migrate("sqlite", path)
	t.Cleanup(func() { _, _ = migration.Close() })
	if err := migration.Up(); err != nil {
		t.Fatalf("sqlite migration failed: %v", err)
	}

	columnRows, err := db.Query("PRAGMA table_info(nodes)")
	if err != nil {
		t.Fatal(err)
	}
	defer columnRows.Close()
	columns := map[string]bool{}
	for columnRows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := columnRows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	for _, name := range []string{"relay_group_id", "relay_rule_id"} {
		if !columns[name] {
			t.Fatalf("sqlite migration did not add %s", name)
		}
	}

	var groupID sql.NullInt64
	var ruleID string
	if err := db.QueryRow("SELECT relay_group_id, relay_rule_id FROM nodes WHERE id = 1").Scan(&groupID, &ruleID); err != nil {
		t.Fatal(err)
	}
	if !groupID.Valid || groupID.Int64 != 7 || ruleID != "rule-1" {
		t.Fatalf("valid ownership backfill = (%v, %q), want (7, rule-1)", groupID, ruleID)
	}
	for id := 2; id <= 8; id++ {
		groupID, ruleID = sql.NullInt64{}, ""
		if err := db.QueryRow("SELECT relay_group_id, relay_rule_id FROM nodes WHERE id = ?", id).Scan(&groupID, &ruleID); err != nil {
			t.Fatal(err)
		}
		if groupID.Valid || ruleID != "" {
			t.Fatalf("node %d unexpectedly backfilled to (%v, %q)", id, groupID, ruleID)
		}
	}
}
