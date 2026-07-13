package initialize

import (
	"testing"

	"github.com/perfect-panel/server/internal/config"
)

func TestNodeConfigFromDBPreservesLegacyCompatibilitySwitch(t *testing.T) {
	current := config.NodeConfig{NodeSecret: "yaml-secret", AllowLegacyNodeSecret: true}
	dbConfig := config.NodeDBConfig{NodeSecret: "db-secret", NodePullInterval: 30}

	got := nodeConfigFromDB(current, dbConfig)
	if got.NodeSecret != "db-secret" || got.NodePullInterval != 30 {
		t.Fatalf("database-managed fields not applied: %#v", got)
	}
	if !got.AllowLegacyNodeSecret {
		t.Fatal("runtime legacy compatibility switch was discarded")
	}
}
