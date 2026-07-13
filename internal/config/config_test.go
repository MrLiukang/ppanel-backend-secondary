package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/perfect-panel/server/internal/config"
	"github.com/perfect-panel/server/pkg/conf"
)

func TestAllowLegacyNodeSecretDefaultsTrueAndAllowsExplicitFalse(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{name: "omitted", yaml: "Node:\n  NodeSecret: secret\n", want: true},
		{name: "explicit false", yaml: "Node:\n  NodeSecret: secret\n  AllowLegacyNodeSecret: false\n", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ppanel.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			var cfg config.Config
			if err := conf.Load(path, &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.Node.AllowLegacyNodeSecret != tt.want {
				t.Fatalf("AllowLegacyNodeSecret = %v, want %v", cfg.Node.AllowLegacyNodeSecret, tt.want)
			}
		})
	}
}
