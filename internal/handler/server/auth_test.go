package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
)

func expectedServerToken(secret string, serverID int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strconv.FormatInt(serverID, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestDeriveServerTokenBindsCredentialToServerID(t *testing.T) {
	tokenA := deriveServerToken("root-secret", 101)
	if want := expectedServerToken("root-secret", 101); tokenA != want {
		t.Fatalf("derived token = %q, want HMAC-SHA256(NodeSecret, serverID) %q", tokenA, want)
	}
	if !validServerToken(tokenA, "root-secret", 101, false) {
		t.Fatal("server A token must authorize server A")
	}
	if validServerToken(tokenA, "root-secret", 202, false) {
		t.Fatal("server A token must not authorize server B")
	}
}

func TestValidServerTokenLegacyMigrationSwitch(t *testing.T) {
	if validServerToken("root-secret", "root-secret", 101, false) {
		t.Fatal("legacy global secret must be rejected by default")
	}
	if !validServerToken("root-secret", "root-secret", 101, true) {
		t.Fatal("legacy global secret must be accepted while migration switch is enabled")
	}
}
