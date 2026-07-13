package server

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/perfect-panel/server/internal/model/node"
	"gorm.io/gorm"
)

func TestDeleteServerManagedStateSkipsNodeDeleteHooksAndPreservesSorts(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&node.Node{}, &node.RelaySubscriptionGroup{}); err != nil {
		t.Fatal(err)
	}
	groupID := int64(7)
	enabled := true
	nodes := []node.Node{
		{Id: 1, Name: "other server", ServerId: 2, Sort: 1, Enabled: &enabled},
		{Id: 2, Name: "managed", ServerId: 1, Sort: 2, RelayGroupId: &groupID, RelayRuleId: "rule", Enabled: &enabled},
		{Id: 3, Name: "manual", ServerId: 1, Sort: 3, Enabled: &enabled},
		{Id: 4, Name: "other server 2", ServerId: 2, Sort: 4, Enabled: &enabled},
	}
	if err := db.Create(&nodes).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&node.RelaySubscriptionGroup{Id: groupID, ServerId: 1, Name: "group", URL: "https://example.com", Rules: "[]"}).Error; err != nil {
		t.Fatal(err)
	}

	if err := deleteServerManagedStateTx(db, 1); err != nil {
		t.Fatal(err)
	}
	var got []node.Node
	if err := db.Order("id").Find(&got).Error; err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Id != 1 || got[0].Sort != 1 || got[1].Id != 4 || got[1].Sort != 4 {
		t.Fatalf("remaining nodes/sorts = %#v, want other-server ids 1,4 with unchanged sorts 1,4", got)
	}
	var count int64
	if err := db.Model(&node.RelaySubscriptionGroup{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("relay groups remaining = %d, want 0", count)
	}
}

func TestManagedRelayNodesRejectOrdinaryMutation(t *testing.T) {
	groupID := int64(1)
	if err := rejectManagedRelayNode(&node.Node{RelayGroupId: &groupID, RelayRuleId: "rule"}); err == nil {
		t.Fatal("managed relay node mutation accepted")
	}
	if err := rejectManagedRelayNode(&node.Node{}); err != nil {
		t.Fatalf("ordinary node mutation rejected: %v", err)
	}
}

func TestRelayPreviewTokenBindsInputsAndExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	base := relayPreviewTokenBinding{
		GroupID:         7,
		URL:             "https://example.com/sub",
		ListenPortStart: 643,
		ListenPortStep:  100,
		Revision:        "revision",
		RulesDigest:     "rules",
	}
	token, err := signRelayPreviewToken("secret", base, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRelayPreviewToken("secret", token, base, now.Add(time.Minute)); err != nil {
		t.Fatalf("fresh token rejected: %v", err)
	}

	mutations := []struct {
		name string
		fn   func(*relayPreviewTokenBinding)
	}{
		{"group", func(v *relayPreviewTokenBinding) { v.GroupID++ }},
		{"url", func(v *relayPreviewTokenBinding) { v.URL += "?changed=1" }},
		{"start port", func(v *relayPreviewTokenBinding) { v.ListenPortStart++ }},
		{"step", func(v *relayPreviewTokenBinding) { v.ListenPortStep++ }},
		{"revision", func(v *relayPreviewTokenBinding) { v.Revision += "x" }},
		{"rules digest", func(v *relayPreviewTokenBinding) { v.RulesDigest += "x" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := base
			mutation.fn(&changed)
			if err := verifyRelayPreviewToken("secret", token, changed, now.Add(time.Minute)); err == nil {
				t.Fatal("token accepted after bound input changed")
			}
		})
	}
	if err := verifyRelayPreviewToken("other-secret", token, base, now.Add(time.Minute)); err == nil {
		t.Fatal("token accepted with a different secret")
	}
	if err := verifyRelayPreviewToken("secret", token+"x", base, now.Add(time.Minute)); err == nil {
		t.Fatal("tampered token accepted")
	}
	if err := verifyRelayPreviewToken("secret", token, base, now.Add(relayPreviewTokenTTL+time.Second)); err == nil {
		t.Fatal("expired token accepted")
	}
}
