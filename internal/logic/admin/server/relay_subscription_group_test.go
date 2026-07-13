package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/perfect-panel/server/internal/model/node"
	"github.com/perfect-panel/server/internal/types"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestRelayNodeOwnershipDoesNotUseTags(t *testing.T) {
	n := node.Node{Tags: "relay-group:7,relay-rule:user-tag", RelayGroupId: int64Ptr(9), RelayRuleId: "owned"}
	if relayNodeBelongsToGroup(n, 7) {
		t.Fatal("ordinary tags must not establish relay ownership")
	}
	if !relayNodeMatchesGroupRule(n, 9, "owned") {
		t.Fatal("explicit ownership fields were not matched")
	}
}

func TestValidateRelaySubscriptionRequestRejectsAutoUpdateAndInvalidURL(t *testing.T) {
	if err := validateRelaySubscriptionRequest(true, "https://example.com/sub"); err == nil {
		t.Fatal("auto_update=true accepted")
	}
	for _, raw := range []string{"httpx://example.com", "ftp://example.com", "https:example.com"} {
		if err := validateRelaySubscriptionRequest(false, raw); err == nil {
			t.Fatalf("invalid URL %q accepted", raw)
		}
	}
	if err := validateRelaySubscriptionRequest(false, "https://example.com/sub"); err != nil {
		t.Fatalf("valid URL rejected: %v", err)
	}
}

func int64Ptr(value int64) *int64 { return &value }

func TestValidateRelayGroupHealthEnabledRejectsDisabled(t *testing.T) {
	if err := validateRelayGroupHealthEnabled(false); err == nil {
		t.Fatal("disabled group accepted health results")
	}
}

func TestRelayGroupTransitionRebuildsOnReenable(t *testing.T) {
	deleteNodes, rebuild := relayGroupTransition(false, true)
	if deleteNodes || !rebuild {
		t.Fatalf("disable->enable transition = delete %v rebuild %v", deleteNodes, rebuild)
	}
	deleteNodes, rebuild = relayGroupTransition(true, false)
	if !deleteNodes || !rebuild {
		t.Fatalf("enable->disable transition = delete %v rebuild %v", deleteNodes, rebuild)
	}
}

func TestSyncRelayNodeManagedFieldsPreservesUserName(t *testing.T) {
	enabled := false
	existing := node.Node{Name: "Custom user name", Port: 1, Address: "old", Protocol: "old", Enabled: &enabled}
	syncRelayNodeManagedFields(&existing, 643, "new.example.com", "vless")
	if existing.Name != "Custom user name" {
		t.Fatalf("node name = %q, want user-owned name preserved", existing.Name)
	}
	if existing.Port != 643 || existing.Address != "new.example.com" || existing.Protocol != "vless" || existing.Enabled == nil || !*existing.Enabled {
		t.Fatalf("managed fields were not synchronized: %#v", existing)
	}
}

func TestMergeSubscriptionRelayRulesPreservesManualRules(t *testing.T) {
	manual := types.NodeRelayRule{ID: "manual", Enabled: true, ListenPort: 443}
	oldDerived := types.NodeRelayRule{ID: subscriptionRelayRuleID(1, "old"), Enabled: true, ListenPort: 643}
	newDerived := types.NodeRelayRule{ID: "new", Enabled: true, ListenPort: 743}

	got, err := mergeSubscriptionRelayRules([]types.NodeRelayRule{manual, oldDerived}, map[int64][]types.NodeRelayRule{2: {newDerived}})
	if err != nil {
		t.Fatalf("mergeSubscriptionRelayRules() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("merged rules = %#v, want manual and current derived rule", got)
	}
	if got[0].ID != manual.ID {
		t.Fatalf("first rule ID = %q, want preserved manual rule", got[0].ID)
	}
	if got[1].ID != subscriptionRelayRuleID(2, newDerived.ID) {
		t.Fatalf("derived rule ID = %q, want group ownership marker", got[1].ID)
	}
}

func TestRelayNodeMatchesGroupRuleUsesExactTags(t *testing.T) {
	if relayNodeMatchesGroupRule(node.Node{RelayGroupId: int64Ptr(10), RelayRuleId: "abc"}, 1, "abc") {
		t.Fatal("group 1 matched group 10 tags")
	}
	if relayNodeMatchesGroupRule(node.Node{RelayGroupId: int64Ptr(1), RelayRuleId: "abc-extra"}, 1, "abc") {
		t.Fatal("rule abc matched rule abc-extra tag")
	}
	if !relayNodeMatchesGroupRule(node.Node{RelayGroupId: int64Ptr(1), RelayRuleId: "abc"}, 1, "abc") {
		t.Fatal("exact group and rule tags did not match")
	}
}

func TestCurrentHealthResultsRejectUnknownRules(t *testing.T) {
	rules := []types.NodeRelayRule{{ID: "current"}}
	results := []types.RelaySubscriptionGroupHealthResult{
		{RuleID: "current", Healthy: true},
		{RuleID: "stale", Healthy: true},
	}

	if _, err := currentHealthResults(rules, results); err == nil {
		t.Fatal("currentHealthResults() error = nil, want stale rule rejection")
	}
}

func TestRelayNodeIsOrphanedWhenRuleWasRemoved(t *testing.T) {
	current := map[string]struct{}{"current": {}}
	if !relayNodeIsOrphaned(node.Node{RelayGroupId: int64Ptr(7), RelayRuleId: "removed"}, 7, current) {
		t.Fatal("removed derived node was not classified as orphaned")
	}
	if relayNodeIsOrphaned(node.Node{RelayGroupId: int64Ptr(7), RelayRuleId: "current"}, 7, current) {
		t.Fatal("current derived node was classified as orphaned")
	}
	if relayNodeIsOrphaned(node.Node{Tags: "relay-group:7,relay-rule:removed"}, 7, current) {
		t.Fatal("manual node was classified as orphaned")
	}
}

func TestAssignSidecarPortsKeepsPortsStableAcrossReorderAndInsert(t *testing.T) {
	oldRules := []types.NodeRelayRule{
		{ID: "a", SidecarPort: 31001},
		{ID: "b", SidecarPort: 31002},
	}
	newRules := []types.NodeRelayRule{{ID: "b"}, {ID: "c"}, {ID: "a"}}

	got, err := assignSidecarPorts(newRules, oldRules, nil)
	if err != nil {
		t.Fatalf("assignSidecarPorts() error = %v", err)
	}
	if got[0].SidecarPort != 31002 || got[1].SidecarPort != 31003 || got[2].SidecarPort != 31001 {
		t.Fatalf("sidecar ports = [%d %d %d], want [31002 31003 31001]", got[0].SidecarPort, got[1].SidecarPort, got[2].SidecarPort)
	}
}

func TestAssignSidecarPortsMigratesLegacyRulesByOldIndex(t *testing.T) {
	oldRules := []types.NodeRelayRule{{ID: "a"}, {ID: "b"}}
	newRules := []types.NodeRelayRule{{ID: "b"}, {ID: "a"}}

	got, err := assignSidecarPorts(newRules, oldRules, nil)
	if err != nil {
		t.Fatalf("assignSidecarPorts() error = %v", err)
	}
	if got[0].SidecarPort != 31002 || got[1].SidecarPort != 31001 {
		t.Fatalf("migrated ports = [%d %d], want [31002 31001]", got[0].SidecarPort, got[1].SidecarPort)
	}
}

func TestAssignSidecarPortsRejectsGroupOverCapacity(t *testing.T) {
	rules := make([]types.NodeRelayRule, 30001)
	for i := range rules {
		rules[i].ID = fmt.Sprintf("rule-%d", i)
	}
	if _, err := assignSidecarPorts(rules, nil, nil); err == nil {
		t.Fatal("assignSidecarPorts() error = nil, want group capacity error")
	}
}

func TestAssignSidecarPortsUsesServerWideOccupiedPool(t *testing.T) {
	rules := []types.NodeRelayRule{{ID: "new"}}
	got, err := assignSidecarPorts(rules, nil, map[int]struct{}{31001: {}, 31002: {}, 31101: {}})
	if err != nil {
		t.Fatalf("assignSidecarPorts() error = %v", err)
	}
	if got[0].SidecarPort != 31003 {
		t.Fatalf("sidecar port = %d, want first server-wide free port 31003", got[0].SidecarPort)
	}
}

func TestAssignSidecarPortsDoesNotReusePortOccupiedByAnotherGroup(t *testing.T) {
	rules := []types.NodeRelayRule{{ID: "same"}}
	oldRules := []types.NodeRelayRule{{ID: "same", SidecarPort: 31001}}
	got, err := assignSidecarPorts(rules, oldRules, map[int]struct{}{31001: {}})
	if err != nil {
		t.Fatalf("assignSidecarPorts() error = %v", err)
	}
	if got[0].SidecarPort != 31002 {
		t.Fatalf("sidecar port = %d, want 31002 because 31001 belongs to another group", got[0].SidecarPort)
	}
}

func TestValidateSubscriptionRuntimeRules(t *testing.T) {
	valid := types.NodeRelayRule{ID: "rule", Enabled: true, ListenPort: 643, Network: "tcp,udp", TargetAddress: "example.com", TargetPort: 443}
	tests := []struct {
		name string
		rule types.NodeRelayRule
	}{
		{name: "reject generic socks", rule: func() types.NodeRelayRule { r := valid; r.TargetProtocol = "socks"; return r }()},
		{name: "vless requires uuid", rule: func() types.NodeRelayRule { r := valid; r.TargetProtocol = "vless"; return r }()},
		{name: "trojan requires password", rule: func() types.NodeRelayRule { r := valid; r.TargetProtocol = "trojan"; return r }()},
		{name: "shadowsocks requires password", rule: func() types.NodeRelayRule {
			r := valid
			r.TargetProtocol = "shadowsocks"
			r.TargetMethod = "aes-256-gcm"
			return r
		}()},
		{name: "anytls requires password", rule: func() types.NodeRelayRule { r := valid; r.TargetProtocol = "anytls"; return r }()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateSubscriptionRuntimeRules([]types.NodeRelayRule{tt.rule}); err == nil {
				t.Fatal("validateSubscriptionRuntimeRules() error = nil")
			}
		})
	}
	valid.TargetProtocol, valid.TargetUUID = "vless", "11111111-1111-1111-1111-111111111111"
	if err := validateSubscriptionRuntimeRules([]types.NodeRelayRule{valid}); err != nil {
		t.Fatalf("valid vless rejected: %v", err)
	}
}

func TestMergeSubscriptionRelayRulesPreservesUnownedRuleOnExactLegacyCollision(t *testing.T) {
	manual := types.NodeRelayRule{ID: "manual", ListenPort: 443}
	legacyOwned := types.NodeRelayRule{ID: "owned", ListenPort: 643}
	legacySameIDWrongPort := types.NodeRelayRule{ID: "owned", ListenPort: 644}
	groupRules := map[int64][]types.NodeRelayRule{7: {{ID: "owned", ListenPort: 643}}}

	got, err := mergeSubscriptionRelayRules([]types.NodeRelayRule{manual, legacyOwned, legacySameIDWrongPort}, groupRules)
	if err == nil || !strings.Contains(err.Error(), "legacy migration conflict") {
		t.Fatalf("mergeSubscriptionRelayRules() error = %v, want legacy migration conflict", err)
	}
	if got != nil {
		t.Fatalf("merged rules = %#v, want no partial result", got)
	}
}

func TestMergeSubscriptionRelayRulesExactCollisionNeverDeletesManualRule(t *testing.T) {
	manual := types.NodeRelayRule{ID: "same", ListenPort: 643}
	_, err := mergeSubscriptionRelayRules([]types.NodeRelayRule{manual}, map[int64][]types.NodeRelayRule{7: {{ID: "same", ListenPort: 643}}})
	if err == nil || !strings.Contains(err.Error(), "legacy migration conflict") {
		t.Fatalf("mergeSubscriptionRelayRules() error = %v, want exact-collision conflict", err)
	}
}

func TestRelaySubscriptionRulesRevisionIsStableAndTracksRuntimeChanges(t *testing.T) {
	rules := []types.NodeRelayRule{{ID: "same", Enabled: true, ListenPort: 643, TargetProtocol: "vless", TargetAddress: "old.example", TargetPort: 443}}
	first, err := relaySubscriptionRulesRevision(rules)
	if err != nil {
		t.Fatalf("relaySubscriptionRulesRevision() error = %v", err)
	}
	second, err := relaySubscriptionRulesRevision(append([]types.NodeRelayRule(nil), rules...))
	if err != nil || second != first {
		t.Fatalf("equivalent revision = %q, %v; want %q", second, err, first)
	}
	changed := append([]types.NodeRelayRule(nil), rules...)
	changed[0].TargetAddress = "new.example"
	third, err := relaySubscriptionRulesRevision(changed)
	if err != nil {
		t.Fatalf("changed revision error = %v", err)
	}
	if third == first {
		t.Fatal("upstream change did not change revision")
	}
}

func TestWithCurrentRelayRevisionRejectsStaleReportWithoutMutation(t *testing.T) {
	rules := []types.NodeRelayRule{{ID: "same", TargetAddress: "new.example"}}
	mutated := false
	err := withCurrentRelayRevision(rules, "old-revision", func() error {
		mutated = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "revision mismatch") {
		t.Fatalf("withCurrentRelayRevision() error = %v, want revision mismatch", err)
	}
	if mutated {
		t.Fatal("stale health report invoked mutation")
	}
	if shouldRecordRelayHealthFailure(err) {
		t.Fatal("revision mismatch would update group status")
	}
}

func TestRelaySubscriptionGroupResponseIncludesCurrentRevision(t *testing.T) {
	rules := []types.NodeRelayRule{{ID: "same", TargetAddress: "new.example"}}
	raw, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	response := relaySubscriptionGroupResponse(node.RelaySubscriptionGroup{Id: 7, Rules: string(raw)})
	want, err := relaySubscriptionRulesRevision(rules)
	if err != nil {
		t.Fatal(err)
	}
	if response.Revision != want {
		t.Fatalf("response revision = %q, want %q", response.Revision, want)
	}
}

func TestHealthStatusRequiresEveryEnabledRuleHealthy(t *testing.T) {
	rules := []types.NodeRelayRule{{ID: "a", Enabled: true}, {ID: "b", Enabled: true}, {ID: "off", Enabled: false}}
	results := map[string]types.RelaySubscriptionGroupHealthResult{"a": {RuleID: "a", Healthy: true}, "b": {RuleID: "b", Healthy: false, Error: "dial failed"}}
	status, message := relayGroupHealthStatus(rules, results)
	if status != "error" || message != "dial failed" {
		t.Fatalf("status = %q, error = %q", status, message)
	}
	results["b"] = types.RelaySubscriptionGroupHealthResult{RuleID: "b", Healthy: true}
	status, message = relayGroupHealthStatus(rules, results)
	if status != "success" || message != "" {
		t.Fatalf("all healthy status = %q, error = %q", status, message)
	}
}

func TestApplyStatusValuesNeverReportsSuccessForFailure(t *testing.T) {
	values := applyStatusValues(errors.New("override rejected"), time.Now())
	if values["last_status"] == "success" {
		t.Fatal("failed apply was recorded as success")
	}
	if values["last_status"] != "error" || values["last_error"] != "override rejected" {
		t.Fatalf("failure values = %#v", values)
	}
}

func TestDisableUnhealthyRelayNodePropagatesDatabaseError(t *testing.T) {
	db, err := gorm.Open(mysql.New(mysql.Config{
		DSN:                       "gorm:gorm@tcp(localhost:9910)/gorm?charset=utf8&parseTime=True&loc=Local",
		SkipInitializeWithVersion: true,
	}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("node query failed")
	db.AddError(want)
	if err := disableUnhealthyRelayNode(db, 1, 2, "rule"); !errors.Is(err, want) {
		t.Fatalf("disableUnhealthyRelayNode() error = %v, want %v", err, want)
	}
}
