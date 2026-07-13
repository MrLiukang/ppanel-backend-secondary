package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildRuleRuntimeKeepsRulesIndependent(t *testing.T) {
	first, ok, err := buildRuleRuntime(1, 0, relayRule{ID: "a", Enabled: true, TargetProtocol: "anytls", TargetAddress: "a.example", TargetPort: 443, TargetPassword: "secret"})
	if err != nil || !ok {
		t.Fatalf("AnyTLS runtime: ok=%v err=%v", ok, err)
	}
	second, ok, err := buildRuleRuntime(1, 1, relayRule{ID: "b", Enabled: true, TargetProtocol: "trojan", TargetAddress: "b.example", TargetPort: 443, TargetPassword: "secret", TargetSecurity: "tls", TargetSNI: "b.example"})
	if err != nil || !ok {
		t.Fatalf("Trojan runtime: ok=%v err=%v", ok, err)
	}
	if first.Key == second.Key || first.Script == second.Script || first.Digest == second.Digest {
		t.Fatalf("runtime entries are not independent: %#v %#v", first, second)
	}
	if second.Config == "" {
		t.Fatal("Trojan runtime did not generate an Xray config")
	}
}

func TestBuildRuleRuntimeSupportsShadowsocks(t *testing.T) {
	entry, ok, err := buildRuleRuntime(2, 0, relayRule{ID: "ss", Enabled: true, TargetProtocol: "shadowsocks", TargetAddress: "ss.example", TargetPort: 8443, TargetMethod: "aes-256-gcm", TargetPassword: "secret"})
	if err != nil || !ok || entry.Config == "" {
		t.Fatalf("Shadowsocks runtime: entry=%#v ok=%v err=%v", entry, ok, err)
	}
}

func TestBuildRuleRuntimeUsesSidecarPortAndStableRuleIdentity(t *testing.T) {
	rule := relayRule{ID: "stable", Enabled: true, SidecarPort: 31042, TargetProtocol: "anytls", TargetAddress: "a.example", TargetPort: 443, TargetPassword: "secret"}
	before, ok, err := buildRuleRuntime(1, 7, rule)
	if err != nil || !ok {
		t.Fatalf("build before: ok=%v err=%v", ok, err)
	}
	after, ok, err := buildRuleRuntime(1, 2, rule)
	if err != nil || !ok {
		t.Fatalf("build after: ok=%v err=%v", ok, err)
	}
	if before.Key != after.Key || before.Digest != after.Digest {
		t.Fatalf("index changed stable runtime: before=%#v after=%#v", before, after)
	}
	if before.Port != rule.SidecarPort {
		t.Fatalf("runtime port = %d, want %d", before.Port, rule.SidecarPort)
	}
}

func TestBuildRuleRuntimeFallsBackToLegacyIndexPort(t *testing.T) {
	entry, ok, err := buildRuleRuntime(3, 4, relayRule{ID: "legacy", Enabled: true, TargetProtocol: "anytls", TargetAddress: "a.example", TargetPort: 443, TargetPassword: "secret"})
	if err != nil || !ok {
		t.Fatalf("build legacy: ok=%v err=%v", ok, err)
	}
	if entry.Port != basePort(3)+4 {
		t.Fatalf("legacy port = %d, want %d", entry.Port, basePort(3)+4)
	}
}

func TestBuildRuleRuntimeRejectsMissingStableRuleID(t *testing.T) {
	_, _, err := buildRuleRuntime(1, 0, relayRule{Enabled: true, TargetProtocol: "anytls", TargetAddress: "a.example", TargetPort: 443, TargetPassword: "secret"})
	if err == nil {
		t.Fatal("expected missing rule ID error")
	}
}

func TestBuildRuleRuntimeReturnsExplicitProtocolAndCredentialErrors(t *testing.T) {
	tests := []struct {
		name string
		rule relayRule
		want string
	}{
		{name: "unknown protocol", rule: relayRule{ID: "bad", Enabled: true, TargetProtocol: "invalid", TargetAddress: "example.com", TargetPort: 443}, want: "unsupported target protocol"},
		{name: "AnyTLS password", rule: relayRule{ID: "bad", Enabled: true, TargetProtocol: "anytls", TargetAddress: "example.com", TargetPort: 443}, want: "password is required"},
		{name: "VLESS UUID", rule: relayRule{ID: "bad", Enabled: true, TargetProtocol: "vless", TargetAddress: "example.com", TargetPort: 443}, want: "UUID is required"},
		{name: "Trojan password", rule: relayRule{ID: "bad", Enabled: true, TargetProtocol: "trojan", TargetAddress: "example.com", TargetPort: 443}, want: "password is required"},
		{name: "Shadowsocks method", rule: relayRule{ID: "bad", Enabled: true, TargetProtocol: "shadowsocks", TargetAddress: "example.com", TargetPort: 443, TargetPassword: "secret"}, want: "method is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok, err := buildRuleRuntime(1, 0, tt.rule)
			if ok || err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("build result: ok=%v err=%v, want error containing %q", ok, err, tt.want)
			}
		})
	}
}

func TestValidateRuntimePortsUsesGlobalSidecarRange(t *testing.T) {
	tests := []struct {
		name    string
		entries []runtimeEntry
	}{
		{name: "duplicate", entries: []runtimeEntry{{Key: "a", Port: 31101}, {Key: "b", Port: 31101}}},
		{name: "below global", entries: []runtimeEntry{{Key: "a", Port: 31000}}},
		{name: "above global", entries: []runtimeEntry{{Key: "a", Port: 61001}}},
		{name: "duplicate identity", entries: []runtimeEntry{{Key: "same", Port: 31101}, {Key: "same", Port: 31102}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateRuntimePorts(2, tt.entries); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if err := validateRuntimePorts(2, []runtimeEntry{{Key: "first", Port: 31001}, {Key: "cross-group", Port: 60000}, {Key: "last", Port: 61000}}); err != nil {
		t.Fatalf("valid boundary ports: %v", err)
	}
}

func TestApplyRuntimeEntriesContinuesAfterRuleFailure(t *testing.T) {
	entries := []runtimeEntry{{Key: "bad", Digest: "bad-digest"}, {Key: "good", Digest: "good-digest"}}
	state := map[string]string{}
	var applied []string
	failures := applyRuntimeEntries(entries, state, func(runtimeEntry) bool { return false }, func(entry runtimeEntry) error {
		applied = append(applied, entry.Key)
		if entry.Key == "bad" {
			return errors.New("start failed")
		}
		return nil
	})
	if want := []string{"bad", "good"}; !reflect.DeepEqual(applied, want) {
		t.Fatalf("applied = %v, want %v", applied, want)
	}
	if !strings.Contains(failures["bad"].Error(), "start failed") || failures["good"] != nil {
		t.Fatalf("failures = %#v", failures)
	}
	if _, exists := state["bad"]; exists || state["good"] != "good-digest" {
		t.Fatalf("state = %#v", state)
	}
}

func TestBuildRuntimeEntriesContinuesAfterInvalidRule(t *testing.T) {
	item := group{Id: 1, Rules: []relayRule{
		{ID: "bad", Enabled: true, SidecarPort: 31001, TargetProtocol: "unknown", TargetAddress: "bad.example", TargetPort: 443},
		{ID: "good", Enabled: true, SidecarPort: 31002, TargetProtocol: "anytls", TargetAddress: "good.example", TargetPort: 443, TargetPassword: "secret"},
	}}
	entries, failures := buildRuntimeEntries([]group{item})
	if len(entries) != 1 || entries[0].RuleID != "good" {
		t.Fatalf("entries = %#v", entries)
	}
	if !strings.Contains(failures[1]["bad"].Error(), "unsupported target protocol") {
		t.Fatalf("failures = %#v", failures)
	}
}

func TestGroupJSONReadsRevision(t *testing.T) {
	var payload response
	if err := json.Unmarshal([]byte(`{"groups":[{"id":1,"enabled":true,"revision":42,"rules":[]}]}`), &payload); err != nil {
		t.Fatalf("decode groups: %v", err)
	}
	if len(payload.Groups) != 1 || payload.Groups[0].Revision != 42 {
		t.Fatalf("groups = %#v, want revision 42", payload.Groups)
	}
}

func TestReportGroupHealthPostsBuildFailureFalseAndContinues(t *testing.T) {
	var posted struct {
		Revision int64 `json:"revision"`
		Results  []struct {
			RuleID  string `json:"rule_id"`
			Healthy bool   `json:"healthy"`
			Error   string `json:"error"`
		} `json:"results"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
			t.Fatalf("decode health body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	item := group{Id: 1, Revision: 73, Rules: []relayRule{
		{ID: "bad", Enabled: true, SidecarPort: 31001, TargetProtocol: "unknown", TargetAddress: "bad.example", TargetPort: 443},
		{ID: "good", Enabled: true, SidecarPort: 31002, TargetProtocol: "anytls", TargetAddress: "good.example", TargetPort: 443, TargetPassword: "secret"},
	}}
	var probed []int
	err := reportGroupHealthWithFailures(server.Client(), server.URL, "server", "secret", item, map[string]error{"bad": errors.New("unsupported target protocol \"unknown\"")}, func(port int) error {
		probed = append(probed, port)
		return nil
	})
	if err != nil {
		t.Fatalf("report health: %v", err)
	}
	if want := []int{31002}; !reflect.DeepEqual(probed, want) {
		t.Fatalf("probed = %v, want %v", probed, want)
	}
	if len(posted.Results) != 2 || posted.Results[0].Healthy || !strings.Contains(posted.Results[0].Error, "unsupported target protocol") || !posted.Results[1].Healthy {
		t.Fatalf("posted results = %#v", posted.Results)
	}
	if posted.Revision != item.Revision {
		t.Fatalf("posted revision = %d, want %d", posted.Revision, item.Revision)
	}
}

func TestProcessIdentityMismatchDoesNotKill(t *testing.T) {
	record := processIdentity{PID: "123", StartTime: "456", Marker: "/config/rules/g1-rule.json"}
	var killed bool
	matched, err := stopMatchingProcess(record, func(pid string) (processIdentity, error) {
		return processIdentity{PID: pid, StartTime: "999", Marker: "sleep\x001000"}, nil
	}, func(pid string) error {
		killed = true
		return nil
	})
	if err != nil {
		t.Fatalf("stop process: %v", err)
	}
	if matched || killed {
		t.Fatalf("identity mismatch matched=%v killed=%v", matched, killed)
	}
}

func TestProcessIdentityMatchKills(t *testing.T) {
	record := processIdentity{PID: "123", StartTime: "456", Marker: "/config/rules/g1-rule.json"}
	var killedPID string
	matched, err := stopMatchingProcess(record, func(pid string) (processIdentity, error) {
		return processIdentity{PID: pid, StartTime: "456", Marker: "xray\x00run\x00-c\x00/config/rules/g1-rule.json"}, nil
	}, func(pid string) error {
		killedPID = pid
		return nil
	})
	if err != nil || !matched || killedPID != "123" {
		t.Fatalf("matched=%v killed=%q err=%v", matched, killedPID, err)
	}
}

func TestReportGroupHealthUsesEachRulesActualPort(t *testing.T) {
	var probed []int
	probe := func(port int) error {
		probed = append(probed, port)
		return nil
	}
	var posted struct {
		Revision int64 `json:"revision"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
			t.Fatalf("decode health body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	item := group{Id: 1, Revision: 91, Rules: []relayRule{
		{ID: "explicit", Enabled: true, SidecarPort: 31042, TargetProtocol: "anytls", TargetAddress: "a.example", TargetPort: 443, TargetPassword: "secret"},
		{ID: "invalid", Enabled: false},
		{ID: "legacy", Enabled: true, TargetProtocol: "trojan", TargetAddress: "b.example", TargetPort: 443, TargetPassword: "secret"},
	}}
	if err := reportGroupHealthWithProbe(server.Client(), server.URL, "server", "secret", item, probe); err != nil {
		t.Fatalf("report health: %v", err)
	}
	if want := []int{31042, 31003}; !reflect.DeepEqual(probed, want) {
		t.Fatalf("probed ports = %v, want %v", probed, want)
	}
	if posted.Revision != item.Revision {
		t.Fatalf("posted revision = %d, want %d", posted.Revision, item.Revision)
	}
}

func TestApplyRuleUpdateValidatesBeforeStoppingOldRule(t *testing.T) {
	dir := t.TempDir()
	var events []string
	err := applyRuleUpdate(runtimeEntry{Key: "g1-rule", Script: "new script", Config: "new config"}, dir,
		func(runtimeEntry, string, string) error {
			events = append(events, "validate")
			return errors.New("invalid config")
		},
		func(string) { events = append(events, "stop") },
		func(string) error { events = append(events, "start"); return nil },
	)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if want := []string{"validate"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestWriteStateAtomicReplacesStateAndRemovesTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{"old":"digest"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeStateAtomic(path, map[string]string{"new": "digest"}); err != nil {
		t.Fatalf("write state: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]string
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if want := map[string]string{"new": "digest"}; !reflect.DeepEqual(state, want) {
		t.Fatalf("state = %v, want %v", state, want)
	}
	if matches, err := filepath.Glob(filepath.Join(dir, ".state-*.tmp")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary state files = %v, err=%v", matches, err)
	}
}

func TestOrphanRuleKeysFindsPIDFilesMissingFromState(t *testing.T) {
	rulesDir := t.TempDir()
	for _, name := range []string{"tracked.pid", "orphan.pid", "ignore.txt"} {
		if err := os.WriteFile(filepath.Join(rulesDir, name), []byte("123"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := orphanRuleKeys(rulesDir, map[string]string{"tracked": "digest"})
	if err != nil {
		t.Fatalf("find orphans: %v", err)
	}
	if want := []string{"orphan"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("orphan keys = %v, want %v", keys, want)
	}
}
