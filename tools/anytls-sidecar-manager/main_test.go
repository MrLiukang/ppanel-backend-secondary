package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAuthenticatedRequestsUseServerScopedToken(t *testing.T) {
	secret := "root-secret"
	expected := func(serverID string) string {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = io.WriteString(mac, serverID)
		return fmt.Sprintf("%x", mac.Sum(nil))
	}
	tokenA, err := deriveServerToken(secret, "101")
	if err != nil {
		t.Fatalf("derive server A token: %v", err)
	}
	tokenB, err := deriveServerToken(secret, "202")
	if err != nil {
		t.Fatalf("derive server B token: %v", err)
	}
	if tokenA != expected("101") || tokenB != expected("202") || tokenA == tokenB {
		t.Fatalf("tokens A=%q B=%q, want distinct expected HMACs", tokenA, tokenB)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		request, requestErr := newAuthenticatedRequest(method, "https://panel.example/v2/server/101/test", "101", secret, nil)
		if requestErr != nil {
			t.Fatalf("%s request: %v", method, requestErr)
		}
		got := request.URL.Query().Get("secret_key")
		if got != tokenA || got == secret {
			t.Fatalf("%s secret_key = %q, want derived token %q", method, got, tokenA)
		}
	}
}

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

func TestBuildRuleRuntimeRejectsUnsupportedTargetFieldsFromJSON(t *testing.T) {
	tests := []struct {
		field string
		value string
	}{
		{field: "target_flow", value: "xtls-rprx-vision"},
		{field: "target_fingerprint", value: "chrome"},
		{field: "target_alpn", value: "h2"},
		{field: "target_xhttp_extra", value: `{"downloadSettings":{}}`},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			raw := fmt.Sprintf(`{"id":"rule","enabled":true,"target_protocol":"vless","target_address":"example.com","target_port":443,"target_uuid":"11111111-1111-1111-1111-111111111111",%q:%q}`, tt.field, tt.value)
			var rule relayRule
			if err := json.Unmarshal([]byte(raw), &rule); err != nil {
				t.Fatalf("decode rule: %v", err)
			}
			_, ok, err := buildRuleRuntime(1, 0, rule)
			if ok || err == nil || !strings.Contains(err.Error(), tt.field) || !strings.Contains(err.Error(), "unsupported") {
				t.Fatalf("build result: ok=%v err=%v, want explicit unsupported %s error", ok, err, tt.field)
			}
		})
	}
}

func TestApplyRuntimeEntriesContinuesAfterRuleFailure(t *testing.T) {
	entries := []runtimeEntry{{Key: "bad", Digest: "bad-digest"}, {Key: "good", Digest: "good-digest"}}
	state := map[string]runtimeState{"bad": {Digest: "old-digest", Port: 31001}}
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
	if state["bad"].Digest != "old-digest" || state["bad"].Port != 31001 || state["good"].Digest != "good-digest" {
		t.Fatalf("state = %#v", state)
	}
}

func TestDesiredRuleKeysKeepEnabledRulesWithBuildFailures(t *testing.T) {
	groups := []group{
		{Id: 1, Enabled: true, Rules: []relayRule{{ID: "invalid", Enabled: true}, {ID: "disabled", Enabled: false}}},
		{Id: 2, Enabled: false, Rules: []relayRule{{ID: "group-disabled", Enabled: true}}},
	}
	if want := map[string]struct{}{"g1-invalid": {}}; !reflect.DeepEqual(desiredRuleKeys(groups), want) {
		t.Fatalf("desired keys = %#v, want %#v", desiredRuleKeys(groups), want)
	}
}

func TestStopUndesiredKeepsStateWhenStopFails(t *testing.T) {
	state := map[string]runtimeState{"g1-deleted": {Digest: "old", Port: 31001}}
	err := stopUndesired(state, map[string]struct{}{}, func(key string, port int) error {
		if key != "g1-deleted" || port != 31001 {
			t.Fatalf("stop called with key=%q port=%d", key, port)
		}
		return errors.New("port still listening")
	})
	if err == nil || !strings.Contains(err.Error(), "port still listening") {
		t.Fatalf("stop undesired error = %v", err)
	}
	if _, exists := state["g1-deleted"]; !exists {
		t.Fatal("state removed after failed stop")
	}
}

func TestReadStatePreservesRuntimePort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"g1-existing":{"digest":"abc","port":31042}}`), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := readState(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if state["g1-existing"].Digest != "abc" || state["g1-existing"].Port != 31042 {
		t.Fatalf("state = %#v", state)
	}
}

func TestLegacyRuleKeepsPortFromStateAfterSorting(t *testing.T) {
	entries, failures := buildRuntimeEntriesWithPorts([]group{{Id: 1, Rules: []relayRule{
		{ID: "new-first", Enabled: true, TargetProtocol: "anytls", TargetAddress: "new.example", TargetPort: 443, TargetPassword: "secret"},
		{ID: "existing", Enabled: true, TargetProtocol: "anytls", TargetAddress: "old.example", TargetPort: 443, TargetPassword: "secret"},
	}}}, map[string]int{"g1-existing": 31001})
	if len(failures) != 0 || len(entries) != 2 {
		t.Fatalf("entries=%#v failures=%#v", entries, failures)
	}
	if entries[1].Port != 31001 {
		t.Fatalf("existing legacy port = %d, want state port 31001", entries[1].Port)
	}
}

func TestReportGroupsHealthContinuesAfterPostFailure(t *testing.T) {
	var groupIDs []int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			GroupID int64 `json:"group_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode health body: %v", err)
		}
		groupIDs = append(groupIDs, body.GroupID)
		if body.GroupID == 1 {
			http.Error(w, "first failed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := reportGroupsHealth(server.Client(), server.URL, "1", "secret", []group{{Id: 1}, {Id: 2}}, nil, func(int) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "first failed") {
		t.Fatalf("report groups error = %v", err)
	}
	if want := []int64{1, 2}; !reflect.DeepEqual(groupIDs, want) {
		t.Fatalf("posted groups = %v, want %v", groupIDs, want)
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
	revision := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if err := json.Unmarshal([]byte(`{"groups":[{"id":1,"enabled":true,"revision":"`+revision+`","rules":[]}]}`), &payload); err != nil {
		t.Fatalf("decode groups: %v", err)
	}
	if len(payload.Groups) != 1 || payload.Groups[0].Revision != revision {
		t.Fatalf("groups = %#v, want revision %s", payload.Groups, revision)
	}
}

func TestReportGroupHealthPostsBuildFailureFalseAndContinues(t *testing.T) {
	var posted struct {
		Revision string `json:"revision"`
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
	item := group{Id: 1, Revision: "73a8d8c22f07ef12ce8a75b69421a201cea54f1944ce6a88ac71b6c0bf8e11a2", Rules: []relayRule{
		{ID: "bad", Enabled: true, SidecarPort: 31001, TargetProtocol: "unknown", TargetAddress: "bad.example", TargetPort: 443},
		{ID: "good", Enabled: true, SidecarPort: 31002, TargetProtocol: "anytls", TargetAddress: "good.example", TargetPort: 443, TargetPassword: "secret"},
	}}
	var probed []int
	err := reportGroupHealthWithFailures(server.Client(), server.URL, "1", "secret", item, map[string]error{"bad": errors.New("unsupported target protocol \"unknown\"")}, func(port int) error {
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
		t.Fatalf("posted revision = %q, want %q", posted.Revision, item.Revision)
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

func TestStopTrackedRuleReturnsErrorAndKeepsFilesWhenProcessDoesNotStop(t *testing.T) {
	rulesDir := t.TempDir()
	key := "g1-rule"
	for name, content := range map[string]string{
		key + ".pid":  "123 456 /config/rules/g1-rule.json",
		key + ".sh":   "old script",
		key + ".json": "old config",
	} {
		if err := os.WriteFile(filepath.Join(rulesDir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	err := stopTrackedRule(key, rulesDir, 31001,
		func(string) (processIdentity, error) {
			return processIdentity{PID: "123", StartTime: "456", Marker: "/config/rules/g1-rule.json"}, nil
		},
		func(string) error { return nil },
		func(processIdentity, int) error { return errors.New("PID still alive") },
	)
	if err == nil || !strings.Contains(err.Error(), "PID still alive") {
		t.Fatalf("stop error = %v", err)
	}
	for _, suffix := range []string{".pid", ".sh", ".json"} {
		if _, err := os.Stat(filepath.Join(rulesDir, key+suffix)); err != nil {
			t.Fatalf("tracking file %s removed after failed stop: %v", suffix, err)
		}
	}
}

func TestStopTrackedRuleRemovesFilesAfterExitAndPortRelease(t *testing.T) {
	rulesDir := t.TempDir()
	key := "g1-rule"
	if err := os.WriteFile(filepath.Join(rulesDir, key+".pid"), []byte("123 456 /config/rules/g1-rule.json"), 0600); err != nil {
		t.Fatal(err)
	}
	verifiedPort := 0
	err := stopTrackedRule(key, rulesDir, 31001,
		func(string) (processIdentity, error) {
			return processIdentity{PID: "123", StartTime: "456", Marker: "/config/rules/g1-rule.json"}, nil
		},
		func(string) error { return nil },
		func(_ processIdentity, port int) error { verifiedPort = port; return nil },
	)
	if err != nil {
		t.Fatalf("stop tracked rule: %v", err)
	}
	if verifiedPort != 31001 {
		t.Fatalf("verified port = %d", verifiedPort)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, key+".pid")); !os.IsNotExist(err) {
		t.Fatalf("PID file remains after verified stop: %v", err)
	}
}

func TestReportGroupHealthUsesEachRulesActualPort(t *testing.T) {
	var probed []int
	probe := func(port int) error {
		probed = append(probed, port)
		return nil
	}
	var posted struct {
		Revision string `json:"revision"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
			t.Fatalf("decode health body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	item := group{Id: 1, Revision: "91b63fa748c1fc72f04f0b7a78f9da11e2de11ca773df841ac837a9d025f8bc2", Rules: []relayRule{
		{ID: "explicit", Enabled: true, SidecarPort: 31042, TargetProtocol: "anytls", TargetAddress: "a.example", TargetPort: 443, TargetPassword: "secret"},
		{ID: "invalid", Enabled: false},
		{ID: "legacy", Enabled: true, TargetProtocol: "trojan", TargetAddress: "b.example", TargetPort: 443, TargetPassword: "secret"},
	}}
	if err := reportGroupHealthWithProbe(server.Client(), server.URL, "1", "secret", item, probe); err != nil {
		t.Fatalf("report health: %v", err)
	}
	if want := []int{31042, 31003}; !reflect.DeepEqual(probed, want) {
		t.Fatalf("probed ports = %v, want %v", probed, want)
	}
	if posted.Revision != item.Revision {
		t.Fatalf("posted revision = %q, want %q", posted.Revision, item.Revision)
	}
}

func TestApplyRuleUpdateValidatesBeforeStoppingOldRule(t *testing.T) {
	dir := t.TempDir()
	var events []string
	err := applyRuleUpdate(runtimeEntry{Key: "g1-rule", Script: "new script", Config: "new config", Port: 31001}, 31001, dir,
		func(runtimeEntry, string, string) error {
			events = append(events, "validate")
			return errors.New("invalid config")
		},
		func(string, int) error { events = append(events, "stop"); return nil },
		func(string) error { events = append(events, "start"); return nil },
		func(runtimeEntry) error { events = append(events, "verify"); return nil },
	)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if want := []string{"validate"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestApplyRuleUpdateRestoresOldRuntimeWhenNewRuntimeFailsVerification(t *testing.T) {
	dir := t.TempDir()
	key := "g1-rule"
	finalScript := filepath.Join(dir, key+".sh")
	finalConfig := filepath.Join(dir, key+".json")
	if err := os.WriteFile(finalScript, []byte("old script"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(finalConfig, []byte("old config"), 0600); err != nil {
		t.Fatal(err)
	}
	var events []string
	err := applyRuleUpdate(runtimeEntry{Key: key, Script: "new script", Config: "new config", Port: 31002}, 31001, dir,
		func(runtimeEntry, string, string) error { events = append(events, "validate"); return nil },
		func(_ string, port int) error { events = append(events, fmt.Sprintf("stop:%d", port)); return nil },
		func(string) error { events = append(events, "start"); return nil },
		func(entry runtimeEntry) error {
			raw, readErr := os.ReadFile(finalScript)
			if readErr != nil {
				return readErr
			}
			events = append(events, "verify:"+string(raw))
			if string(raw) == "new script" {
				return errors.New("SOCKS port not listening")
			}
			if entry.Port != 31001 {
				return fmt.Errorf("restored port = %d", entry.Port)
			}
			return nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "SOCKS port not listening") {
		t.Fatalf("apply update error = %v", err)
	}
	if want := []string{"validate", "stop:31001", "start", "verify:new script", "stop:31002", "start", "verify:old script"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for path, want := range map[string]string{finalScript: "old script", finalConfig: "old config"} {
		raw, readErr := os.ReadFile(path)
		if readErr != nil || string(raw) != want {
			t.Fatalf("restored %s = %q, err=%v, want %q", path, raw, readErr, want)
		}
	}
}

type ruleUpdateFailureHarness struct {
	dir         string
	key         string
	oldState    map[string]runtimeState
	state       map[string]runtimeState
	pid         string
	socksHealth bool
}

func newRuleUpdateFailureHarness(t *testing.T) *ruleUpdateFailureHarness {
	t.Helper()
	h := &ruleUpdateFailureHarness{
		dir:         t.TempDir(),
		key:         "g1-rule",
		oldState:    map[string]runtimeState{"g1-rule": {Digest: "old-digest", Port: 31001}},
		state:       map[string]runtimeState{"g1-rule": {Digest: "old-digest", Port: 31001}},
		pid:         "old-pid",
		socksHealth: true,
	}
	for suffix, content := range map[string]string{
		".sh":   "old script",
		".json": "old config",
	} {
		if err := os.WriteFile(filepath.Join(h.dir, h.key+suffix), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *ruleUpdateFailureHarness) apply(fileOps ruleUpdateFileOps, startFailure bool) error {
	entry := runtimeEntry{Key: h.key, Digest: "new-digest", Script: "new script", Config: "new config", Port: 31002}
	failures := applyRuntimeEntries([]runtimeEntry{entry}, h.state,
		func(runtimeEntry) bool { return h.pid != "" && h.socksHealth },
		func(entry runtimeEntry) error {
			return applyRuleUpdateWithFileOps(entry, 31001, h.dir,
				func(runtimeEntry, string, string) error { return nil },
				func(_ string, port int) error {
					h.pid = ""
					h.socksHealth = false
					return nil
				},
				func(string) error {
					script, err := os.ReadFile(filepath.Join(h.dir, h.key+".sh"))
					if err != nil {
						return err
					}
					if string(script) == "new script" && startFailure {
						return errors.New("injected start failure")
					}
					if string(script) == "old script" {
						h.pid = "old-pid"
						h.socksHealth = true
					}
					return nil
				},
				func(entry runtimeEntry) error {
					if entry.Script == "old script" && (h.pid != "old-pid" || !h.socksHealth) {
						return errors.New("old PID/SOCKS unhealthy")
					}
					return nil
				},
				fileOps,
			)
		})
	return failures[h.key]
}

func (h *ruleUpdateFailureHarness) assertRolledBack(t *testing.T, err error, wantError string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), wantError) {
		t.Fatalf("apply error = %v, want %q", err, wantError)
	}
	for suffix, want := range map[string]string{".sh": "old script", ".json": "old config"} {
		raw, readErr := os.ReadFile(filepath.Join(h.dir, h.key+suffix))
		if readErr != nil || string(raw) != want {
			t.Fatalf("restored %s = %q, err=%v, want %q", suffix, raw, readErr, want)
		}
	}
	if h.pid != "old-pid" || !h.socksHealth {
		t.Fatalf("old runtime health: pid=%q socks=%v", h.pid, h.socksHealth)
	}
	if !reflect.DeepEqual(h.state, h.oldState) {
		t.Fatalf("state changed: got %#v want %#v", h.state, h.oldState)
	}
}

func TestApplyRuleUpdateRollsBackAfterScriptRenameFailure(t *testing.T) {
	h := newRuleUpdateFailureHarness(t)
	failed := false
	ops := defaultRuleUpdateFileOps()
	ops.rename = func(oldPath, newPath string) error {
		if !failed && strings.HasSuffix(oldPath, ".next.sh") {
			failed = true
			return errors.New("injected script rename failure")
		}
		return os.Rename(oldPath, newPath)
	}
	h.assertRolledBack(t, h.apply(ops, false), "injected script rename failure")
}

func TestApplyRuleUpdateRollsBackAfterConfigRenameFailure(t *testing.T) {
	h := newRuleUpdateFailureHarness(t)
	failed := false
	ops := defaultRuleUpdateFileOps()
	ops.rename = func(oldPath, newPath string) error {
		if !failed && strings.HasSuffix(oldPath, ".next.json") {
			failed = true
			return errors.New("injected config rename failure")
		}
		return os.Rename(oldPath, newPath)
	}
	h.assertRolledBack(t, h.apply(ops, false), "injected config rename failure")
}

func TestApplyRuleUpdateRollsBackAfterStartFailure(t *testing.T) {
	h := newRuleUpdateFailureHarness(t)
	h.assertRolledBack(t, h.apply(defaultRuleUpdateFileOps(), true), "injected start failure")
}

func TestWriteStateAtomicReplacesStateAndRemovesTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{"old":"digest"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeStateAtomic(path, map[string]runtimeState{"new": {Digest: "digest", Port: 31001}}); err != nil {
		t.Fatalf("write state: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]runtimeState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if want := map[string]runtimeState{"new": {Digest: "digest", Port: 31001}}; !reflect.DeepEqual(state, want) {
		t.Fatalf("state = %v, want %v", state, want)
	}
	if matches, err := filepath.Glob(filepath.Join(dir, ".state-*.tmp")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary state files = %v, err=%v", matches, err)
	}
}
