package main

import "testing"

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
