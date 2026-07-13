package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const sidecarName = "ppanel-relay-sidecar"
const alpineImage = "alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

type relayRule struct {
	ID                  string `json:"id"`
	Enabled             bool   `json:"enabled"`
	SidecarPort         int    `json:"sidecar_port"`
	TargetProtocol      string `json:"target_protocol"`
	TargetAddress       string `json:"target_address"`
	TargetPort          int    `json:"target_port"`
	TargetPassword      string `json:"target_password"`
	TargetSecurity      string `json:"target_security"`
	TargetSNI           string `json:"target_sni"`
	TargetAllowInsecure bool   `json:"target_allow_insecure"`
	TargetTransport     string `json:"target_transport"`
	TargetPath          string `json:"target_path"`
	TargetXHTTPMode     string `json:"target_xhttp_mode"`
	TargetUUID          string `json:"target_uuid"`
	TargetMethod        string `json:"target_method"`
	TargetCipher        string `json:"target_cipher"`
	TargetPlugin        string `json:"target_plugin"`
	TargetPluginOpts    string `json:"target_plugin_opts"`
}

type group struct {
	Id       int64       `json:"id"`
	Enabled  bool        `json:"enabled"`
	Revision int64       `json:"revision"`
	Rules    []relayRule `json:"rules"`
}

type response struct {
	Groups []group `json:"groups"`
}

func main() {
	baseURL := strings.TrimRight(os.Getenv("PPANEL_URL"), "/")
	secret, serverID := os.Getenv("PPANEL_SECRET_KEY"), os.Getenv("PPANEL_SERVER_ID")
	hostRoot, dockerRoot := os.Getenv("SIDECAR_HOST_ROOT"), os.Getenv("SIDECAR_DOCKER_ROOT")
	if dockerRoot == "" {
		dockerRoot = hostRoot
	}
	if baseURL == "" || secret == "" || serverID == "" || hostRoot == "" {
		panic("PPANEL_URL, PPANEL_SECRET_KEY, PPANEL_SERVER_ID and SIDECAR_HOST_ROOT are required")
	}
	interval := 30 * time.Second
	if value, err := strconv.Atoi(os.Getenv("SIDECAR_POLL_SECONDS")); err == nil && value > 0 {
		interval = time.Duration(value) * time.Second
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for {
		if err := reconcile(client, baseURL, serverID, secret, hostRoot, dockerRoot); err != nil {
			fmt.Printf("reconcile failed: %v\n", err)
		}
		time.Sleep(interval)
	}
}

func reconcile(client *http.Client, baseURL, serverID, secret, hostRoot, dockerRoot string) error {
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v2/server/%s/relay-subscription-groups?secret_key=%s", baseURL, serverID, secret), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("runtime endpoint returned %s", resp.Status)
	}
	var payload response
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}

	groups := make([]group, 0, len(payload.Groups))
	for _, item := range payload.Groups {
		if item.Enabled {
			groups = append(groups, item)
		}
	}
	dir := filepath.Join(hostRoot, "relay-sidecar")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0750); err != nil {
		return err
	}
	if err := ensureSidecar(dockerRoot, dir); err != nil {
		return err
	}
	entries, failures := buildRuntimeEntries(groups)
	desired := make(map[string]runtimeEntry, len(entries))
	for _, entry := range entries {
		desired[entry.Key] = entry
	}
	statePath := filepath.Join(dir, "state.json")
	state := map[string]string{}
	if raw, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(raw, &state)
	}
	orphans, err := orphanRuleKeys(rulesDir, state)
	if err != nil {
		return err
	}
	for _, key := range orphans {
		stopRule(key, dockerRoot, dir)
	}
	for key := range state {
		if _, ok := desired[key]; !ok {
			stopRule(key, dockerRoot, dir)
			delete(state, key)
		}
	}
	applyFailures := applyRuntimeEntries(entries, state,
		func(entry runtimeEntry) bool { return ruleProcessAlive(entry.Key, dir) },
		func(entry runtimeEntry) error {
			return applyRuleUpdate(entry, rulesDir, validateRuleConfig,
				func(key string) { stopRule(key, dockerRoot, dir) },
				func(key string) error { return startRule(key, dir) })
		})
	for _, entry := range entries {
		if err := applyFailures[entry.Key]; err != nil {
			if failures[entry.GroupID] == nil {
				failures[entry.GroupID] = make(map[string]error)
			}
			failures[entry.GroupID][entry.RuleID] = err
		}
	}
	if err := writeStateAtomic(statePath, state); err != nil {
		return err
	}
	for _, item := range groups {
		if err := reportGroupHealthWithFailures(client, baseURL, serverID, secret, item, failures[item.Id], checkSOCKS); err != nil {
			return err
		}
	}
	return nil
}

func applyRuleUpdate(entry runtimeEntry, rulesDir string, validate func(runtimeEntry, string, string) error, stop func(string), start func(string) error) error {
	scriptPath := filepath.Join(rulesDir, entry.Key+".next.sh")
	configPath := filepath.Join(rulesDir, entry.Key+".next.json")
	defer os.Remove(scriptPath)
	defer os.Remove(configPath)
	if err := os.WriteFile(scriptPath, []byte(entry.Script), 0700); err != nil {
		return err
	}
	if entry.Config != "" {
		if err := os.WriteFile(configPath, []byte(entry.Config), 0600); err != nil {
			return err
		}
	}
	if err := validate(entry, scriptPath, configPath); err != nil {
		return fmt.Errorf("validate rule %s: %w", entry.Key, err)
	}
	stop(entry.Key)
	finalScript := filepath.Join(rulesDir, entry.Key+".sh")
	finalConfig := filepath.Join(rulesDir, entry.Key+".json")
	_ = os.Remove(finalScript)
	if err := os.Rename(scriptPath, finalScript); err != nil {
		return err
	}
	if entry.Config != "" {
		_ = os.Remove(finalConfig)
		if err := os.Rename(configPath, finalConfig); err != nil {
			return err
		}
	} else {
		_ = os.Remove(finalConfig)
	}
	return start(entry.Key)
}

func validateRuleConfig(entry runtimeEntry, _, _ string) error {
	containerScript := "/config/rules/" + entry.Key + ".next.sh"
	if err := docker("exec", sidecarName, "/bin/sh", "-n", containerScript); err != nil {
		return err
	}
	if entry.Config == "" {
		return nil
	}
	return docker("exec", sidecarName, "/usr/local/bin/xray", "run", "-test", "-c", "/config/rules/"+entry.Key+".next.json")
}

func writeStateAtomic(path string, state map[string]string) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".state-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(encoded); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(tempPath, path)
}

func orphanRuleKeys(rulesDir string, state map[string]string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(rulesDir, "*.pid"))
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(matches))
	for _, path := range matches {
		key := strings.TrimSuffix(filepath.Base(path), ".pid")
		if _, tracked := state[key]; !tracked {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

type runtimeEntry struct {
	Key, Digest, Script, Config string
	Port                        int
	GroupID                     int64
	RuleID                      string
}

type processIdentity struct {
	PID       string
	StartTime string
	Marker    string
}

func buildRuleRuntime(groupID int64, index int, rule relayRule) (runtimeEntry, bool, error) {
	protocol := strings.ToLower(strings.TrimSpace(rule.TargetProtocol))
	if !rule.Enabled || rule.TargetAddress == "" || rule.TargetPort <= 0 {
		return runtimeEntry{}, false, nil
	}
	if strings.TrimSpace(rule.ID) == "" {
		return runtimeEntry{}, false, fmt.Errorf("relay rule ID is required")
	}
	if err := validateRuleCredentials(protocol, rule); err != nil {
		return runtimeEntry{}, false, fmt.Errorf("rule %s: %w", rule.ID, err)
	}
	if protocol == "anytls" {
		key, port := runtimeKey(groupID, rule.ID), sidecarPort(groupID, index, rule)
		script := ruleScript(key, "anytls-client", fmt.Sprintf("exec /usr/local/bin/anytls-client -l 127.0.0.1:%d -s %s:%d -p %s -sni %s", port, shellQuote(rule.TargetAddress), rule.TargetPort, shellQuote(rule.TargetPassword), shellQuote(rule.TargetSNI)))
		return runtimeEntry{Key: key, Digest: digestOf(script), Script: script, Port: port, GroupID: groupID, RuleID: rule.ID}, true, nil
	}
	port := sidecarPort(groupID, index, rule)
	config, err := buildXrayConfig([]xrayRule{{Port: port, Rule: rule}})
	if err != nil {
		return runtimeEntry{}, false, err
	}
	key := runtimeKey(groupID, rule.ID)
	marker := "/config/rules/" + key + ".json"
	script := ruleScript(key, marker, "exec /usr/local/bin/xray run -c "+marker)
	return runtimeEntry{Key: key, Digest: digestOf(config), Script: script, Config: config, Port: port, GroupID: groupID, RuleID: rule.ID}, true, nil
}

func buildRuntimeEntries(groups []group) ([]runtimeEntry, map[int64]map[string]error) {
	entries := make([]runtimeEntry, 0)
	failures := make(map[int64]map[string]error)
	usedPorts := make(map[int]string)
	usedKeys := make(map[string]struct{})
	for _, item := range groups {
		for index, rule := range item.Rules {
			entry, ok, err := buildRuleRuntime(item.Id, index, rule)
			if err == nil && ok {
				if _, exists := usedKeys[entry.Key]; exists {
					err = fmt.Errorf("duplicate runtime key %q", entry.Key)
				} else if entry.Port < 31001 || entry.Port > 61000 {
					err = fmt.Errorf("rule %s sidecar port %d is outside global range 31001-61000", entry.Key, entry.Port)
				} else if owner, exists := usedPorts[entry.Port]; exists {
					err = fmt.Errorf("rule %s sidecar port %d conflicts with %s", entry.Key, entry.Port, owner)
				}
			}
			if err != nil {
				if failures[item.Id] == nil {
					failures[item.Id] = make(map[string]error)
				}
				failures[item.Id][rule.ID] = err
				continue
			}
			if !ok {
				continue
			}
			usedKeys[entry.Key] = struct{}{}
			usedPorts[entry.Port] = entry.Key
			entries = append(entries, entry)
		}
	}
	return entries, failures
}

func validateRuleCredentials(protocol string, rule relayRule) error {
	switch protocol {
	case "anytls", "trojan":
		if rule.TargetPassword == "" {
			return fmt.Errorf("%s password is required", protocol)
		}
	case "vless":
		if rule.TargetUUID == "" {
			return fmt.Errorf("vless UUID is required")
		}
	case "shadowsocks":
		if rule.TargetPassword == "" {
			return fmt.Errorf("shadowsocks password is required")
		}
		if rule.TargetMethod == "" && rule.TargetCipher == "" {
			return fmt.Errorf("shadowsocks method is required")
		}
	default:
		return fmt.Errorf("unsupported target protocol %q", protocol)
	}
	return nil
}

func ruleScript(key, marker, command string) string {
	return fmt.Sprintf("#!/bin/sh\nstarttime=$(cut -d ' ' -f 22 /proc/$$/stat)\nprintf '%%s %%s %%s\\n' \"$$\" \"$starttime\" %s > /config/rules/%s.pid\ntrap 'rm -f /config/rules/%s.pid' EXIT\n%s\n", shellQuote(marker), key, key, command)
}

func runtimeKey(groupID int64, ruleID string) string {
	return fmt.Sprintf("g%d-%s", groupID, strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, ruleID))
}

func sidecarPort(groupID int64, index int, rule relayRule) int {
	if rule.SidecarPort > 0 {
		return rule.SidecarPort
	}
	return basePort(groupID) + index
}

func validateRuntimePorts(groupID int64, entries []runtimeEntry) error {
	const first, last = 31001, 61000
	used := make(map[int]string, len(entries))
	keys := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, exists := keys[entry.Key]; exists {
			return fmt.Errorf("duplicate runtime key %q", entry.Key)
		}
		keys[entry.Key] = struct{}{}
		if entry.Port < first || entry.Port > last {
			return fmt.Errorf("rule %s sidecar port %d is outside global range %d-%d", entry.Key, entry.Port, first, last)
		}
		if owner, exists := used[entry.Port]; exists {
			return fmt.Errorf("rule %s sidecar port %d conflicts with %s", entry.Key, entry.Port, owner)
		}
		used[entry.Port] = entry.Key
	}
	return nil
}

func applyRuntimeEntries(entries []runtimeEntry, state map[string]string, alive func(runtimeEntry) bool, apply func(runtimeEntry) error) map[string]error {
	failures := make(map[string]error)
	for _, entry := range entries {
		if state[entry.Key] == entry.Digest && alive(entry) {
			continue
		}
		if err := apply(entry); err != nil {
			failures[entry.Key] = err
			delete(state, entry.Key)
			continue
		}
		state[entry.Key] = entry.Digest
	}
	return failures
}
func digestOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func ensureSidecar(dockerRoot, dir string) error {
	if containerExists(sidecarName) && containerMode() == "per-rule" {
		return nil
	}
	if containerExists(sidecarName) {
		_ = docker("rm", "-f", sidecarName)
		time.Sleep(1 * time.Second)
	}
	if xray, err := os.ReadFile("/usr/local/bin/xray"); err == nil {
		if err := os.WriteFile(filepath.Join(dir, "xray"), xray, 0755); err != nil {
			return err
		}
	}
	return docker("run", "-d", "--name", sidecarName, "--network", "host", "--restart", "unless-stopped", "--label", "ppanel.relay.mode=per-rule", "-v", dockerRoot+"/relay-sidecar:/config", "-v", dockerRoot+"/anytls-client:/usr/local/bin/anytls-client:ro", "-v", dockerRoot+"/relay-sidecar/xray:/usr/local/bin/xray:ro", alpineImage, "/bin/sh", "-c", "while :; do sleep 3600; done")
}

func containerMode() string {
	out, err := exec.Command("docker", "inspect", "-f", "{{index .Config.Labels \"ppanel.relay.mode\"}}", sidecarName).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
func ruleProcessAlive(key, dir string) bool {
	raw, err := os.ReadFile(filepath.Join(dir, "rules", key+".pid"))
	if err != nil {
		return false
	}
	record, err := parseProcessIdentity(string(raw))
	if err != nil {
		return false
	}
	actual, err := inspectProcess(record.PID)
	return err == nil && processIdentityMatches(record, actual)
}
func stopRule(key, dockerRoot, dir string) {
	raw, _ := os.ReadFile(filepath.Join(dir, "rules", key+".pid"))
	if record, err := parseProcessIdentity(string(raw)); err == nil {
		_, _ = stopMatchingProcess(record, inspectProcess, func(pid string) error {
			return docker("exec", sidecarName, "kill", pid)
		})
	}
	_ = os.Remove(filepath.Join(dir, "rules", key+".pid"))
	_ = os.Remove(filepath.Join(dir, "rules", key+".sh"))
	_ = os.Remove(filepath.Join(dir, "rules", key+".json"))
}
func startRule(key, dir string) error {
	return docker("exec", "-d", sidecarName, "/bin/sh", "/config/rules/"+key+".sh")
}

func parseProcessIdentity(value string) (processIdentity, error) {
	fields := strings.Fields(value)
	if len(fields) != 3 {
		return processIdentity{}, fmt.Errorf("invalid process identity")
	}
	if _, err := strconv.Atoi(fields[0]); err != nil {
		return processIdentity{}, fmt.Errorf("invalid process PID: %w", err)
	}
	return processIdentity{PID: fields[0], StartTime: fields[1], Marker: fields[2]}, nil
}

func inspectProcess(pid string) (processIdentity, error) {
	stat, err := exec.Command("docker", "exec", sidecarName, "cat", "/proc/"+pid+"/stat").Output()
	if err != nil {
		return processIdentity{}, err
	}
	closing := strings.LastIndex(string(stat), ")")
	if closing < 0 {
		return processIdentity{}, fmt.Errorf("invalid /proc/%s/stat", pid)
	}
	fields := strings.Fields(string(stat)[closing+1:])
	if len(fields) < 20 {
		return processIdentity{}, fmt.Errorf("short /proc/%s/stat", pid)
	}
	cmdline, err := exec.Command("docker", "exec", sidecarName, "cat", "/proc/"+pid+"/cmdline").Output()
	if err != nil {
		return processIdentity{}, err
	}
	return processIdentity{PID: pid, StartTime: fields[19], Marker: string(cmdline)}, nil
}

func processIdentityMatches(record, actual processIdentity) bool {
	return record.PID == actual.PID && record.StartTime != "" && record.StartTime == actual.StartTime && record.Marker != "" && strings.Contains(actual.Marker, record.Marker)
}

func stopMatchingProcess(record processIdentity, inspect func(string) (processIdentity, error), kill func(string) error) (bool, error) {
	actual, err := inspect(record.PID)
	if err != nil {
		return false, nil
	}
	if !processIdentityMatches(record, actual) {
		return false, nil
	}
	if err := kill(record.PID); err != nil {
		return true, err
	}
	return true, nil
}

func reportGroupHealth(client *http.Client, baseURL, serverID, secret string, item group) error {
	return reportGroupHealthWithProbe(client, baseURL, serverID, secret, item, checkSOCKS)
}

func reportGroupHealthWithProbe(client *http.Client, baseURL, serverID, secret string, item group, probe func(int) error) error {
	return reportGroupHealthWithFailures(client, baseURL, serverID, secret, item, nil, probe)
}

func reportGroupHealthWithFailures(client *http.Client, baseURL, serverID, secret string, item group, failures map[string]error, probe func(int) error) error {
	results := make([]map[string]any, 0, len(item.Rules))
	for index, rule := range item.Rules {
		result := map[string]any{"rule_id": rule.ID, "healthy": false}
		if ruleErr := failures[rule.ID]; ruleErr != nil {
			result["error"] = ruleErr.Error()
			results = append(results, result)
			continue
		}
		protocol := strings.ToLower(strings.TrimSpace(rule.TargetProtocol))
		valid := rule.Enabled && rule.TargetAddress != "" && rule.TargetPort > 0 && ((protocol == "anytls" && rule.TargetPassword != "") || (protocol == "vless" && rule.TargetUUID != "") || (protocol == "trojan" && rule.TargetPassword != "") || (protocol == "shadowsocks" && rule.TargetPassword != "" && (rule.TargetMethod != "" || rule.TargetCipher != "")))
		if valid {
			if err := probe(sidecarPort(item.Id, index, rule)); err == nil {
				result["healthy"] = true
			} else {
				result["error"] = err.Error()
			}
		}
		results = append(results, result)
		if !valid {
			continue
		}
	}
	body, err := json.Marshal(map[string]any{"group_id": item.Id, "revision": item.Revision, "results": results})
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v2/server/%s/relay-subscription-groups/health?secret_key=%s", baseURL, serverID, secret), strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health report returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func checkSOCKS(port int) error {
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, proxy.Direct)
	if err != nil {
		return err
	}
	transport := &http.Transport{DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
		return dialer.Dial(network, address)
	}}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	defer transport.CloseIdleConnections()
	resp, err := client.Get("http://www.google.com/generate_204")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("probe returned %s", resp.Status)
	}
	return nil
}

type xrayRule struct {
	Port int
	Rule relayRule
}

func basePort(groupID int64) int { return 31001 + int((groupID-1)*100) }

func buildXrayConfig(rules []xrayRule) (string, error) {
	type user struct {
		ID         string `json:"id"`
		Encryption string `json:"encryption"`
	}
	type vnext struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
		Users   []user `json:"users"`
	}
	type outbound struct {
		Protocol       string         `json:"protocol"`
		Settings       any            `json:"settings"`
		StreamSettings map[string]any `json:"streamSettings"`
		Tag            string         `json:"tag"`
	}
	type inbound struct {
		Listen   string         `json:"listen"`
		Port     int            `json:"port"`
		Protocol string         `json:"protocol"`
		Settings map[string]any `json:"settings"`
		Tag      string         `json:"tag"`
	}
	type routeRule struct {
		Type        string   `json:"type"`
		InboundTag  []string `json:"inboundTag"`
		OutboundTag string   `json:"outboundTag"`
	}
	config := struct {
		Log       map[string]string `json:"log"`
		Inbounds  []inbound         `json:"inbounds"`
		Outbounds []outbound        `json:"outbounds"`
		Routing   struct {
			Rules []routeRule `json:"rules"`
		} `json:"routing"`
	}{Log: map[string]string{"loglevel": "warning"}}
	for _, item := range rules {
		inTag, outTag := fmt.Sprintf("socks-%d", item.Port), fmt.Sprintf("out-%d", item.Port)
		config.Inbounds = append(config.Inbounds, inbound{Listen: "127.0.0.1", Port: item.Port, Protocol: "socks", Tag: inTag, Settings: map[string]any{"udp": true}})
		protocol := strings.ToLower(strings.TrimSpace(item.Rule.TargetProtocol))
		var outboundProtocol string
		var settings map[string]any
		switch protocol {
		case "vless":
			outboundProtocol = "vless"
			settings = map[string]any{"vnext": []vnext{{Address: item.Rule.TargetAddress, Port: item.Rule.TargetPort, Users: []user{{ID: item.Rule.TargetUUID, Encryption: "none"}}}}}
		case "trojan":
			outboundProtocol = "trojan"
			settings = map[string]any{"servers": []map[string]any{{"address": item.Rule.TargetAddress, "port": item.Rule.TargetPort, "password": item.Rule.TargetPassword}}}
		case "shadowsocks":
			outboundProtocol = "shadowsocks"
			method := item.Rule.TargetMethod
			if method == "" {
				method = item.Rule.TargetCipher
			}
			settings = map[string]any{"servers": []map[string]any{{"address": item.Rule.TargetAddress, "port": item.Rule.TargetPort, "method": method, "password": item.Rule.TargetPassword}}}
		default:
			continue
		}
		stream := map[string]any{}
		if protocol != "shadowsocks" {
			security := item.Rule.TargetSecurity
			if protocol == "trojan" && security == "" {
				security = "tls"
			}
			stream = map[string]any{"network": item.Rule.TargetTransport, "security": security, "tlsSettings": map[string]any{"serverName": item.Rule.TargetSNI}}
			if strings.EqualFold(item.Rule.TargetTransport, "xhttp") || strings.EqualFold(item.Rule.TargetTransport, "splithttp") {
				stream["xhttpSettings"] = map[string]any{"path": item.Rule.TargetPath, "mode": item.Rule.TargetXHTTPMode}
			}
		}
		config.Outbounds = append(config.Outbounds, outbound{Protocol: outboundProtocol, Settings: settings, StreamSettings: stream, Tag: outTag})
		config.Routing.Rules = append(config.Routing.Rules, routeRule{Type: "field", InboundTag: []string{inTag}, OutboundTag: outTag})
	}
	if len(config.Inbounds) == 0 {
		return "{}", nil
	}
	data, err := json.Marshal(config)
	return string(data), err
}

func shellQuote(value string) string   { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
func containerExists(name string) bool { return exec.Command("docker", "inspect", name).Run() == nil }
func docker(args ...string) error {
	command := exec.CommandContext(context.Background(), "docker", args...)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	return command.Run()
}
