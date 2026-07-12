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
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const sidecarName = "ppanel-relay-sidecar"

type relayRule struct {
	ID                  string `json:"id"`
	Enabled             bool   `json:"enabled"`
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
	Id      int64       `json:"id"`
	Enabled bool        `json:"enabled"`
	Rules   []relayRule `json:"rules"`
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
	desired := make(map[string]runtimeEntry)
	for _, item := range groups {
		for index, rule := range item.Rules {
			entry, ok, err := buildRuleRuntime(item.Id, index, rule)
			if err != nil {
				return err
			}
			if ok {
				desired[entry.Key] = entry
			}
		}
	}
	statePath := filepath.Join(dir, "state.json")
	state := map[string]string{}
	if raw, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(raw, &state)
	}
	for key, digest := range state {
		if _, ok := desired[key]; !ok {
			stopRule(key, dockerRoot, dir)
			delete(state, key)
			continue
		}
		if desired[key].Digest != digest || !ruleProcessAlive(key, dir) {
			stopRule(key, dockerRoot, dir)
			delete(state, key)
		}
	}
	for key, entry := range desired {
		if _, running := state[key]; running {
			continue
		}
		if err := os.WriteFile(filepath.Join(rulesDir, key+".json"), []byte(entry.Config), 0600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(rulesDir, key+".sh"), []byte(entry.Script), 0700); err != nil {
			return err
		}
		if err := startRule(key, dir); err != nil {
			return err
		}
		state[key] = entry.Digest
	}
	encoded, _ := json.Marshal(state)
	if err := os.WriteFile(statePath, encoded, 0600); err != nil {
		return err
	}
	for _, item := range groups {
		if err := reportGroupHealth(client, baseURL, serverID, secret, item); err != nil {
			return err
		}
	}
	return nil
}

type runtimeEntry struct{ Key, Digest, Script, Config string }

func buildRuleRuntime(groupID int64, index int, rule relayRule) (runtimeEntry, bool, error) {
	protocol := strings.ToLower(strings.TrimSpace(rule.TargetProtocol))
	if !rule.Enabled || rule.TargetAddress == "" || rule.TargetPort <= 0 {
		return runtimeEntry{}, false, nil
	}
	if protocol == "anytls" && rule.TargetPassword != "" {
		key := runtimeKey(groupID, index, rule.ID)
		script := fmt.Sprintf("#!/bin/sh\necho $$ > /config/rules/%s.pid\ntrap 'rm -f /config/rules/%s.pid' EXIT\nexec /usr/local/bin/anytls-client -l 127.0.0.1:%d -s %s:%d -p %s -sni %s\n", key, key, basePort(groupID)+index, shellQuote(rule.TargetAddress), rule.TargetPort, shellQuote(rule.TargetPassword), shellQuote(rule.TargetSNI))
		return runtimeEntry{Key: key, Digest: digestOf(script), Script: script}, true, nil
	}
	if protocol != "vless" && protocol != "trojan" && protocol != "shadowsocks" {
		return runtimeEntry{}, false, nil
	}
	config, err := buildXrayConfig([]xrayRule{{Port: basePort(groupID) + index, Rule: rule}})
	if err != nil {
		return runtimeEntry{}, false, err
	}
	key := runtimeKey(groupID, index, rule.ID)
	script := fmt.Sprintf("#!/bin/sh\necho $$ > /config/rules/%s.pid\ntrap 'rm -f /config/rules/%s.pid' EXIT\nexec /usr/local/bin/xray run -c /config/rules/%s.json\n", key, key, key)
	return runtimeEntry{Key: key, Digest: digestOf(config), Script: script, Config: config}, true, nil
}

func runtimeKey(groupID int64, index int, ruleID string) string {
	return fmt.Sprintf("g%d-r%d-%s", groupID, index, strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, ruleID))
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
	return docker("run", "-d", "--name", sidecarName, "--network", "host", "--restart", "unless-stopped", "--label", "ppanel.relay.mode=per-rule", "-v", dockerRoot+"/relay-sidecar:/config", "-v", dockerRoot+"/anytls-client:/usr/local/bin/anytls-client:ro", "-v", dockerRoot+"/relay-sidecar/xray:/usr/local/bin/xray:ro", "alpine:3.20", "/bin/sh", "-c", "while :; do sleep 3600; done")
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
	pid := strings.TrimSpace(string(raw))
	return exec.Command("docker", "exec", sidecarName, "kill", "-0", pid).Run() == nil
}
func stopRule(key, dockerRoot, dir string) {
	raw, _ := os.ReadFile(filepath.Join(dir, "rules", key+".pid"))
	pid := strings.TrimSpace(string(raw))
	if pid != "" {
		_ = docker("exec", sidecarName, "kill", pid)
	}
	_ = os.Remove(filepath.Join(dir, "rules", key+".pid"))
	_ = os.Remove(filepath.Join(dir, "rules", key+".sh"))
	_ = os.Remove(filepath.Join(dir, "rules", key+".json"))
}
func startRule(key, dir string) error {
	return docker("exec", "-d", sidecarName, "/bin/sh", "/config/rules/"+key+".sh")
}

func reportGroupHealth(client *http.Client, baseURL, serverID, secret string, item group) error {
	results := make([]map[string]any, 0, len(item.Rules))
	port := basePort(item.Id)
	for _, rule := range item.Rules {
		result := map[string]any{"rule_id": rule.ID, "healthy": false}
		protocol := strings.ToLower(strings.TrimSpace(rule.TargetProtocol))
		valid := rule.Enabled && rule.TargetAddress != "" && rule.TargetPort > 0 && ((protocol == "anytls" && rule.TargetPassword != "") || (protocol == "vless" && rule.TargetUUID != "") || (protocol == "trojan" && rule.TargetPassword != "") || (protocol == "shadowsocks" && rule.TargetPassword != "" && (rule.TargetMethod != "" || rule.TargetCipher != "")))
		if valid {
			if err := checkSOCKS(port); err == nil {
				result["healthy"] = true
			} else {
				result["error"] = err.Error()
			}
			port++
		}
		results = append(results, result)
		if !valid {
			continue
		}
	}
	body, err := json.Marshal(map[string]any{"group_id": item.Id, "results": results})
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

func buildRuntime(groups []group) (string, string, error) {
	var script strings.Builder
	script.WriteString("#!/bin/sh\nset -eu\npids=\"\"\ncleanup() { for pid in $pids; do kill \"$pid\" 2>/dev/null || true; done; }\ntrap cleanup TERM INT EXIT\n")
	var xrayRules []xrayRule
	for _, item := range groups {
		port := basePort(item.Id)
		for _, rule := range item.Rules {
			if !rule.Enabled || rule.TargetAddress == "" || rule.TargetPort <= 0 {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(rule.TargetProtocol)) {
			case "anytls":
				if rule.TargetPassword == "" {
					continue
				}
				script.WriteString(fmt.Sprintf("/usr/local/bin/anytls-client -l 127.0.0.1:%d -s %s:%d -p %s -sni %s >/tmp/anytls-%d.log 2>&1 &\npids=\"$pids $!\"\n", port, shellQuote(rule.TargetAddress), rule.TargetPort, shellQuote(rule.TargetPassword), shellQuote(rule.TargetSNI), port))
			case "vless":
				if rule.TargetUUID == "" {
					continue
				}
				xrayRules = append(xrayRules, xrayRule{Port: port, Rule: rule})
			case "trojan":
				if rule.TargetPassword == "" {
					continue
				}
				xrayRules = append(xrayRules, xrayRule{Port: port, Rule: rule})
			case "shadowsocks":
				if rule.TargetPassword == "" || (rule.TargetMethod == "" && rule.TargetCipher == "") {
					continue
				}
				xrayRules = append(xrayRules, xrayRule{Port: port, Rule: rule})
			}
			port++
		}
	}
	if len(xrayRules) > 0 {
		script.WriteString("/usr/local/bin/xray run -c /config/xray.json >/tmp/xray.log 2>&1 &\npids=\"$pids $!\"\n")
	}
	script.WriteString("while :; do sleep 30; done\n")
	config, err := buildXrayConfig(xrayRules)
	return script.String(), config, err
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
