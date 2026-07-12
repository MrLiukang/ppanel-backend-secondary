package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/perfect-panel/server/internal/types"
)

type SubscriptionRelayImportOptions struct {
	ListenPortStart int
	ListenPortStep  int
}

type SubscriptionRelaySkipEntry struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

const subscriptionRelayPreviewMaxBytes = 2 << 20

func FetchSubscriptionRelayPreview(ctx context.Context, subscriptionURL string, options SubscriptionRelayImportOptions) (*types.SubscriptionRelayPreviewResponse, error) {
	parsed, err := url.Parse(strings.TrimSpace(subscriptionURL))
	if err != nil {
		return nil, fmt.Errorf("invalid subscription url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported subscription url scheme %q", parsed.Scheme)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build subscription request: %w", err)
	}
	req.Header.Set("User-Agent", "clash-verge")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch subscription returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, subscriptionRelayPreviewMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read subscription body: %w", err)
	}
	if len(body) > subscriptionRelayPreviewMaxBytes {
		return nil, fmt.Errorf("subscription response exceeds %d bytes", subscriptionRelayPreviewMaxBytes)
	}

	rules, skipped := ParseSubscriptionRelayRules(string(body), options)
	return &types.SubscriptionRelayPreviewResponse{
		Rules:   rules,
		Skipped: subscriptionRelaySkippedResponse(skipped),
	}, nil
}

func subscriptionRelaySkippedResponse(values []SubscriptionRelaySkipEntry) []types.SubscriptionRelayPreviewSkipEntry {
	result := make([]types.SubscriptionRelayPreviewSkipEntry, 0, len(values))
	for _, item := range values {
		result = append(result, types.SubscriptionRelayPreviewSkipEntry{
			Name:   item.Name,
			Reason: item.Reason,
		})
	}
	return result
}

func ParseSubscriptionRelayRules(raw string, options SubscriptionRelayImportOptions) ([]types.NodeRelayRule, []SubscriptionRelaySkipEntry) {
	content := decodeSubscriptionContent(raw)
	if rules, skipped, ok := parseSubscriptionYAML(content, options); ok {
		return rules, skipped
	}
	lines := strings.FieldsFunc(content, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	start := options.ListenPortStart
	if start == 0 {
		start = 643
	}
	step := options.ListenPortStep
	if step == 0 {
		step = 100
	}

	rules := make([]types.NodeRelayRule, 0, len(lines))
	skipped := make([]SubscriptionRelaySkipEntry, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rule, name, reason := parseSubscriptionRelayLine(line, start+len(rules)*step, len(rules)+1)
		if reason != "" {
			skipped = append(skipped, SubscriptionRelaySkipEntry{Name: name, Reason: reason})
			continue
		}
		rules = append(rules, rule)
	}
	return rules, skipped
}

type subscriptionYAML struct {
	Proxies []subscriptionYAMLProxy `yaml:"proxies"`
}

type subscriptionYAMLProxy struct {
	Name             string    `yaml:"name"`
	Type             string    `yaml:"type"`
	Server           string    `yaml:"server"`
	Port             yaml.Node `yaml:"port"`
	Password         string    `yaml:"password"`
	SNI              string    `yaml:"sni"`
	SkipCertVerify   bool      `yaml:"skip-cert-verify"`
	TargetTransport  string    `yaml:"network"`
	TargetXHTTPMode  string    `yaml:"xhttp-mode"`
	TargetXHTTPExtra string    `yaml:"xhttp-extra"`
	Cipher           string    `yaml:"cipher"`
	Plugin           string    `yaml:"plugin"`
	PluginOpts       string    `yaml:"plugin-opts"`
}

func parseSubscriptionYAML(content string, options SubscriptionRelayImportOptions) ([]types.NodeRelayRule, []SubscriptionRelaySkipEntry, bool) {
	if !strings.Contains(content, "proxies:") {
		return nil, nil, false
	}
	var document subscriptionYAML
	if err := yaml.Unmarshal([]byte(content), &document); err != nil || len(document.Proxies) == 0 {
		return nil, nil, false
	}

	start, step := relayImportPorts(options)
	rules := make([]types.NodeRelayRule, 0, len(document.Proxies))
	skipped := make([]SubscriptionRelaySkipEntry, 0)
	for _, proxy := range document.Proxies {
		name := strings.TrimSpace(proxy.Name)
		protocol := strings.ToLower(strings.TrimSpace(proxy.Type))
		if protocol != "anytls" && protocol != "vless" && protocol != "trojan" && protocol != "shadowsocks" {
			skipped = append(skipped, SubscriptionRelaySkipEntry{Name: name, Reason: fmt.Sprintf("unsupported protocol %q", protocol)})
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(proxy.Port.Value))
		if err != nil || port < 1 || port > 65535 {
			skipped = append(skipped, SubscriptionRelaySkipEntry{Name: name, Reason: "invalid target port"})
			continue
		}
		address := strings.TrimSpace(proxy.Server)
		if address == "" || address == "0.0.0.0" {
			skipped = append(skipped, SubscriptionRelaySkipEntry{Name: name, Reason: "invalid target address"})
			continue
		}
		security := ""
		if protocol == "anytls" {
			security = "tls"
		}
		transport := strings.ToLower(strings.TrimSpace(proxy.TargetTransport))
		if transport == "" {
			transport = "tcp"
		}
		rule := types.NodeRelayRule{
			ID:                  relayImportID(name, start+len(rules)*step),
			Enabled:             true,
			Sort:                int64(len(rules) + 1),
			Remark:              name,
			ListenPort:          start + len(rules)*step,
			Network:             "tcp,udp",
			TargetAddress:       address,
			TargetPort:          port,
			TargetProtocol:      protocol,
			TargetSecurity:      security,
			TargetSNI:           strings.TrimSpace(proxy.SNI),
			TargetTransport:     transport,
			TargetPassword:      strings.TrimSpace(proxy.Password),
			TargetAllowInsecure: proxy.SkipCertVerify,
			TargetXHTTPMode:     strings.TrimSpace(proxy.TargetXHTTPMode),
			TargetXHTTPExtra:    strings.TrimSpace(proxy.TargetXHTTPExtra),
			TargetMethod:        strings.TrimSpace(proxy.Cipher),
			TargetCipher:        strings.TrimSpace(proxy.Cipher),
			TargetPlugin:        strings.TrimSpace(proxy.Plugin),
			TargetPluginOpts:    strings.TrimSpace(proxy.PluginOpts),
		}
		rules = append(rules, rule)
	}
	return rules, skipped, true
}

func relayImportPorts(options SubscriptionRelayImportOptions) (int, int) {
	start := options.ListenPortStart
	if start == 0 {
		start = 643
	}
	step := options.ListenPortStep
	if step == 0 {
		step = 100
	}
	return start, step
}

func decodeSubscriptionContent(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return string(decoded)
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
		return string(decoded)
	}
	return raw
}

func parseSubscriptionRelayLine(line string, listenPort int, sort int) (types.NodeRelayRule, string, string) {
	u, err := url.Parse(line)
	if err != nil {
		return types.NodeRelayRule{}, "", fmt.Sprintf("invalid proxy link: %v", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "ss" {
		scheme = "shadowsocks"
		decoded := strings.Trim(u.Host, "/")
		if !strings.Contains(decoded, "@") {
			if value, err := decodeBase64Value(decoded); err == nil {
				decodedURL, parseErr := url.Parse("ss://" + value)
				if parseErr == nil {
					decodedURL.Fragment = u.Fragment
					u = decodedURL
				}
			}
		}
	}
	if scheme != "anytls" && scheme != "vless" && scheme != "trojan" && scheme != "shadowsocks" {
		return types.NodeRelayRule{}, displayName(u), fmt.Sprintf("unsupported protocol %q", scheme)
	}
	host := strings.TrimSpace(u.Hostname())
	name := displayName(u)
	if host == "" || host == "0.0.0.0" {
		return types.NodeRelayRule{}, name, "invalid target address"
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return types.NodeRelayRule{}, name, "invalid target port"
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return types.NodeRelayRule{}, name, "invalid target address"
	}

	query := u.Query()
	credential := u.User.Username()
	password, _ := u.User.Password()
	rule := types.NodeRelayRule{
		ID:                  relayImportID(name, listenPort),
		Enabled:             true,
		Sort:                int64(sort),
		Remark:              name,
		ListenPort:          listenPort,
		Network:             "tcp,udp",
		TargetAddress:       host,
		TargetPort:          port,
		TargetProtocol:      scheme,
		TargetSecurity:      strings.ToLower(strings.TrimSpace(query.Get("security"))),
		TargetSNI:           strings.TrimSpace(query.Get("sni")),
		TargetTransport:     strings.ToLower(strings.TrimSpace(query.Get("type"))),
		TargetHost:          strings.TrimSpace(query.Get("host")),
		TargetPath:          strings.TrimSpace(query.Get("path")),
		TargetXHTTPMode:     strings.TrimSpace(query.Get("mode")),
		TargetXHTTPExtra:    strings.TrimSpace(query.Get("extra")),
		TargetAllowInsecure: parseSubscriptionBool(query.Get("allowInsecure")),
		TargetMethod:        strings.TrimSpace(query.Get("method")),
		TargetCipher:        strings.TrimSpace(query.Get("cipher")),
		TargetPlugin:        strings.TrimSpace(query.Get("plugin")),
		TargetPluginOpts:    strings.TrimSpace(query.Get("plugin-opts")),
	}
	if rule.TargetTransport == "" {
		rule.TargetTransport = "tcp"
	}
	if scheme == "vless" {
		rule.TargetUUID = credential
	} else if scheme == "anytls" {
		rule.TargetSecurity = "tls"
		rule.TargetTransport = "tcp"
		rule.TargetPassword = credential
	} else {
		if scheme == "shadowsocks" {
			rule.TargetMethod = credential
			rule.TargetCipher = credential
			rule.TargetPassword = password
		} else {
			rule.TargetPassword = credential
		}
	}
	return rule, name, ""
}

func decodeBase64Value(value string) (string, error) {
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return string(decoded), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	return string(decoded), err
}

func displayName(u *url.URL) string {
	name := strings.TrimSpace(u.Fragment)
	if name != "" {
		return name
	}
	host := strings.TrimSpace(u.Hostname())
	if host != "" {
		return host
	}
	return strings.TrimSpace(u.String())
}

func parseSubscriptionBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

var relayImportIDNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func relayImportID(name string, listenPort int) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	slug = relayImportIDNonAlnum.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "node"
	}
	return fmt.Sprintf("relay-import-%s-%d", slug, listenPort)
}
