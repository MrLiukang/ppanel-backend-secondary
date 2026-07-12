package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/perfect-panel/server/internal/types"
	"github.com/stretchr/testify/require"
)

func TestParseSubscriptionRelayRulesMapsVlessXhttpTLS(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte("vless://11111111-1111-1111-1111-111111111111@hk1.example.com:443?type=xhttp&security=tls&sni=update.microsoft.com&path=%2Fpath&mode=packet-up&extra=%7B%22scStreamUpServerName%22%3A%22cdn.example.com%22%7D&allowInsecure=1#HK%201"))

	rules, skipped := ParseSubscriptionRelayRules(raw, SubscriptionRelayImportOptions{
		ListenPortStart: 643,
		ListenPortStep:  100,
	})

	require.Empty(t, skipped)
	require.Len(t, rules, 1)
	require.Equal(t, "relay-import-hk-1-643", rules[0].ID)
	require.True(t, rules[0].Enabled)
	require.EqualValues(t, 1, rules[0].Sort)
	require.Equal(t, "HK 1", rules[0].Remark)
	require.Equal(t, 643, rules[0].ListenPort)
	require.Equal(t, "tcp,udp", rules[0].Network)
	require.Equal(t, "vless", rules[0].TargetProtocol)
	require.Equal(t, "11111111-1111-1111-1111-111111111111", rules[0].TargetUUID)
	require.Empty(t, rules[0].TargetPassword)
	require.Equal(t, "hk1.example.com", rules[0].TargetAddress)
	require.Equal(t, 443, rules[0].TargetPort)
	require.Equal(t, "xhttp", rules[0].TargetTransport)
	require.Equal(t, "tls", rules[0].TargetSecurity)
	require.Equal(t, "update.microsoft.com", rules[0].TargetSNI)
	require.Equal(t, "/path", rules[0].TargetPath)
	require.Equal(t, "packet-up", rules[0].TargetXHTTPMode)
	require.Equal(t, `{"scStreamUpServerName":"cdn.example.com"}`, rules[0].TargetXHTTPExtra)
	require.True(t, rules[0].TargetAllowInsecure)
}

func TestParseSubscriptionRelayRulesSkipsInvalidTrojanPlaceholder(t *testing.T) {
	raw := "trojan://password@0.0.0.0:443?type=ws&security=tls&sni=0.0.0.0#Notice"

	rules, skipped := ParseSubscriptionRelayRules(raw, SubscriptionRelayImportOptions{
		ListenPortStart: 643,
		ListenPortStep:  100,
	})

	require.Empty(t, rules)
	require.Len(t, skipped, 1)
	require.Equal(t, "Notice", skipped[0].Name)
	require.Contains(t, skipped[0].Reason, "invalid target address")
}

func TestParseSubscriptionRelayRulesMapsAnyTLSYAML(t *testing.T) {
	raw := `mode: rule
proxies:
  - name: Hong Kong 01
    type: anytls
    server: relay.example.com
    port: 601
    password: secret
    sni: down.example.com
    skip-cert-verify: true
`

	rules, skipped := ParseSubscriptionRelayRules(raw, SubscriptionRelayImportOptions{
		ListenPortStart: 643,
		ListenPortStep:  100,
	})

	require.Empty(t, skipped)
	require.Len(t, rules, 1)
	require.Equal(t, "anytls", rules[0].TargetProtocol)
	require.Equal(t, "tls", rules[0].TargetSecurity)
	require.Equal(t, "tcp", rules[0].TargetTransport)
	require.Equal(t, "relay.example.com", rules[0].TargetAddress)
	require.Equal(t, 601, rules[0].TargetPort)
	require.Equal(t, "secret", rules[0].TargetPassword)
	require.Equal(t, "down.example.com", rules[0].TargetSNI)
	require.True(t, rules[0].TargetAllowInsecure)
}

func TestParseSubscriptionRelayRulesMapsTrojanAndShadowsocks(t *testing.T) {
	raw := "trojan://trojan-pass@example.com:443?security=tls&sni=example.com#Trojan%20One\nss://YWVzLTI1Ni1nY206c2VjcmV0QGV4YW1wbGUuY29tOjg0NDM=#SS%20One"
	rules, skipped := ParseSubscriptionRelayRules(raw, SubscriptionRelayImportOptions{ListenPortStart: 643, ListenPortStep: 100})
	if len(skipped) != 0 || len(rules) != 2 {
		t.Fatalf("rules=%#v skipped=%#v", rules, skipped)
	}
	if rules[0].TargetProtocol != "trojan" || rules[0].TargetPassword != "trojan-pass" {
		t.Fatalf("trojan rule = %#v", rules[0])
	}
	if rules[1].TargetProtocol != "shadowsocks" || rules[1].TargetMethod != "aes-256-gcm" || rules[1].TargetPassword != "secret" {
		t.Fatalf("shadowsocks rule = %#v", rules[1])
	}
}

func TestFetchSubscriptionRelayPreviewReadsRemoteSubscription(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte("vless://11111111-1111-1111-1111-111111111111@hk1.example.com:443?type=xhttp&security=tls&sni=update.microsoft.com&path=%2Fpath&allowInsecure=1#HK%201"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "clash-verge", r.Header.Get("User-Agent"))
		_, _ = w.Write([]byte(raw))
	}))
	defer server.Close()

	resp, err := FetchSubscriptionRelayPreview(context.Background(), server.URL, SubscriptionRelayImportOptions{
		ListenPortStart: 643,
		ListenPortStep:  100,
	})

	require.NoError(t, err)
	require.Len(t, resp.Rules, 1)
	require.Empty(t, resp.Skipped)
	require.Equal(t, "hk1.example.com", resp.Rules[0].TargetAddress)
	require.True(t, resp.Rules[0].TargetAllowInsecure)
}

func TestSidecarRelayRulesMapsAnyTLSToLocalSOCKS(t *testing.T) {
	rules := []types.NodeRelayRule{
		{ID: "one", Enabled: true, ListenPort: 643, TargetProtocol: "anytls", TargetAddress: "sg.example", TargetPort: 12002, TargetPassword: "secret", TargetSNI: "www.bing.com"},
		{ID: "two", Enabled: true, ListenPort: 743, TargetProtocol: "vless", TargetAddress: "v.example", TargetPort: 443},
	}
	got := sidecarRelayRules(rules, 1)
	if got[0].TargetProtocol != "socks" || got[0].TargetAddress != "127.0.0.1" || got[0].TargetPort != 31001 || got[0].TargetPassword != "" {
		t.Fatalf("mapped AnyTLS rule = %#v", got[0])
	}
	if got[1].TargetProtocol != "socks" || got[1].TargetAddress != "127.0.0.1" || got[1].TargetPort != 31002 {
		t.Fatalf("mapped VLESS rule = %#v", got[1])
	}
	groupTwo := sidecarRelayRules(rules, 2)
	if groupTwo[0].TargetPort != 31101 || groupTwo[1].TargetPort != 31102 {
		t.Fatalf("group port range = %#v", groupTwo)
	}
}

func TestUniqueRelayNodeNameUsesSubscriptionRemark(t *testing.T) {
	used := map[string]struct{}{"香港 01": {}, "香港 01 2": {}}
	if got := uniqueRelayNodeName("香港 01", used); got != "香港 01 3" {
		t.Fatalf("unique name = %q", got)
	}
	used = map[string]struct{}{}
	if got := uniqueRelayNodeName("香港 01", used); got != "香港 01" {
		t.Fatalf("first name = %q", got)
	}
}
