package types

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestRelaySubscriptionPreviewTokenJSONContract(t *testing.T) {
	previewData, err := json.Marshal(SubscriptionRelayPreviewResponse{PreviewToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(previewData), `"preview_token":"token"`) {
		t.Fatalf("preview response JSON = %s", previewData)
	}
	applyData, err := json.Marshal(RelaySubscriptionGroupApplyRequest{PreviewToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(applyData), `"preview_token":"token"`) {
		t.Fatalf("apply request JSON = %s", applyData)
	}
}

func TestRelaySubscriptionAPIIncludesPreviewTokenContract(t *testing.T) {
	data, err := os.ReadFile("../../apis/admin/server.api")
	if err != nil {
		t.Fatal(err)
	}
	api := string(data)
	for _, required := range []string{
		"SubscriptionRelayPreviewResponse",
		"RelaySubscriptionGroupApplyRequest",
		"/relay/subscription/group/preview",
		"/relay/subscription/group/apply",
	} {
		if !strings.Contains(api, required) {
			t.Fatalf("server.api missing %q", required)
		}
	}
	if !regexp.MustCompile("PreviewToken\\s+string\\s+`json:\"preview_token\" validate:\"required\"`").MatchString(api) {
		t.Fatal("server.api apply request does not require preview_token")
	}
}
