package publication

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPlanFileBuildsValidatedPlan(t *testing.T) {
	path := writePolicyFile(t, `{
  "schema_version": 1,
  "routes": [
    {
      "hostname": "manager.goreecloud.com",
      "upstream": "http://goreecloud-manager:8000",
      "exposure": "private",
      "allowed_cidrs": ["100.64.0.0/10"]
    }
  ]
}`)

	plan, err := LoadPlanFile(path)
	if err != nil {
		t.Fatalf("load plan: %v", err)
	}
	if plan.DataPlaneAuthority != CaddyDataPlaneAuthority {
		t.Fatalf("data-plane authority = %q", plan.DataPlaneAuthority)
	}
	if len(plan.Routes) != 1 || plan.Routes[0].Hostname != "manager.goreecloud.com" {
		t.Fatalf("unexpected plan routes: %#v", plan.Routes)
	}
}

func TestLoadPlanFileRejectsUnknownFields(t *testing.T) {
	path := writePolicyFile(t, `{
  "schema_version": 1,
  "routes": [{
    "hostname": "api.goreecloud.com",
    "upstream": "http://goreecloud-api:8000",
    "exposure": "public",
    "unexpected": true
  }]
}`)

	_, err := LoadPlanFile(path)
	if !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("expected invalid policy error, got %v", err)
	}
}

func TestLoadPlanFileRejectsTrailingJSON(t *testing.T) {
	path := writePolicyFile(t, `{"schema_version":1,"routes":[{"hostname":"api.goreecloud.com","upstream":"http://goreecloud-api:8000","exposure":"public"}]} {}`)

	_, err := LoadPlanFile(path)
	if !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("expected invalid policy error, got %v", err)
	}
}

func TestLoadPlanFileRejectsOversizedPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publication.json")
	payload := strings.Repeat(" ", int(MaxPolicyBytes)+1)
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write oversized policy: %v", err)
	}

	_, err := LoadPlanFile(path)
	if !errors.Is(err, ErrPolicyTooLarge) {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}

func TestLoadPlanFileDoesNotEchoRejectedSecrets(t *testing.T) {
	const secret = "sentinel-control-plane-secret"
	path := writePolicyFile(t, `{"schema_version":1,"routes":[{"hostname":"api.goreecloud.com","upstream":"http://user:`+secret+`@goreecloud-api:8000","exposure":"public"}]}`)

	_, err := LoadPlanFile(path)
	if !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("expected invalid policy error, got %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("publication loader leaked rejected secret into error")
	}
}

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "publication.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write publication policy: %v", err)
	}

	return path
}
