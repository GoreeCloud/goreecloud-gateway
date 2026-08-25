package proxy

import (
	"testing"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
	"github.com/GoreeCloud/goreecloud-gateway/internal/health"
)

func TestStatusSnapshotIsAggregateAndPrivacySafe(t *testing.T) {
	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	handler := New(&config.Config{
		Schema: "goreecloud-gateway-config/v1",
		Services: []config.Service{{ID: "svc", BackendIDs: []string{"healthy", "unhealthy", "unknown"}}},
		Routes: []config.Route{
			{ID: "enabled", ServiceID: "svc", Hostname: "private.example", Enabled: true},
			{ID: "disabled", ServiceID: "svc", Hostname: "disabled.example", Enabled: false},
		},
		Backends: []config.Backend{
			{ID: "healthy", URL: "http://10.0.0.1", Enabled: true},
			{ID: "unhealthy", URL: "http://10.0.0.2", Enabled: true},
			{ID: "unknown", URL: "http://10.0.0.3", Enabled: true},
			{ID: "disabled", URL: "http://10.0.0.4", Enabled: false},
		},
	})
	defer handler.Close()

	handler.healthMu.Lock()
	handler.healthState["healthy"] = cachedHealth{result: health.Result{BackendID: "healthy", Healthy: true}, checkedAt: now}
	handler.healthState["unhealthy"] = cachedHealth{result: health.Result{BackendID: "unhealthy", Healthy: false}, checkedAt: now}
	handler.healthMu.Unlock()

	got := handler.StatusSnapshot(now)
	if got.Schema != RuntimeStatusSchemaV1 || !got.GeneratedAt.Equal(now) {
		t.Fatalf("unexpected status identity: %+v", got)
	}
	if got.Services != 1 || got.Routes != 1 || got.Backends != 3 {
		t.Fatalf("unexpected aggregate counts: %+v", got)
	}
	if got.HealthyBackends != 1 || got.Unhealthy != 1 || got.Unknown != 1 {
		t.Fatalf("unexpected health counts: %+v", got)
	}
}
