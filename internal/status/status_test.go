package status

import (
	"testing"
	"time"
)

func TestDevelopmentSnapshotIsPrivacyMinimized(t *testing.T) {
	now := time.Date(2026, 9, 1, 16, 0, 0, 0, time.UTC)
	snapshot := DevelopmentSnapshot(now)

	if snapshot.SchemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", snapshot.SchemaVersion)
	}
	if snapshot.Producer.ServiceID != "goreecloud-gateway" {
		t.Fatalf("service id = %q", snapshot.Producer.ServiceID)
	}
	if snapshot.State != StateDevelopment || snapshot.Acceptance.ProductionApproved {
		t.Fatal("development snapshot must not claim production readiness")
	}
	if !snapshot.Acceptance.RuntimeAcceptanceRequired {
		t.Fatal("runtime acceptance boundary must remain explicit")
	}
	if snapshot.Privacy.ContainsCredentials || snapshot.Privacy.ContainsPersonalData || snapshot.Privacy.ContainsRawLogs || snapshot.Privacy.ContainsNetworkIdentifiers || snapshot.Privacy.ContainsQueryData || snapshot.Privacy.ContainsCertificateMaterial {
		t.Fatal("status snapshot must exclude sensitive content")
	}

	want := []string{"ingress", "https", "certificates", "publication"}
	if len(snapshot.Capabilities) != len(want) {
		t.Fatalf("capabilities = %d, want %d", len(snapshot.Capabilities), len(want))
	}
	for i, id := range want {
		if snapshot.Capabilities[i].ID != id || snapshot.Capabilities[i].State != CapabilityPending {
			t.Fatalf("capability %d = %#v", i, snapshot.Capabilities[i])
		}
	}
}
