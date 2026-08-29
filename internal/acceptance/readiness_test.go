package acceptance

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateMigrationReadinessRequiresEveryGate(t *testing.T) {
	evidence := completeMigrationEvidence()
	evidence.BackupRestoreProven = false
	evidence.WardveilSecurityValidated = false

	decision, err := EvaluateMigrationReadiness(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if decision.EligibleForMigrationRehearsal {
		t.Fatal("incomplete evidence unexpectedly eligible for migration rehearsal")
	}
	if decision.ProductionCutoverAuthorized {
		t.Fatal("readiness decision unexpectedly authorized production cutover")
	}
	if len(decision.MissingGates) != 2 || decision.MissingGates[0] != "backup_restore_proven" || decision.MissingGates[1] != "wardveil_security_validated" {
		t.Fatalf("missing gates = %v", decision.MissingGates)
	}
}

func TestEvaluateMigrationReadinessAcceptsCompleteBoundedEvidence(t *testing.T) {
	decision, err := EvaluateMigrationReadiness(completeMigrationEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if !decision.EligibleForMigrationRehearsal || len(decision.MissingGates) != 0 {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if decision.ProductionCutoverAuthorized {
		t.Fatal("complete source evidence unexpectedly authorized production cutover")
	}
}

func TestEvaluateMigrationReadinessRejectsCutoverClaim(t *testing.T) {
	evidence := completeMigrationEvidence()
	evidence.ProductionCutoverAuthorized = true
	if _, err := EvaluateMigrationReadiness(evidence); err == nil {
		t.Fatal("cutover-authorizing evidence unexpectedly accepted")
	}
}

func TestEvaluateMigrationReadinessRejectsInvalidIdentity(t *testing.T) {
	evidence := completeMigrationEvidence()
	evidence.RuntimeArtifactSHA256 = strings.Repeat("z", 64)
	if _, err := EvaluateMigrationReadiness(evidence); err == nil {
		t.Fatal("invalid runtime artifact digest unexpectedly accepted")
	}
}

func completeMigrationEvidence() MigrationEvidence {
	return MigrationEvidence{
		Schema:                       MigrationEvidenceSchemaV1,
		RecordedAt:                   time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		SourceRevision:               strings.Repeat("a", 40),
		RuntimeArtifactSHA256:        strings.Repeat("b", 64),
		ConfigurationValidated:       true,
		RouteParityValidated:         true,
		TLSRenewalRehearsalPassed:    true,
		StreamingUpgradeValidated:    true,
		SustainedLoadValidated:       true,
		BackpressureValidated:        true,
		BackupRestoreProven:          true,
		RollbackRehearsed:            true,
		ListenerOwnershipValidated:   true,
		ObservabilityValidated:       true,
		PrivacyShieldValidated:       true,
		WardveilSecurityValidated:    true,
		EverkeepValidated:            true,
		GlazeUIStableValidated:       true,
		ProductionCutoverAuthorized:  false,
	}
}
