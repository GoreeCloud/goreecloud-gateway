package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const activationTestRevision = "89abcdef0123456789abcdef0123456789abcdef"

func TestStageRevisionDoesNotMutateActiveConfiguration(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(root, "active", "gateway.json")
	writeRecoveryTestConfig(t, active, "active.acceptance.test")
	before, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}

	candidatePath := filepath.Join(root, "candidate.json")
	writeRecoveryTestConfig(t, candidatePath, "candidate.acceptance.test")
	candidate, err := os.ReadFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	stageDir, staged, err := StageRevision(
		root,
		candidate,
		activationTestRevision,
		time.Date(2026, time.August, 29, 13, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if staged.Schema != StagedRevisionSchemaV1 || staged.ConfigSHA256 != recoveryTestSHA(candidate) {
		t.Fatalf("unexpected staged revision: %+v", staged)
	}
	if staged.ProductionCutoverAuthorized {
		t.Fatal("staged revision authorized production cutover")
	}
	if _, err := os.Stat(filepath.Join(stageDir, "manifest.json")); err != nil {
		t.Fatalf("staged manifest missing: %v", err)
	}
	after, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	if recoveryTestSHA(after) != recoveryTestSHA(before) {
		t.Fatal("staging mutated the active configuration")
	}
}

func TestActivateStagedRevisionCreatesRollbackBoundary(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(root, "active", "gateway.json")
	writeRecoveryTestConfig(t, active, "one.acceptance.test")
	original, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	originalDigest := recoveryTestSHA(original)

	candidatePath := filepath.Join(root, "candidate.json")
	writeRecoveryTestConfig(t, candidatePath, "two.acceptance.test")
	candidate, err := os.ReadFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	stageDir, staged, err := StageRevision(
		root,
		candidate,
		activationTestRevision,
		time.Date(2026, time.August, 29, 13, 1, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}

	receipt, err := ActivateStagedRevision(
		root,
		active,
		stageDir,
		originalDigest,
		recoveryTestRevision,
		time.Date(2026, time.August, 29, 13, 2, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != ActivationReceiptSchemaV1 || !receipt.ConfigValidated || !receipt.CompareAndSwapValidated {
		t.Fatalf("unexpected activation receipt: %+v", receipt)
	}
	if receipt.SourceRevision != activationTestRevision || receipt.PreviousSourceRevision != recoveryTestRevision {
		t.Fatalf("unexpected source revisions: %+v", receipt)
	}
	if receipt.PreviousConfigSHA256 != originalDigest || receipt.ActivatedConfigSHA256 != staged.ConfigSHA256 {
		t.Fatalf("unexpected activation digests: %+v", receipt)
	}
	if receipt.ProductionCutoverAuthorized {
		t.Fatal("activation receipt authorized production cutover")
	}
	if filepath.IsAbs(receipt.RecoverySnapshot) || receipt.RecoverySnapshot == "" {
		t.Fatalf("recovery snapshot receipt path must be root-relative: %q", receipt.RecoverySnapshot)
	}

	activated, err := Load(active)
	if err != nil {
		t.Fatal(err)
	}
	if activated.Routes[0].Hostname != "two.acceptance.test" {
		t.Fatalf("candidate was not activated: %+v", activated.Routes[0])
	}

	restoreReceipt, err := RestoreRecoverySnapshot(
		root,
		active,
		filepath.Join(root, filepath.FromSlash(receipt.RecoverySnapshot)),
		receipt.ActivatedConfigSHA256,
		time.Date(2026, time.August, 29, 13, 3, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if restoreReceipt.RestoredConfigSHA256 != originalDigest {
		t.Fatalf("rollback restored unexpected digest: %+v", restoreReceipt)
	}
	restored, err := Load(active)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Routes[0].Hostname != "one.acceptance.test" {
		t.Fatalf("rollback did not restore previous known-good configuration: %+v", restored.Routes[0])
	}
}

func TestActivateStagedRevisionRejectsChangedActiveConfiguration(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(root, "active", "gateway.json")
	writeRecoveryTestConfig(t, active, "one.acceptance.test")
	planned, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	plannedDigest := recoveryTestSHA(planned)

	candidatePath := filepath.Join(root, "candidate.json")
	writeRecoveryTestConfig(t, candidatePath, "two.acceptance.test")
	candidate, err := os.ReadFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	stageDir, _, err := StageRevision(root, candidate, activationTestRevision, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	writeRecoveryTestConfig(t, active, "newer.acceptance.test")
	if _, err := ActivateStagedRevision(root, active, stageDir, plannedDigest, recoveryTestRevision, time.Now().UTC()); err == nil {
		t.Fatal("activation accepted an active configuration that changed after planning")
	}
	current, err := Load(active)
	if err != nil {
		t.Fatal(err)
	}
	if current.Routes[0].Hostname != "newer.acceptance.test" {
		t.Fatalf("changed active configuration was overwritten: %+v", current.Routes[0])
	}
}

func TestActivateStagedRevisionRejectsTamperedCandidate(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(root, "active", "gateway.json")
	writeRecoveryTestConfig(t, active, "one.acceptance.test")
	activeBytes, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}

	candidatePath := filepath.Join(root, "candidate.json")
	writeRecoveryTestConfig(t, candidatePath, "two.acceptance.test")
	candidate, err := os.ReadFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	stageDir, _, err := StageRevision(root, candidate, activationTestRevision, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	writeRecoveryTestConfig(t, filepath.Join(stageDir, "gateway.json"), "tampered.acceptance.test")

	if _, err := ActivateStagedRevision(
		root,
		active,
		stageDir,
		recoveryTestSHA(activeBytes),
		recoveryTestRevision,
		time.Now().UTC(),
	); err == nil {
		t.Fatal("activation accepted a staged configuration whose digest no longer matched its manifest")
	}
	current, err := Load(active)
	if err != nil {
		t.Fatal(err)
	}
	if current.Routes[0].Hostname != "one.acceptance.test" {
		t.Fatalf("tampered activation mutated active configuration: %+v", current.Routes[0])
	}
}

func TestStageRevisionRejectsInvalidConfiguration(t *testing.T) {
	root := t.TempDir()
	invalid := []byte(`{"schema":"unsupported","services":[],"routes":[],"backends":[]}`)
	if _, _, err := StageRevision(root, invalid, activationTestRevision, time.Now().UTC()); err == nil {
		t.Fatal("staging accepted an invalid Gateway configuration")
	}
	if _, err := os.Stat(filepath.Join(root, "staged")); !os.IsNotExist(err) {
		t.Fatalf("invalid candidate created staging state: %v", err)
	}
}
