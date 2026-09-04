package tlsconfig

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

func prepareTestRenewalPublication(t *testing.T, dir string) (RenewalPublicationPlan, string, string, string) {
	t.Helper()
	liveCert, liveKey := writeTestCertificate(t, dir, "transaction-live")
	candidateCert, candidateKey := writeTestCertificate(t, dir, "transaction-candidate")
	candidateCertPEM, err := os.ReadFile(candidateCert)
	if err != nil {
		t.Fatal(err)
	}
	candidateKeyPEM, err := os.ReadFile(candidateKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := RenewalRequest{
		ProfileID:    "primary",
		CurrentSerial: certificateSerialFromFiles(t, liveCert, liveKey),
		DNSNames:     []string{"gateway.example.test"},
		RequestedAt:  now.Format(time.RFC3339Nano),
		Reason:       "certificate-renewal-window-reached",
	}
	candidate, _, err := ValidateRenewalCandidate(request, candidateCertPEM, candidateKeyPEM, now)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageRenewalCandidate(filepath.Join(dir, "staged"), candidate, candidateCertPEM, candidateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	profile := config.CertificateProfile{ID: "primary", CertificateFile: liveCert, PrivateKeyFile: liveKey, Enabled: true}
	plan, err := PrepareRenewalPublication(profile, staged, now)
	if err != nil {
		t.Fatal(err)
	}
	return plan, liveCert, liveKey, candidate.NewSerial
}

func TestExecuteRenewalPublicationCreatesBackupAndSupportsExplicitRollback(t *testing.T) {
	dir := t.TempDir()
	plan, liveCert, liveKey, candidateSerial := prepareTestRenewalPublication(t, dir)
	previousSerial := certificateSerialFromFiles(t, liveCert, liveKey)
	now := time.Now().UTC()

	receipt, err := ExecuteRenewalPublication(plan, filepath.Join(dir, "backups"), now)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != RenewalPublicationReceiptSchemaV1 || receipt.PreviousSerial != previousSerial || receipt.CandidateSerial != candidateSerial {
		t.Fatalf("unexpected publication receipt: %+v", receipt)
	}
	if receipt.ProductionCutoverAuthorized || !receipt.RuntimeReloadRequired {
		t.Fatal("publication receipt violated reload/cutover safety boundary")
	}
	if certificateSerialFromFiles(t, liveCert, liveKey) != candidateSerial {
		t.Fatal("publication did not place the candidate certificate on disk")
	}
	backup, backupCert, backupKey, err := readRenewalBackup(receipt.BackupDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if backup.PreviousSerial != previousSerial || backup.CandidateSerial != candidateSerial {
		t.Fatalf("unexpected backup manifest: %+v", backup)
	}
	_, backupLeaf, err := parseRenewalPair(backupCert, backupKey)
	if err != nil {
		t.Fatal(err)
	}
	if backupLeaf.SerialNumber.String() != previousSerial {
		t.Fatal("backup did not capture the pre-publication certificate")
	}

	if err := RestoreRenewalPublicationBackup(receipt, candidateSerial); err != nil {
		t.Fatal(err)
	}
	if certificateSerialFromFiles(t, liveCert, liveKey) != previousSerial {
		t.Fatal("explicit rollback did not restore the previous live certificate")
	}
}

func TestExecuteRenewalPublicationRejectsLiveStateChangedAfterPlan(t *testing.T) {
	dir := t.TempDir()
	plan, _, _, _ := prepareTestRenewalPublication(t, dir)
	newCert, newKey := writeTestCertificate(t, dir, "transaction-new-live")
	newCertData, err := os.ReadFile(newCert)
	if err != nil {
		t.Fatal(err)
	}
	newKeyData, err := os.ReadFile(newKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plan.LiveCertificateFile, newCertData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plan.LivePrivateKeyFile, newKeyData, 0o600); err != nil {
		t.Fatal(err)
	}
	changedSerial := certificateSerialFromFiles(t, plan.LiveCertificateFile, plan.LivePrivateKeyFile)

	if _, err := ExecuteRenewalPublication(plan, filepath.Join(dir, "backups"), time.Now().UTC()); err == nil {
		t.Fatal("stale publication plan unexpectedly replaced a newer live certificate")
	}
	if certificateSerialFromFiles(t, plan.LiveCertificateFile, plan.LivePrivateKeyFile) != changedSerial {
		t.Fatal("failed stale publication modified the newer live certificate")
	}
}

func TestRestoreRenewalPublicationBackupRejectsChangedCurrentCertificate(t *testing.T) {
	dir := t.TempDir()
	plan, _, _, candidateSerial := prepareTestRenewalPublication(t, dir)
	receipt, err := ExecuteRenewalPublication(plan, filepath.Join(dir, "backups"), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	newCert, newKey := writeTestCertificate(t, dir, "transaction-after-publication")
	newCertData, err := os.ReadFile(newCert)
	if err != nil {
		t.Fatal(err)
	}
	newKeyData, err := os.ReadFile(newKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receipt.LiveCertificateFile, newCertData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receipt.LivePrivateKeyFile, newKeyData, 0o600); err != nil {
		t.Fatal(err)
	}
	changedSerial := certificateSerialFromFiles(t, receipt.LiveCertificateFile, receipt.LivePrivateKeyFile)
	if changedSerial == candidateSerial {
		t.Fatal("test fixture did not change current serial")
	}
	if err := RestoreRenewalPublicationBackup(receipt, candidateSerial); err == nil {
		t.Fatal("rollback unexpectedly overwrote a certificate changed after publication")
	}
	if certificateSerialFromFiles(t, receipt.LiveCertificateFile, receipt.LivePrivateKeyFile) != changedSerial {
		t.Fatal("failed rollback modified newer live certificate")
	}
}
