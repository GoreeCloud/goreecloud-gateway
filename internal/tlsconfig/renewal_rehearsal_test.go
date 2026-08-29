package tlsconfig

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunIsolatedRenewalRehearsalRestoresPreviousPairAndRuntime(t *testing.T) {
	root := t.TempDir()
	oldCert, oldKey := writeTestCertificate(t, root, "live")
	candidateCert, candidateKey := writeTestCertificate(t, root, "candidate")
	candidateCertPEM, err := os.ReadFile(candidateCert)
	if err != nil {
		t.Fatal(err)
	}
	candidateKeyPEM, err := os.ReadFile(candidateKey)
	if err != nil {
		t.Fatal(err)
	}
	previousSerial := certificateSerialForTest(t, oldCert, oldKey)
	candidateSerial := certificateSerialForTest(t, candidateCert, candidateKey)
	now := time.Now().UTC()
	request := RenewalRequest{
		ProfileID:     "primary",
		CurrentSerial: previousSerial,
		DNSNames:      []string{"gateway.example.test"},
		RequestedAt:   now.Format(time.RFC3339Nano),
		Reason:        "isolated-renewal-rehearsal",
	}
	cfg := reloadConfig(oldCert, oldKey)
	reloader, err := NewReloader(cfg)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &testRenewalIssuer{certificatePEM: candidateCertPEM, privateKeyPEM: candidateKeyPEM}

	receipt, err := RunIsolatedRenewalRehearsal(
		context.Background(),
		issuer,
		request,
		cfg,
		reloader,
		root,
		filepath.Join(root, "staging"),
		filepath.Join(root, "backups"),
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != RenewalRehearsalReceiptSchemaV1 || receipt.PreviousSerial != previousSerial || receipt.CandidateSerial != candidateSerial {
		t.Fatalf("unexpected rehearsal receipt identity: %+v", receipt)
	}
	if !receipt.CandidateActivated || !receipt.PreviousPairRestored || !receipt.PreviousRuntimeRestored || receipt.ProductionCutoverAuthorized {
		t.Fatalf("unsafe or incomplete rehearsal receipt: %+v", receipt)
	}
	if restored := certificateSerialForTest(t, oldCert, oldKey); restored != previousSerial {
		t.Fatalf("live rehearsal pair serial = %q, want %q", restored, previousSerial)
	}
}

func TestRunIsolatedRenewalRehearsalRejectsLivePathOutsideScope(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	oldCert, oldKey := writeTestCertificate(t, outside, "live")
	candidateCert, candidateKey := writeTestCertificate(t, root, "candidate")
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
		ProfileID:     "primary",
		CurrentSerial: certificateSerialForTest(t, oldCert, oldKey),
		DNSNames:      []string{"gateway.example.test"},
		RequestedAt:   now.Format(time.RFC3339Nano),
		Reason:        "isolated-renewal-rehearsal",
	}
	cfg := reloadConfig(oldCert, oldKey)
	reloader, err := NewReloader(cfg)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &testRenewalIssuer{certificatePEM: candidateCertPEM, privateKeyPEM: candidateKeyPEM}

	if _, err := RunIsolatedRenewalRehearsal(
		context.Background(),
		issuer,
		request,
		cfg,
		reloader,
		root,
		filepath.Join(root, "staging"),
		filepath.Join(root, "backups"),
		now,
	); err == nil {
		t.Fatal("rehearsal unexpectedly accepted a live certificate path outside the isolated scope")
	}
	if issuer.calls != 0 {
		t.Fatalf("issuer called %d times after rehearsal scope rejection", issuer.calls)
	}
}
