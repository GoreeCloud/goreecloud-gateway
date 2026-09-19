package tlsconfig

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

type testRenewalIssuer struct {
	certificatePEM []byte
	privateKeyPEM  []byte
	err            error
	calls          int
}

func (i *testRenewalIssuer) IssueRenewal(_ context.Context, _ RenewalRequest) ([]byte, []byte, error) {
	i.calls++
	return i.certificatePEM, i.privateKeyPEM, i.err
}

func TestIssueValidateAndStageRenewalStagesValidatedMaterial(t *testing.T) {
	materialDir := t.TempDir()
	certPath, keyPath := writeTestCertificate(t, materialDir, "renewed")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := RenewalRequest{
		ProfileID:     "primary",
		CurrentSerial: "0",
		DNSNames:      []string{"gateway.example.test"},
		RequestedAt:   now.Format(time.RFC3339Nano),
		Reason:        "certificate-renewal-window-reached",
	}
	issuer := &testRenewalIssuer{certificatePEM: certPEM, privateKeyPEM: keyPEM}

	result, err := IssueValidateAndStageRenewal(context.Background(), issuer, request, t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 1 {
		t.Fatalf("issuer calls = %d, want 1", issuer.calls)
	}
	if result.Candidate.ProfileID != request.ProfileID || result.Candidate.PreviousSerial != request.CurrentSerial {
		t.Fatalf("unexpected candidate binding: %+v", result.Candidate)
	}
	if result.Stage.CertificateFile == "" || result.Stage.PrivateKeyFile == "" || result.Stage.ManifestFile == "" {
		t.Fatalf("incomplete staging result: %+v", result.Stage)
	}
	if result.ProductionCutoverAuthorized {
		t.Fatal("staged issuance unexpectedly authorized production cutover")
	}
}

func TestIssueValidateAndStageRenewalRejectsCanceledContextBeforeIssuer(t *testing.T) {
	now := time.Now().UTC()
	request := RenewalRequest{
		ProfileID:     "primary",
		CurrentSerial: "0",
		DNSNames:      []string{"gateway.example.test"},
		RequestedAt:   now.Format(time.RFC3339Nano),
		Reason:        "certificate-renewal-window-reached",
	}
	issuer := &testRenewalIssuer{err: errors.New("issuer should not be called")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := IssueValidateAndStageRenewal(ctx, issuer, request, t.TempDir(), now); err == nil {
		t.Fatal("canceled issuance context unexpectedly accepted")
	}
	if issuer.calls != 0 {
		t.Fatalf("issuer called %d times after context cancellation", issuer.calls)
	}
}
