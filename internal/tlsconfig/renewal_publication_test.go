package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

func certificateSerialFromFiles(t *testing.T, certificateFile, privateKeyFile string) string {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.SerialNumber.String()
}

func TestPrepareRenewalPublicationBindsStagedCandidateToLiveSerial(t *testing.T) {
	dir := t.TempDir()
	liveCert, liveKey := writeTestCertificate(t, dir, "live")
	candidateCert, candidateKey := writeTestCertificate(t, dir, "candidate")
	candidateCertPEM, err := os.ReadFile(candidateCert)
	if err != nil {
		t.Fatal(err)
	}
	candidateKeyPEM, err := os.ReadFile(candidateKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	currentSerial := certificateSerialFromFiles(t, liveCert, liveKey)
	request := RenewalRequest{ProfileID: "primary", CurrentSerial: currentSerial, DNSNames: []string{"gateway.example.test"}, RequestedAt: now.Format(time.RFC3339Nano), Reason: "certificate-renewal-window-reached"}
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
	if plan.Schema != RenewalPublicationPlanSchemaV1 || plan.CurrentSerial != currentSerial || plan.CandidateSerial != candidate.NewSerial {
		t.Fatalf("unexpected publication plan: %+v", plan)
	}
	if !plan.BackupRequired || !plan.RuntimeReloadRequired || plan.ProductionCutoverAuthorized {
		t.Fatal("publication plan did not preserve backup/reload/cutover safety invariants")
	}
}

func TestPrepareRenewalPublicationRejectsStaleLiveCertificate(t *testing.T) {
	dir := t.TempDir()
	liveCert, liveKey := writeTestCertificate(t, dir, "live-original")
	candidateCert, candidateKey := writeTestCertificate(t, dir, "candidate-stale")
	candidateCertPEM, err := os.ReadFile(candidateCert)
	if err != nil {
		t.Fatal(err)
	}
	candidateKeyPEM, err := os.ReadFile(candidateKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := RenewalRequest{ProfileID: "primary", CurrentSerial: certificateSerialFromFiles(t, liveCert, liveKey), DNSNames: []string{"gateway.example.test"}, RequestedAt: now.Format(time.RFC3339Nano), Reason: "certificate-renewal-window-reached"}
	candidate, _, err := ValidateRenewalCandidate(request, candidateCertPEM, candidateKeyPEM, now)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageRenewalCandidate(filepath.Join(dir, "staged"), candidate, candidateCertPEM, candidateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	newLiveCert, newLiveKey := writeTestCertificate(t, dir, "live-newer")
	profile := config.CertificateProfile{ID: "primary", CertificateFile: newLiveCert, PrivateKeyFile: newLiveKey, Enabled: true}
	if _, err := PrepareRenewalPublication(profile, staged, now); err == nil {
		t.Fatal("publication plan unexpectedly accepted a live certificate that changed after renewal validation")
	}
}

func TestPrepareRenewalPublicationRejectsProfileMismatch(t *testing.T) {
	dir := t.TempDir()
	liveCert, liveKey := writeTestCertificate(t, dir, "live-profile")
	candidateCert, candidateKey := writeTestCertificate(t, dir, "candidate-profile")
	candidateCertPEM, err := os.ReadFile(candidateCert)
	if err != nil {
		t.Fatal(err)
	}
	candidateKeyPEM, err := os.ReadFile(candidateKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := RenewalRequest{ProfileID: "primary", CurrentSerial: certificateSerialFromFiles(t, liveCert, liveKey), DNSNames: []string{"gateway.example.test"}, RequestedAt: now.Format(time.RFC3339Nano), Reason: "certificate-renewal-window-reached"}
	candidate, _, err := ValidateRenewalCandidate(request, candidateCertPEM, candidateKeyPEM, now)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageRenewalCandidate(filepath.Join(dir, "staged"), candidate, candidateCertPEM, candidateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	profile := config.CertificateProfile{ID: "other", CertificateFile: liveCert, PrivateKeyFile: liveKey, Enabled: true}
	if _, err := PrepareRenewalPublication(profile, staged, now); err == nil {
		t.Fatal("publication plan unexpectedly accepted a staged renewal for another profile")
	}
}
