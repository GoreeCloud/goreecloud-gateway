package tlsconfig

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyStagedRenewalReopensExactPublishedMaterial(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertificate(t, dir, "renewal-verify")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := RenewalRequest{ProfileID: "primary", CurrentSerial: "0", DNSNames: []string{"gateway.example.test"}, RequestedAt: now.Format(time.RFC3339Nano), Reason: "certificate-renewal-window-reached"}
	candidate, _, err := ValidateRenewalCandidate(request, certPEM, keyPEM, now)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageRenewalCandidate(filepath.Join(dir, "staged"), candidate, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	manifest, pair, err := VerifyStagedRenewal(staged.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ProfileID != candidate.ProfileID || manifest.NewSerial != candidate.NewSerial {
		t.Fatalf("unexpected verified manifest: %+v", manifest)
	}
	if pair.Leaf == nil || pair.Leaf.SerialNumber.String() != candidate.NewSerial {
		t.Fatal("verified staged renewal did not return the expected parsed leaf")
	}
}

func TestVerifyStagedRenewalRejectsTamperedMaterial(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertificate(t, dir, "renewal-verify-tamper")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := RenewalRequest{ProfileID: "primary", CurrentSerial: "0", DNSNames: []string{"gateway.example.test"}, RequestedAt: now.Format(time.RFC3339Nano), Reason: "certificate-renewal-window-reached"}
	candidate, _, err := ValidateRenewalCandidate(request, certPEM, keyPEM, now)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageRenewalCandidate(filepath.Join(dir, "staged"), candidate, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged.CertificateFile, append(certPEM, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyStagedRenewal(staged.Directory); err == nil {
		t.Fatal("tampered staged certificate unexpectedly verified")
	}
}

func TestVerifyStagedRenewalRejectsBroadPermissions(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertificate(t, dir, "renewal-verify-permissions")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := RenewalRequest{ProfileID: "primary", CurrentSerial: "0", DNSNames: []string{"gateway.example.test"}, RequestedAt: now.Format(time.RFC3339Nano), Reason: "certificate-renewal-window-reached"}
	candidate, _, err := ValidateRenewalCandidate(request, certPEM, keyPEM, now)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageRenewalCandidate(filepath.Join(dir, "staged"), candidate, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(staged.ManifestFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyStagedRenewal(staged.Directory); err == nil {
		t.Fatal("staged renewal with broad manifest permissions unexpectedly verified")
	}
}
