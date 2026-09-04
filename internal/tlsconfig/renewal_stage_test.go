package tlsconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStageRenewalCandidatePublishesOwnerOnlyBundle(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertificate(t, dir, "renewal-stage")
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

	stagingRoot := filepath.Join(dir, "staged")
	staged, err := StageRenewalCandidate(stagingRoot, candidate, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(staged.Directory) != stagingRoot {
		t.Fatalf("unexpected staged directory %q", staged.Directory)
	}
	for _, path := range []string{staged.CertificateFile, staged.PrivateKeyFile, staged.ManifestFile} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("staged file %q mode=%#o", path, info.Mode().Perm())
		}
	}
	bundleInfo, err := os.Stat(staged.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if bundleInfo.Mode().Perm() != 0o700 {
		t.Fatalf("staged directory mode=%#o", bundleInfo.Mode().Perm())
	}
	manifestData, err := os.ReadFile(staged.ManifestFile)
	if err != nil {
		t.Fatal(err)
	}
	var manifest RenewalStageManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != RenewalStageManifestSchemaV1 || manifest.ProfileID != candidate.ProfileID || manifest.NewSerial != candidate.NewSerial {
		t.Fatalf("unexpected staging manifest: %+v", manifest)
	}
	if manifest.CertificateSHA256 == "" || manifest.PrivateKeySHA256 == "" {
		t.Fatal("staging manifest is missing material fingerprints")
	}
}

func TestStageRenewalCandidateRejectsMaterialThatDoesNotMatchEvidence(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertificate(t, dir, "renewal-stage-match")
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
	candidate.NewSerial = "mismatched"
	if _, err := StageRenewalCandidate(filepath.Join(dir, "staged"), candidate, certPEM, keyPEM); err == nil {
		t.Fatal("mismatched validated evidence unexpectedly staged")
	}
}
