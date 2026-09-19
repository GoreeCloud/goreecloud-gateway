package tlsconfig

import (
	"os"
	"testing"
	"time"
)

func TestValidateRenewalCandidateBindsKeyPairAndDNSNames(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertificate(t, dir, "renewed")
	certPEM, err := os.ReadFile(certPath)
	if err != nil { t.Fatal(err) }
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil { t.Fatal(err) }
	now := time.Now().UTC()
	request := RenewalRequest{ProfileID: "primary", CurrentSerial: "0", DNSNames: []string{"gateway.example.test"}, RequestedAt: now.Format(time.RFC3339Nano), Reason: "certificate-renewal-window-reached"}

	candidate, pair, err := ValidateRenewalCandidate(request, certPEM, keyPEM, now)
	if err != nil { t.Fatal(err) }
	if candidate.NewSerial == request.CurrentSerial || pair.Leaf == nil {
		t.Fatalf("invalid renewal candidate result: %+v", candidate)
	}

	wrongName := request
	wrongName.DNSNames = []string{"other.example.test"}
	if _, _, err := ValidateRenewalCandidate(wrongName, certPEM, keyPEM, now); err == nil {
		t.Fatal("certificate missing requested DNS name unexpectedly accepted")
	}

	sameSerial := request
	sameSerial.CurrentSerial = candidate.NewSerial
	if _, _, err := ValidateRenewalCandidate(sameSerial, certPEM, keyPEM, now); err == nil {
		t.Fatal("renewal candidate without serial rotation unexpectedly accepted")
	}
}
