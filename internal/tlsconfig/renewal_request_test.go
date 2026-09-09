package tlsconfig

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestBuildRenewalRequestRequiresEligibilityAndMonotonicTime(t *testing.T) {
	now := time.Date(2026, 8, 27, 4, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour)}
	evidence, err := BuildRenewalEvidence("primary", cert, now, 48*time.Hour)
	if err != nil { t.Fatal(err) }
	if !evidence.Eligible { t.Fatal("expected renewal eligibility") }

	request, err := BuildRenewalRequest(evidence, []string{"Gateway.Example.Test.", "gateway.example.test"}, now.Add(time.Minute))
	if err != nil { t.Fatal(err) }
	if err := request.Validate(); err != nil { t.Fatal(err) }
	if request.ProfileID != "primary" || request.CurrentSerial != "42" || len(request.DNSNames) != 1 || request.DNSNames[0] != "gateway.example.test" {
		t.Fatalf("unexpected request: %+v", request)
	}

	if _, err := BuildRenewalRequest(evidence, []string{"gateway.example.test"}, now.Add(-time.Minute)); err == nil {
		t.Fatal("request preceding evidence unexpectedly accepted")
	}
	if _, err := BuildRenewalRequest(evidence, nil, now.Add(time.Minute)); err == nil {
		t.Fatal("renewal request without DNS names unexpectedly accepted")
	}
}

func TestBuildRenewalRequestRejectsCertificateOutsideWindow(t *testing.T) {
	now := time.Date(2026, 8, 27, 4, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)}
	evidence, err := BuildRenewalEvidence("primary", cert, now, 7*24*time.Hour)
	if err != nil { t.Fatal(err) }
	if evidence.Eligible { t.Fatal("certificate unexpectedly renewal-eligible") }
	if _, err := BuildRenewalRequest(evidence, []string{"gateway.example.test"}, now); err == nil {
		t.Fatal("ineligible renewal request unexpectedly accepted")
	}
}
