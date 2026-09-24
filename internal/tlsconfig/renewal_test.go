package tlsconfig

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestBuildRenewalEvidence(t *testing.T) {
	now := time.Date(2026, 8, 27, 3, 40, 0, 0, time.UTC)
	cert := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(48 * time.Hour)}
	evidence, err := BuildRenewalEvidence("primary", cert, now, 72*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Eligible {
		t.Fatal("certificate inside renewal window was not marked eligible")
	}
	if err := evidence.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalEvidenceRejectsTamperedEligibility(t *testing.T) {
	now := time.Date(2026, 8, 27, 3, 40, 0, 0, time.UTC)
	cert := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)}
	evidence, err := BuildRenewalEvidence("primary", cert, now, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Eligible = !evidence.Eligible
	if err := evidence.Validate(); err == nil {
		t.Fatal("tampered renewal eligibility unexpectedly validated")
	}
}
