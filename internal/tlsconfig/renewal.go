package tlsconfig

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// RenewalEvidence is a privacy-safe certificate lifecycle snapshot. It carries
// certificate identity and timing only; it never contains private-key material.
type RenewalEvidence struct {
	ProfileID   string `json:"profile_id"`
	Serial      string `json:"serial"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	ObservedAt  string `json:"observed_at"`
	RenewBefore string `json:"renew_before"`
	Eligible    bool   `json:"eligible"`
}

func BuildRenewalEvidence(profileID string, cert *x509.Certificate, observedAt time.Time, renewBefore time.Duration) (RenewalEvidence, error) {
	if profileID == "" {
		return RenewalEvidence{}, errors.New("gateway tls: certificate profile id is required")
	}
	if cert == nil {
		return RenewalEvidence{}, errors.New("gateway tls: certificate is required")
	}
	if observedAt.IsZero() {
		return RenewalEvidence{}, errors.New("gateway tls: certificate observation time is required")
	}
	if renewBefore <= 0 {
		return RenewalEvidence{}, errors.New("gateway tls: renewal lead time must be positive")
	}
	if !cert.NotAfter.After(cert.NotBefore) {
		return RenewalEvidence{}, errors.New("gateway tls: certificate validity window is invalid")
	}

	now := observedAt.UTC()
	threshold := cert.NotAfter.UTC().Add(-renewBefore)
	return RenewalEvidence{
		ProfileID:   profileID,
		Serial:      cert.SerialNumber.String(),
		NotBefore:   cert.NotBefore.UTC().Format(time.RFC3339Nano),
		NotAfter:    cert.NotAfter.UTC().Format(time.RFC3339Nano),
		ObservedAt:  now.Format(time.RFC3339Nano),
		RenewBefore: threshold.Format(time.RFC3339Nano),
		Eligible:    !now.Before(threshold),
	}, nil
}

func (e RenewalEvidence) Validate() error {
	if e.ProfileID == "" || e.Serial == "" {
		return errors.New("gateway tls: renewal evidence identity is incomplete")
	}
	notBefore, err := time.Parse(time.RFC3339Nano, e.NotBefore)
	if err != nil {
		return fmt.Errorf("gateway tls: invalid renewal evidence not_before: %w", err)
	}
	notAfter, err := time.Parse(time.RFC3339Nano, e.NotAfter)
	if err != nil {
		return fmt.Errorf("gateway tls: invalid renewal evidence not_after: %w", err)
	}
	observedAt, err := time.Parse(time.RFC3339Nano, e.ObservedAt)
	if err != nil {
		return fmt.Errorf("gateway tls: invalid renewal evidence observed_at: %w", err)
	}
	renewBefore, err := time.Parse(time.RFC3339Nano, e.RenewBefore)
	if err != nil {
		return fmt.Errorf("gateway tls: invalid renewal evidence renew_before: %w", err)
	}
	if !notAfter.After(notBefore) || renewBefore.After(notAfter) {
		return errors.New("gateway tls: renewal evidence validity window is inconsistent")
	}
	if e.Eligible != !observedAt.Before(renewBefore) {
		return errors.New("gateway tls: renewal evidence eligibility does not match timing")
	}
	return nil
}
