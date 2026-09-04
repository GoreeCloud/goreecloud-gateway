package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// RenewalCandidate is privacy-safe evidence about returned certificate material.
// Private-key bytes remain only inside the validated tls.Certificate value and
// are never copied into this evidence structure.
type RenewalCandidate struct {
	ProfileID    string   `json:"profile_id"`
	PreviousSerial string `json:"previous_serial"`
	NewSerial    string   `json:"new_serial"`
	DNSNames     []string `json:"dns_names"`
	NotAfter     string   `json:"not_after"`
	ValidatedAt  string   `json:"validated_at"`
}

func ValidateRenewalCandidate(request RenewalRequest, certificatePEM, privateKeyPEM []byte, now time.Time) (RenewalCandidate, tls.Certificate, error) {
	if err := request.Validate(); err != nil {
		return RenewalCandidate{}, tls.Certificate{}, err
	}
	if now.IsZero() {
		return RenewalCandidate{}, tls.Certificate{}, errors.New("gateway tls: renewal candidate validation time is required")
	}
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return RenewalCandidate{}, tls.Certificate{}, fmt.Errorf("gateway tls: renewal candidate key pair rejected: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return RenewalCandidate{}, tls.Certificate{}, errors.New("gateway tls: renewal candidate certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return RenewalCandidate{}, tls.Certificate{}, fmt.Errorf("gateway tls: renewal candidate leaf certificate rejected: %w", err)
	}
	when := now.UTC()
	if when.Before(leaf.NotBefore.UTC()) || !when.Before(leaf.NotAfter.UTC()) {
		return RenewalCandidate{}, tls.Certificate{}, errors.New("gateway tls: renewal candidate is not currently valid")
	}
	if leaf.SerialNumber.String() == request.CurrentSerial {
		return RenewalCandidate{}, tls.Certificate{}, errors.New("gateway tls: renewal candidate did not rotate certificate serial")
	}
	for _, name := range request.DNSNames {
		if err := leaf.VerifyHostname(name); err != nil {
			return RenewalCandidate{}, tls.Certificate{}, fmt.Errorf("gateway tls: renewal candidate does not cover requested DNS name %q: %w", name, err)
		}
	}
	pair.Leaf = leaf
	return RenewalCandidate{
		ProfileID:       request.ProfileID,
		PreviousSerial:  request.CurrentSerial,
		NewSerial:       leaf.SerialNumber.String(),
		DNSNames:        append([]string(nil), request.DNSNames...),
		NotAfter:        leaf.NotAfter.UTC().Format(time.RFC3339Nano),
		ValidatedAt:     when.Format(time.RFC3339Nano),
	}, pair, nil
}
