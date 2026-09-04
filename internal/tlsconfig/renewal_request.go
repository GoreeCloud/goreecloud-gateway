package tlsconfig

import (
	"errors"
	"sort"
	"strings"
	"time"
)

// RenewalRequest is the provider-facing, private-key-free boundary for asking
// an external or future first-party certificate issuer to renew one profile.
// It can be constructed only from internally validated, renewal-eligible
// evidence and does not authorize listener publication by itself.
type RenewalRequest struct {
	ProfileID     string   `json:"profile_id"`
	CurrentSerial string   `json:"current_serial"`
	DNSNames      []string `json:"dns_names"`
	RequestedAt   string   `json:"requested_at"`
	Reason        string   `json:"reason"`
}

func BuildRenewalRequest(evidence RenewalEvidence, dnsNames []string, requestedAt time.Time) (RenewalRequest, error) {
	if err := evidence.Validate(); err != nil {
		return RenewalRequest{}, err
	}
	if !evidence.Eligible {
		return RenewalRequest{}, errors.New("gateway tls: certificate is not yet renewal-eligible")
	}
	if requestedAt.IsZero() {
		return RenewalRequest{}, errors.New("gateway tls: renewal request time is required")
	}
	names, err := normalizeRenewalDNSNames(dnsNames)
	if err != nil {
		return RenewalRequest{}, err
	}
	observedAt, _ := time.Parse(time.RFC3339Nano, evidence.ObservedAt)
	when := requestedAt.UTC()
	if when.Before(observedAt) {
		return RenewalRequest{}, errors.New("gateway tls: renewal request time precedes renewal evidence")
	}
	return RenewalRequest{
		ProfileID:     strings.TrimSpace(evidence.ProfileID),
		CurrentSerial: evidence.Serial,
		DNSNames:      names,
		RequestedAt:   when.Format(time.RFC3339Nano),
		Reason:        "certificate-renewal-window-reached",
	}, nil
}

func (r RenewalRequest) Validate() error {
	if strings.TrimSpace(r.ProfileID) == "" || strings.TrimSpace(r.CurrentSerial) == "" {
		return errors.New("gateway tls: renewal request identity is incomplete")
	}
	if _, err := normalizeRenewalDNSNames(r.DNSNames); err != nil {
		return err
	}
	if r.Reason != "certificate-renewal-window-reached" {
		return errors.New("gateway tls: unsupported renewal request reason")
	}
	if _, err := time.Parse(time.RFC3339Nano, r.RequestedAt); err != nil {
		return errors.New("gateway tls: renewal request time must be RFC3339Nano")
	}
	return nil
}

func normalizeRenewalDNSNames(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("gateway tls: renewal request requires at least one DNS name")
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		if name == "" || strings.ContainsAny(name, " /\\") {
			return nil, errors.New("gateway tls: renewal request contains an invalid DNS name")
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}
