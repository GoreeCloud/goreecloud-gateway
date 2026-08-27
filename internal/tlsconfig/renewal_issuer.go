package tlsconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RenewalIssuer is the provider-neutral boundary for obtaining replacement
// certificate material for an already validated renewal request. Provider
// credentials and account state remain behind the implementation and are never
// represented in the request or orchestration result.
type RenewalIssuer interface {
	IssueRenewal(context.Context, RenewalRequest) (certificatePEM, privateKeyPEM []byte, err error)
}

// IssuedRenewal is privacy-safe orchestration evidence. It deliberately omits
// certificate and private-key bytes and cannot authorize live publication or
// production cutover.
type IssuedRenewal struct {
	Candidate                   RenewalCandidate `json:"candidate"`
	Stage                       StagedRenewal     `json:"stage"`
	ProductionCutoverAuthorized bool              `json:"production_cutover_authorized"`
}

// IssueValidateAndStageRenewal obtains renewal material from a provider,
// validates that material against the exact request, and publishes it only to
// the owner-protected staging boundary. It never changes a live certificate
// path, reloads the Gateway runtime, or authorizes production cutover.
func IssueValidateAndStageRenewal(ctx context.Context, issuer RenewalIssuer, request RenewalRequest, stagingRoot string, now time.Time) (IssuedRenewal, error) {
	if ctx == nil {
		return IssuedRenewal{}, errors.New("gateway tls: renewal issuance context is required")
	}
	if issuer == nil {
		return IssuedRenewal{}, errors.New("gateway tls: renewal issuer is required")
	}
	if err := request.Validate(); err != nil {
		return IssuedRenewal{}, err
	}
	if strings.TrimSpace(stagingRoot) == "" {
		return IssuedRenewal{}, errors.New("gateway tls: renewal staging root is required")
	}
	if now.IsZero() {
		return IssuedRenewal{}, errors.New("gateway tls: renewal issuance time is required")
	}
	requestedAt, err := time.Parse(time.RFC3339Nano, request.RequestedAt)
	if err != nil {
		return IssuedRenewal{}, errors.New("gateway tls: renewal request time must be RFC3339Nano")
	}
	when := now.UTC()
	if when.Before(requestedAt) {
		return IssuedRenewal{}, errors.New("gateway tls: renewal issuance time precedes renewal request")
	}
	if err := ctx.Err(); err != nil {
		return IssuedRenewal{}, fmt.Errorf("gateway tls: renewal issuance context unavailable: %w", err)
	}

	certificatePEM, privateKeyPEM, err := issuer.IssueRenewal(ctx, request)
	if err != nil {
		return IssuedRenewal{}, fmt.Errorf("gateway tls: renewal issuer failed: %w", err)
	}
	if len(certificatePEM) == 0 || len(privateKeyPEM) == 0 {
		return IssuedRenewal{}, errors.New("gateway tls: renewal issuer returned incomplete certificate material")
	}

	candidate, _, err := ValidateRenewalCandidate(request, certificatePEM, privateKeyPEM, when)
	if err != nil {
		return IssuedRenewal{}, err
	}
	stage, err := StageRenewalCandidate(stagingRoot, candidate, certificatePEM, privateKeyPEM)
	if err != nil {
		return IssuedRenewal{}, err
	}

	return IssuedRenewal{
		Candidate:                   candidate,
		Stage:                       stage,
		ProductionCutoverAuthorized: false,
	}, nil
}
