package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

const RenewalRuntimeActivationReceiptSchemaV1 = "goreecloud-gateway-renewal-runtime-activation-receipt/v1"

type RenewalRuntimeActivationReceipt struct {
	Schema                      string `json:"schema"`
	ProfileID                   string `json:"profile_id"`
	ActivatedAt                 string `json:"activated_at"`
	PreviousSerial              string `json:"previous_serial"`
	CandidateSerial             string `json:"candidate_serial"`
	RuntimeReloaded             bool   `json:"runtime_reloaded"`
	BackupRetained              bool   `json:"backup_retained"`
	ProductionCutoverAuthorized bool   `json:"production_cutover_authorized"`
}

// ActivateRenewalPublication is the controlled boundary between an accepted
// on-disk renewal publication and Gateway's in-memory TLS runtime. It verifies
// that the supplied configuration still references the exact published pair,
// loads the candidate before touching runtime state, then asks Reloader to
// validate and atomically publish the replacement runtime. If runtime reload
// fails, the pre-publication on-disk backup is restored while Reloader retains
// its previous last-known-good runtime.
func ActivateRenewalPublication(reloader *Reloader, cfg *config.Config, publication RenewalPublicationReceipt, now time.Time) (RenewalRuntimeActivationReceipt, error) {
	if reloader == nil {
		return RenewalRuntimeActivationReceipt{}, errors.New("gateway tls: reloader is required for renewal activation")
	}
	if cfg == nil {
		return RenewalRuntimeActivationReceipt{}, errors.New("gateway tls: gateway config is required for renewal activation")
	}
	if err := validateRenewalPublicationReceipt(publication); err != nil {
		return RenewalRuntimeActivationReceipt{}, err
	}
	if now.IsZero() {
		return RenewalRuntimeActivationReceipt{}, errors.New("gateway tls: renewal activation time is required")
	}
	if err := cfg.Validate(); err != nil {
		return RenewalRuntimeActivationReceipt{}, fmt.Errorf("gateway tls: renewal activation config rejected: %w", err)
	}
	profile, ok := cfg.CertificateProfile(publication.ProfileID)
	if !ok || !profile.Enabled {
		return RenewalRuntimeActivationReceipt{}, errors.New("gateway tls: renewal activation profile is missing or disabled")
	}
	if profile.CertificateFile != publication.LiveCertificateFile || profile.PrivateKeyFile != publication.LivePrivateKeyFile {
		return RenewalRuntimeActivationReceipt{}, errors.New("gateway tls: renewal activation config no longer references published live files")
	}

	pair, err := tls.LoadX509KeyPair(profile.CertificateFile, profile.PrivateKeyFile)
	if err != nil {
		return RenewalRuntimeActivationReceipt{}, fmt.Errorf("gateway tls: load published pair before runtime activation: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return RenewalRuntimeActivationReceipt{}, errors.New("gateway tls: published certificate chain is empty before runtime activation")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return RenewalRuntimeActivationReceipt{}, fmt.Errorf("gateway tls: parse published certificate before runtime activation: %w", err)
	}
	if strings.TrimSpace(leaf.SerialNumber.String()) != publication.CandidateSerial {
		return RenewalRuntimeActivationReceipt{}, errors.New("gateway tls: published certificate changed before runtime activation")
	}

	if err := reloader.Reload(cfg); err != nil {
		rollbackErr := RestoreRenewalPublicationBackup(publication, publication.CandidateSerial)
		if rollbackErr != nil {
			return RenewalRuntimeActivationReceipt{}, fmt.Errorf("gateway tls: runtime renewal activation failed and on-disk rollback failed: %v; rollback: %w", err, rollbackErr)
		}
		return RenewalRuntimeActivationReceipt{}, fmt.Errorf("gateway tls: runtime renewal activation failed; on-disk publication restored: %w", err)
	}

	return RenewalRuntimeActivationReceipt{
		Schema:                      RenewalRuntimeActivationReceiptSchemaV1,
		ProfileID:                   publication.ProfileID,
		ActivatedAt:                 now.UTC().Format(time.RFC3339Nano),
		PreviousSerial:              publication.PreviousSerial,
		CandidateSerial:             publication.CandidateSerial,
		RuntimeReloaded:             true,
		BackupRetained:              true,
		ProductionCutoverAuthorized: false,
	}, nil
}
