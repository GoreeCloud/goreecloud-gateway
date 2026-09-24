package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

const RenewalPublicationPlanSchemaV1 = "goreecloud-gateway-renewal-publication-plan/v1"

// RenewalPublicationPlan is a non-mutating, privacy-safe publication contract.
// It proves which live profile and staged bundle would participate in a future
// certificate publication operation, but it never writes either path.
type RenewalPublicationPlan struct {
	Schema                      string `json:"schema"`
	ProfileID                   string `json:"profile_id"`
	PreparedAt                  string `json:"prepared_at"`
	CurrentSerial               string `json:"current_serial"`
	CandidateSerial             string `json:"candidate_serial"`
	LiveCertificateFile         string `json:"live_certificate_file"`
	LivePrivateKeyFile          string `json:"live_private_key_file"`
	StagedDirectory             string `json:"staged_directory"`
	StagedCertificateSHA256     string `json:"staged_certificate_sha256"`
	StagedPrivateKeySHA256      string `json:"staged_private_key_sha256"`
	BackupRequired              bool   `json:"backup_required"`
	RuntimeReloadRequired       bool   `json:"runtime_reload_required"`
	ProductionCutoverAuthorized bool   `json:"production_cutover_authorized"`
}

// PrepareRenewalPublication binds a verified staged renewal to the exact live
// certificate serial currently referenced by a certificate profile. It fails
// closed if the live profile has changed since the renewal request was built.
func PrepareRenewalPublication(profile config.CertificateProfile, staged StagedRenewal, now time.Time) (RenewalPublicationPlan, error) {
	if strings.TrimSpace(profile.ID) == "" || !profile.Enabled {
		return RenewalPublicationPlan{}, errors.New("gateway tls: enabled certificate profile is required for renewal publication")
	}
	if strings.TrimSpace(profile.CertificateFile) == "" || strings.TrimSpace(profile.PrivateKeyFile) == "" {
		return RenewalPublicationPlan{}, errors.New("gateway tls: certificate profile file references are required for renewal publication")
	}
	if now.IsZero() {
		return RenewalPublicationPlan{}, errors.New("gateway tls: renewal publication preparation time is required")
	}
	directory := filepath.Clean(strings.TrimSpace(staged.Directory))
	if directory == "." || directory == "" {
		return RenewalPublicationPlan{}, errors.New("gateway tls: staged renewal directory is required")
	}
	expectedCertificateFile := filepath.Join(directory, "certificate.pem")
	expectedPrivateKeyFile := filepath.Join(directory, "private-key.pem")
	expectedManifestFile := filepath.Join(directory, "manifest.json")
	if filepath.Clean(staged.CertificateFile) != expectedCertificateFile || filepath.Clean(staged.PrivateKeyFile) != expectedPrivateKeyFile || filepath.Clean(staged.ManifestFile) != expectedManifestFile {
		return RenewalPublicationPlan{}, errors.New("gateway tls: staged renewal file references do not match the published bundle")
	}
	if filepath.Clean(profile.CertificateFile) == expectedCertificateFile || filepath.Clean(profile.PrivateKeyFile) == expectedPrivateKeyFile {
		return RenewalPublicationPlan{}, errors.New("gateway tls: staged renewal bundle must remain separate from live profile files")
	}

	manifest, _, err := VerifyStagedRenewal(directory)
	if err != nil {
		return RenewalPublicationPlan{}, err
	}
	if manifest.ProfileID != profile.ID {
		return RenewalPublicationPlan{}, errors.New("gateway tls: staged renewal profile does not match live certificate profile")
	}
	currentPair, err := tls.LoadX509KeyPair(profile.CertificateFile, profile.PrivateKeyFile)
	if err != nil {
		return RenewalPublicationPlan{}, fmt.Errorf("gateway tls: load current live certificate profile: %w", err)
	}
	if len(currentPair.Certificate) == 0 {
		return RenewalPublicationPlan{}, errors.New("gateway tls: current live certificate chain is empty")
	}
	currentLeaf, err := x509.ParseCertificate(currentPair.Certificate[0])
	if err != nil {
		return RenewalPublicationPlan{}, fmt.Errorf("gateway tls: parse current live certificate: %w", err)
	}
	currentSerial := currentLeaf.SerialNumber.String()
	if currentSerial != manifest.PreviousSerial {
		return RenewalPublicationPlan{}, errors.New("gateway tls: live certificate changed since renewal candidate validation")
	}
	if currentSerial == manifest.NewSerial {
		return RenewalPublicationPlan{}, errors.New("gateway tls: renewal publication candidate does not rotate live certificate serial")
	}

	return RenewalPublicationPlan{
		Schema:                      RenewalPublicationPlanSchemaV1,
		ProfileID:                   profile.ID,
		PreparedAt:                  now.UTC().Format(time.RFC3339Nano),
		CurrentSerial:               currentSerial,
		CandidateSerial:             manifest.NewSerial,
		LiveCertificateFile:         profile.CertificateFile,
		LivePrivateKeyFile:          profile.PrivateKeyFile,
		StagedDirectory:             directory,
		StagedCertificateSHA256:     manifest.CertificateSHA256,
		StagedPrivateKeySHA256:      manifest.PrivateKeySHA256,
		BackupRequired:              true,
		RuntimeReloadRequired:       true,
		ProductionCutoverAuthorized: false,
	}, nil
}
