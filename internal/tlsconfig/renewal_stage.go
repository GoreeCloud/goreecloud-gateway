package tlsconfig

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const RenewalStageManifestSchemaV1 = "goreecloud-gateway-renewal-stage/v1"

type RenewalStageManifest struct {
	Schema            string   `json:"schema"`
	ProfileID         string   `json:"profile_id"`
	PreviousSerial    string   `json:"previous_serial"`
	NewSerial         string   `json:"new_serial"`
	DNSNames          []string `json:"dns_names"`
	NotAfter          string   `json:"not_after"`
	ValidatedAt       string   `json:"validated_at"`
	CertificateSHA256 string   `json:"certificate_sha256"`
	PrivateKeySHA256  string   `json:"private_key_sha256"`
}

type StagedRenewal struct {
	Directory       string `json:"directory"`
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
	ManifestFile    string `json:"manifest_file"`
}

// StageRenewalCandidate durably publishes already-validated renewal material
// into an owner-only staging bundle. It never changes a live TLS profile path,
// reloads the gateway, or authorizes production cutover.
func StageRenewalCandidate(root string, candidate RenewalCandidate, certificatePEM, privateKeyPEM []byte) (StagedRenewal, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return StagedRenewal{}, errors.New("gateway tls: renewal staging root is required")
	}
	if strings.TrimSpace(candidate.ProfileID) == "" || strings.TrimSpace(candidate.NewSerial) == "" {
		return StagedRenewal{}, errors.New("gateway tls: renewal candidate identity is incomplete")
	}
	validatedAt, err := time.Parse(time.RFC3339Nano, candidate.ValidatedAt)
	if err != nil || validatedAt.IsZero() {
		return StagedRenewal{}, errors.New("gateway tls: renewal candidate validated_at is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, candidate.NotAfter); err != nil {
		return StagedRenewal{}, errors.New("gateway tls: renewal candidate not_after is invalid")
	}
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return StagedRenewal{}, fmt.Errorf("gateway tls: staged renewal key pair rejected: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return StagedRenewal{}, errors.New("gateway tls: staged renewal certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return StagedRenewal{}, fmt.Errorf("gateway tls: staged renewal leaf certificate rejected: %w", err)
	}
	if leaf.SerialNumber.String() != candidate.NewSerial || leaf.NotAfter.UTC().Format(time.RFC3339Nano) != candidate.NotAfter {
		return StagedRenewal{}, errors.New("gateway tls: staged renewal material does not match validated candidate")
	}
	for _, name := range candidate.DNSNames {
		if err := leaf.VerifyHostname(name); err != nil {
			return StagedRenewal{}, fmt.Errorf("gateway tls: staged renewal does not cover candidate DNS name %q: %w", name, err)
		}
	}

	if err := os.MkdirAll(root, 0o700); err != nil {
		return StagedRenewal{}, fmt.Errorf("gateway tls: create renewal staging root: %w", err)
	}
	tmpDir, err := os.MkdirTemp(root, ".renewal-stage-*")
	if err != nil {
		return StagedRenewal{}, fmt.Errorf("gateway tls: create renewal staging directory: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(tmpDir)
		}
	}()
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return StagedRenewal{}, fmt.Errorf("gateway tls: protect renewal staging directory: %w", err)
	}

	certHash := sha256.Sum256(certificatePEM)
	keyHash := sha256.Sum256(privateKeyPEM)
	manifest := RenewalStageManifest{
		Schema:            RenewalStageManifestSchemaV1,
		ProfileID:         candidate.ProfileID,
		PreviousSerial:    candidate.PreviousSerial,
		NewSerial:         candidate.NewSerial,
		DNSNames:          append([]string(nil), candidate.DNSNames...),
		NotAfter:          candidate.NotAfter,
		ValidatedAt:       candidate.ValidatedAt,
		CertificateSHA256: hex.EncodeToString(certHash[:]),
		PrivateKeySHA256:  hex.EncodeToString(keyHash[:]),
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return StagedRenewal{}, fmt.Errorf("gateway tls: encode renewal staging manifest: %w", err)
	}
	manifestJSON = append(manifestJSON, '\n')

	for name, data := range map[string][]byte{
		"certificate.pem": certificatePEM,
		"private-key.pem": privateKeyPEM,
		"manifest.json":   manifestJSON,
	} {
		path := filepath.Join(tmpDir, name)
		file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr != nil {
			return StagedRenewal{}, fmt.Errorf("gateway tls: create staged renewal file %q: %w", name, openErr)
		}
		if _, writeErr := file.Write(data); writeErr != nil {
			_ = file.Close()
			return StagedRenewal{}, fmt.Errorf("gateway tls: write staged renewal file %q: %w", name, writeErr)
		}
		if syncErr := file.Sync(); syncErr != nil {
			_ = file.Close()
			return StagedRenewal{}, fmt.Errorf("gateway tls: sync staged renewal file %q: %w", name, syncErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return StagedRenewal{}, fmt.Errorf("gateway tls: close staged renewal file %q: %w", name, closeErr)
		}
	}

	bundleID := hex.EncodeToString(certHash[:8])
	finalDir := filepath.Join(root, "renewal-"+bundleID)
	if err := os.Rename(tmpDir, finalDir); err != nil {
		return StagedRenewal{}, fmt.Errorf("gateway tls: publish renewal staging bundle: %w", err)
	}
	published = true

	return StagedRenewal{
		Directory:       finalDir,
		CertificateFile: filepath.Join(finalDir, "certificate.pem"),
		PrivateKeyFile:  filepath.Join(finalDir, "private-key.pem"),
		ManifestFile:    filepath.Join(finalDir, "manifest.json"),
	}, nil
}
