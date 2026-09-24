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

// VerifyStagedRenewal re-opens a published renewal bundle and proves that its
// manifest, certificate, and private key are still mutually consistent. It is
// a read-only verification boundary and never changes live TLS configuration.
func VerifyStagedRenewal(directory string) (RenewalStageManifest, tls.Certificate, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return RenewalStageManifest{}, tls.Certificate{}, errors.New("gateway tls: staged renewal directory is required")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return RenewalStageManifest{}, tls.Certificate{}, fmt.Errorf("gateway tls: stat staged renewal directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return RenewalStageManifest{}, tls.Certificate{}, errors.New("gateway tls: staged renewal directory must be a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return RenewalStageManifest{}, tls.Certificate{}, errors.New("gateway tls: staged renewal directory permissions are too broad")
	}

	manifestPath := filepath.Join(directory, "manifest.json")
	certificatePath := filepath.Join(directory, "certificate.pem")
	privateKeyPath := filepath.Join(directory, "private-key.pem")
	for _, path := range []string{manifestPath, certificatePath, privateKeyPath} {
		fileInfo, statErr := os.Lstat(path)
		if statErr != nil {
			return RenewalStageManifest{}, tls.Certificate{}, fmt.Errorf("gateway tls: stat staged renewal file %q: %w", filepath.Base(path), statErr)
		}
		if fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() {
			return RenewalStageManifest{}, tls.Certificate{}, fmt.Errorf("gateway tls: staged renewal file %q must be a regular file", filepath.Base(path))
		}
		if fileInfo.Mode().Perm()&0o077 != 0 {
			return RenewalStageManifest{}, tls.Certificate{}, fmt.Errorf("gateway tls: staged renewal file %q permissions are too broad", filepath.Base(path))
		}
	}

	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return RenewalStageManifest{}, tls.Certificate{}, fmt.Errorf("gateway tls: read staged renewal manifest: %w", err)
	}
	var manifest RenewalStageManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return RenewalStageManifest{}, tls.Certificate{}, fmt.Errorf("gateway tls: decode staged renewal manifest: %w", err)
	}
	if err := validateRenewalStageManifest(manifest); err != nil {
		return RenewalStageManifest{}, tls.Certificate{}, err
	}

	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return RenewalStageManifest{}, tls.Certificate{}, fmt.Errorf("gateway tls: read staged renewal certificate: %w", err)
	}
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return RenewalStageManifest{}, tls.Certificate{}, fmt.Errorf("gateway tls: read staged renewal private key: %w", err)
	}
	certificateHash := sha256.Sum256(certificatePEM)
	privateKeyHash := sha256.Sum256(privateKeyPEM)
	if hex.EncodeToString(certificateHash[:]) != strings.ToLower(manifest.CertificateSHA256) {
		return RenewalStageManifest{}, tls.Certificate{}, errors.New("gateway tls: staged renewal certificate fingerprint mismatch")
	}
	if hex.EncodeToString(privateKeyHash[:]) != strings.ToLower(manifest.PrivateKeySHA256) {
		return RenewalStageManifest{}, tls.Certificate{}, errors.New("gateway tls: staged renewal private-key fingerprint mismatch")
	}

	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return RenewalStageManifest{}, tls.Certificate{}, fmt.Errorf("gateway tls: staged renewal key pair rejected: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return RenewalStageManifest{}, tls.Certificate{}, errors.New("gateway tls: staged renewal certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return RenewalStageManifest{}, tls.Certificate{}, fmt.Errorf("gateway tls: staged renewal leaf certificate rejected: %w", err)
	}
	if leaf.SerialNumber.String() != manifest.NewSerial || leaf.NotAfter.UTC().Format(time.RFC3339Nano) != manifest.NotAfter {
		return RenewalStageManifest{}, tls.Certificate{}, errors.New("gateway tls: staged renewal certificate does not match manifest identity")
	}
	for _, name := range manifest.DNSNames {
		if err := leaf.VerifyHostname(name); err != nil {
			return RenewalStageManifest{}, tls.Certificate{}, fmt.Errorf("gateway tls: staged renewal certificate does not cover manifest DNS name %q: %w", name, err)
		}
	}
	pair.Leaf = leaf
	return manifest, pair, nil
}

func validateRenewalStageManifest(manifest RenewalStageManifest) error {
	if manifest.Schema != RenewalStageManifestSchemaV1 {
		return errors.New("gateway tls: unsupported renewal staging manifest schema")
	}
	if strings.TrimSpace(manifest.ProfileID) == "" || strings.TrimSpace(manifest.PreviousSerial) == "" || strings.TrimSpace(manifest.NewSerial) == "" {
		return errors.New("gateway tls: renewal staging manifest identity is incomplete")
	}
	if manifest.PreviousSerial == manifest.NewSerial {
		return errors.New("gateway tls: renewal staging manifest did not rotate certificate serial")
	}
	if len(manifest.DNSNames) == 0 {
		return errors.New("gateway tls: renewal staging manifest DNS names are required")
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.ValidatedAt); err != nil {
		return errors.New("gateway tls: renewal staging manifest validated_at is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.NotAfter); err != nil {
		return errors.New("gateway tls: renewal staging manifest not_after is invalid")
	}
	for _, value := range []string{manifest.CertificateSHA256, manifest.PrivateKeySHA256} {
		decoded, err := hex.DecodeString(strings.TrimSpace(value))
		if err != nil || len(decoded) != sha256.Size {
			return errors.New("gateway tls: renewal staging manifest fingerprint is invalid")
		}
	}
	return nil
}
