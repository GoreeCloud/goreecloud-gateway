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

const (
	RenewalPublicationReceiptSchemaV1 = "goreecloud-gateway-renewal-publication-receipt/v1"
	RenewalBackupManifestSchemaV1      = "goreecloud-gateway-renewal-backup/v1"
)

type RenewalBackupManifest struct {
	Schema                    string `json:"schema"`
	CreatedAt                 string `json:"created_at"`
	ProfileID                 string `json:"profile_id"`
	PreviousSerial            string `json:"previous_serial"`
	CandidateSerial           string `json:"candidate_serial"`
	PreviousCertificateSHA256 string `json:"previous_certificate_sha256"`
	PreviousPrivateKeySHA256  string `json:"previous_private_key_sha256"`
}

type RenewalPublicationReceipt struct {
	Schema                      string `json:"schema"`
	ProfileID                   string `json:"profile_id"`
	PublishedAt                 string `json:"published_at"`
	PreviousSerial              string `json:"previous_serial"`
	CandidateSerial             string `json:"candidate_serial"`
	LiveCertificateFile         string `json:"live_certificate_file"`
	LivePrivateKeyFile          string `json:"live_private_key_file"`
	BackupDirectory             string `json:"backup_directory"`
	RuntimeReloadRequired       bool   `json:"runtime_reload_required"`
	ProductionCutoverAuthorized bool   `json:"production_cutover_authorized"`
}

// ExecuteRenewalPublication performs an on-disk certificate/key transaction only
// after revalidating the non-mutating publication plan against both staged and
// currently live material. It captures an owner-only backup first and restores
// the previous pair if any replacement or post-write verification step fails.
// Runtime TLS state is not reloaded here and production cutover is never granted.
func ExecuteRenewalPublication(plan RenewalPublicationPlan, backupRoot string, now time.Time) (RenewalPublicationReceipt, error) {
	if err := validateRenewalPublicationPlan(plan); err != nil {
		return RenewalPublicationReceipt{}, err
	}
	if now.IsZero() {
		return RenewalPublicationReceipt{}, errors.New("gateway tls: renewal publication time is required")
	}
	backupRoot = strings.TrimSpace(backupRoot)
	if backupRoot == "" {
		return RenewalPublicationReceipt{}, errors.New("gateway tls: renewal backup root is required")
	}

	manifest, _, err := VerifyStagedRenewal(plan.StagedDirectory)
	if err != nil {
		return RenewalPublicationReceipt{}, err
	}
	if manifest.ProfileID != plan.ProfileID || manifest.PreviousSerial != plan.CurrentSerial || manifest.NewSerial != plan.CandidateSerial ||
		strings.ToLower(manifest.CertificateSHA256) != strings.ToLower(plan.StagedCertificateSHA256) ||
		strings.ToLower(manifest.PrivateKeySHA256) != strings.ToLower(plan.StagedPrivateKeySHA256) {
		return RenewalPublicationReceipt{}, errors.New("gateway tls: staged renewal no longer matches publication plan")
	}

	currentCert, err := readRenewalLiveFile(plan.LiveCertificateFile, false)
	if err != nil {
		return RenewalPublicationReceipt{}, err
	}
	currentKey, err := readRenewalLiveFile(plan.LivePrivateKeyFile, true)
	if err != nil {
		return RenewalPublicationReceipt{}, err
	}
	currentPair, currentLeaf, err := parseRenewalPair(currentCert, currentKey)
	if err != nil {
		return RenewalPublicationReceipt{}, fmt.Errorf("gateway tls: current live pair rejected before publication: %w", err)
	}
	_ = currentPair
	if currentLeaf.SerialNumber.String() != plan.CurrentSerial {
		return RenewalPublicationReceipt{}, errors.New("gateway tls: live certificate changed after publication plan preparation")
	}

	stagedCert, err := os.ReadFile(filepath.Join(plan.StagedDirectory, "certificate.pem"))
	if err != nil {
		return RenewalPublicationReceipt{}, fmt.Errorf("gateway tls: read staged publication certificate: %w", err)
	}
	stagedKey, err := os.ReadFile(filepath.Join(plan.StagedDirectory, "private-key.pem"))
	if err != nil {
		return RenewalPublicationReceipt{}, fmt.Errorf("gateway tls: read staged publication private key: %w", err)
	}

	backupDirectory, err := createRenewalBackup(backupRoot, plan, currentCert, currentKey, now)
	if err != nil {
		return RenewalPublicationReceipt{}, err
	}

	if err := replaceRenewalLivePair(plan.LiveCertificateFile, plan.LivePrivateKeyFile, stagedCert, stagedKey, currentCert, currentKey); err != nil {
		return RenewalPublicationReceipt{}, err
	}
	_, publishedLeaf, err := loadRenewalLivePair(plan.LiveCertificateFile, plan.LivePrivateKeyFile)
	if err != nil || publishedLeaf.SerialNumber.String() != plan.CandidateSerial {
		rollbackErr := replaceRenewalLivePair(plan.LiveCertificateFile, plan.LivePrivateKeyFile, currentCert, currentKey, stagedCert, stagedKey)
		if rollbackErr != nil {
			return RenewalPublicationReceipt{}, fmt.Errorf("gateway tls: published renewal verification failed and rollback failed: %v; rollback: %w", err, rollbackErr)
		}
		if err != nil {
			return RenewalPublicationReceipt{}, fmt.Errorf("gateway tls: published renewal verification failed: %w", err)
		}
		return RenewalPublicationReceipt{}, errors.New("gateway tls: published renewal serial does not match candidate")
	}

	return RenewalPublicationReceipt{
		Schema:                      RenewalPublicationReceiptSchemaV1,
		ProfileID:                   plan.ProfileID,
		PublishedAt:                 now.UTC().Format(time.RFC3339Nano),
		PreviousSerial:              plan.CurrentSerial,
		CandidateSerial:             plan.CandidateSerial,
		LiveCertificateFile:         plan.LiveCertificateFile,
		LivePrivateKeyFile:          plan.LivePrivateKeyFile,
		BackupDirectory:             backupDirectory,
		RuntimeReloadRequired:       true,
		ProductionCutoverAuthorized: false,
	}, nil
}

// RestoreRenewalPublicationBackup explicitly restores the pre-publication pair
// only while the live certificate is still the exact candidate named by the
// receipt. It does not reload runtime TLS state or authorize production cutover.
func RestoreRenewalPublicationBackup(receipt RenewalPublicationReceipt, expectedCurrentSerial string) error {
	if err := validateRenewalPublicationReceipt(receipt); err != nil {
		return err
	}
	expectedCurrentSerial = strings.TrimSpace(expectedCurrentSerial)
	if expectedCurrentSerial == "" || expectedCurrentSerial != receipt.CandidateSerial {
		return errors.New("gateway tls: renewal rollback expected current serial mismatch")
	}
	_, currentLeaf, err := loadRenewalLivePair(receipt.LiveCertificateFile, receipt.LivePrivateKeyFile)
	if err != nil {
		return err
	}
	if currentLeaf.SerialNumber.String() != expectedCurrentSerial {
		return errors.New("gateway tls: live certificate changed after renewal publication")
	}

	backupManifest, backupCert, backupKey, err := readRenewalBackup(receipt.BackupDirectory)
	if err != nil {
		return err
	}
	if backupManifest.ProfileID != receipt.ProfileID || backupManifest.PreviousSerial != receipt.PreviousSerial || backupManifest.CandidateSerial != receipt.CandidateSerial {
		return errors.New("gateway tls: renewal backup does not match publication receipt")
	}
	_, backupLeaf, err := parseRenewalPair(backupCert, backupKey)
	if err != nil {
		return fmt.Errorf("gateway tls: renewal backup pair rejected: %w", err)
	}
	if backupLeaf.SerialNumber.String() != receipt.PreviousSerial {
		return errors.New("gateway tls: renewal backup serial does not match publication receipt")
	}

	currentCert, err := os.ReadFile(receipt.LiveCertificateFile)
	if err != nil {
		return err
	}
	currentKey, err := os.ReadFile(receipt.LivePrivateKeyFile)
	if err != nil {
		return err
	}
	if err := replaceRenewalLivePair(receipt.LiveCertificateFile, receipt.LivePrivateKeyFile, backupCert, backupKey, currentCert, currentKey); err != nil {
		return err
	}
	_, restoredLeaf, err := loadRenewalLivePair(receipt.LiveCertificateFile, receipt.LivePrivateKeyFile)
	if err != nil {
		return err
	}
	if restoredLeaf.SerialNumber.String() != receipt.PreviousSerial {
		return errors.New("gateway tls: renewal rollback did not restore previous certificate serial")
	}
	return nil
}

func validateRenewalPublicationPlan(plan RenewalPublicationPlan) error {
	if plan.Schema != RenewalPublicationPlanSchemaV1 {
		return errors.New("gateway tls: unsupported renewal publication plan schema")
	}
	if strings.TrimSpace(plan.ProfileID) == "" || strings.TrimSpace(plan.CurrentSerial) == "" || strings.TrimSpace(plan.CandidateSerial) == "" {
		return errors.New("gateway tls: renewal publication plan identity is incomplete")
	}
	if plan.CurrentSerial == plan.CandidateSerial {
		return errors.New("gateway tls: renewal publication plan does not rotate certificate serial")
	}
	if _, err := time.Parse(time.RFC3339Nano, plan.PreparedAt); err != nil {
		return errors.New("gateway tls: renewal publication plan prepared_at is invalid")
	}
	if strings.TrimSpace(plan.LiveCertificateFile) == "" || strings.TrimSpace(plan.LivePrivateKeyFile) == "" || strings.TrimSpace(plan.StagedDirectory) == "" {
		return errors.New("gateway tls: renewal publication plan file references are incomplete")
	}
	if !plan.BackupRequired || !plan.RuntimeReloadRequired || plan.ProductionCutoverAuthorized {
		return errors.New("gateway tls: renewal publication plan safety invariants are invalid")
	}
	for _, fingerprint := range []string{plan.StagedCertificateSHA256, plan.StagedPrivateKeySHA256} {
		decoded, err := hex.DecodeString(strings.TrimSpace(fingerprint))
		if err != nil || len(decoded) != sha256.Size {
			return errors.New("gateway tls: renewal publication plan fingerprint is invalid")
		}
	}
	return nil
}

func validateRenewalPublicationReceipt(receipt RenewalPublicationReceipt) error {
	if receipt.Schema != RenewalPublicationReceiptSchemaV1 {
		return errors.New("gateway tls: unsupported renewal publication receipt schema")
	}
	if strings.TrimSpace(receipt.ProfileID) == "" || strings.TrimSpace(receipt.PreviousSerial) == "" || strings.TrimSpace(receipt.CandidateSerial) == "" {
		return errors.New("gateway tls: renewal publication receipt identity is incomplete")
	}
	if _, err := time.Parse(time.RFC3339Nano, receipt.PublishedAt); err != nil {
		return errors.New("gateway tls: renewal publication receipt published_at is invalid")
	}
	if strings.TrimSpace(receipt.LiveCertificateFile) == "" || strings.TrimSpace(receipt.LivePrivateKeyFile) == "" || strings.TrimSpace(receipt.BackupDirectory) == "" {
		return errors.New("gateway tls: renewal publication receipt file references are incomplete")
	}
	if !receipt.RuntimeReloadRequired || receipt.ProductionCutoverAuthorized {
		return errors.New("gateway tls: renewal publication receipt safety invariants are invalid")
	}
	return nil
}

func readRenewalLiveFile(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("gateway tls: stat live renewal file %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("gateway tls: live renewal file %q must be a regular file", path)
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("gateway tls: live private-key file %q permissions are too broad", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gateway tls: read live renewal file %q: %w", path, err)
	}
	return data, nil
}

func parseRenewalPair(certificatePEM, privateKeyPEM []byte) (tls.Certificate, *x509.Certificate, error) {
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if len(pair.Certificate) == 0 {
		return tls.Certificate{}, nil, errors.New("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pair.Leaf = leaf
	return pair, leaf, nil
}

func loadRenewalLivePair(certificateFile, privateKeyFile string) (tls.Certificate, *x509.Certificate, error) {
	certificatePEM, err := readRenewalLiveFile(certificateFile, false)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	privateKeyPEM, err := readRenewalLiveFile(privateKeyFile, true)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return parseRenewalPair(certificatePEM, privateKeyPEM)
}

func createRenewalBackup(root string, plan RenewalPublicationPlan, certificatePEM, privateKeyPEM []byte, now time.Time) (string, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("gateway tls: create renewal backup root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", fmt.Errorf("gateway tls: protect renewal backup root: %w", err)
	}
	tmpDir, err := os.MkdirTemp(root, ".renewal-backup-*")
	if err != nil {
		return "", fmt.Errorf("gateway tls: create renewal backup directory: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(tmpDir)
		}
	}()
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return "", err
	}
	certHash := sha256.Sum256(certificatePEM)
	keyHash := sha256.Sum256(privateKeyPEM)
	manifest := RenewalBackupManifest{
		Schema:                    RenewalBackupManifestSchemaV1,
		CreatedAt:                 now.UTC().Format(time.RFC3339Nano),
		ProfileID:                 plan.ProfileID,
		PreviousSerial:            plan.CurrentSerial,
		CandidateSerial:           plan.CandidateSerial,
		PreviousCertificateSHA256: hex.EncodeToString(certHash[:]),
		PreviousPrivateKeySHA256:  hex.EncodeToString(keyHash[:]),
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	manifestData = append(manifestData, '\n')
	for name, data := range map[string][]byte{
		"certificate.pem": certificatePEM,
		"private-key.pem": privateKeyPEM,
		"manifest.json":   manifestData,
	} {
		if err := writeRenewalFile(filepath.Join(tmpDir, name), data); err != nil {
			return "", err
		}
	}
	bundleHash := sha256.Sum256(append(append([]byte(nil), certificatePEM...), privateKeyPEM...))
	finalDir := filepath.Join(root, "renewal-backup-"+hex.EncodeToString(bundleHash[:8]))
	if _, err := os.Stat(finalDir); err == nil {
		return "", errors.New("gateway tls: renewal backup bundle already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(tmpDir, finalDir); err != nil {
		return "", fmt.Errorf("gateway tls: publish renewal backup: %w", err)
	}
	published = true
	return finalDir, nil
}

func readRenewalBackup(directory string) (RenewalBackupManifest, []byte, []byte, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return RenewalBackupManifest{}, nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return RenewalBackupManifest{}, nil, nil, errors.New("gateway tls: renewal backup directory is not protected")
	}
	manifestData, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return RenewalBackupManifest{}, nil, nil, err
	}
	var manifest RenewalBackupManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return RenewalBackupManifest{}, nil, nil, err
	}
	if manifest.Schema != RenewalBackupManifestSchemaV1 {
		return RenewalBackupManifest{}, nil, nil, errors.New("gateway tls: unsupported renewal backup manifest schema")
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil {
		return RenewalBackupManifest{}, nil, nil, errors.New("gateway tls: renewal backup manifest created_at is invalid")
	}
	certificatePEM, err := os.ReadFile(filepath.Join(directory, "certificate.pem"))
	if err != nil {
		return RenewalBackupManifest{}, nil, nil, err
	}
	privateKeyPEM, err := os.ReadFile(filepath.Join(directory, "private-key.pem"))
	if err != nil {
		return RenewalBackupManifest{}, nil, nil, err
	}
	certHash := sha256.Sum256(certificatePEM)
	keyHash := sha256.Sum256(privateKeyPEM)
	if hex.EncodeToString(certHash[:]) != strings.ToLower(manifest.PreviousCertificateSHA256) || hex.EncodeToString(keyHash[:]) != strings.ToLower(manifest.PreviousPrivateKeySHA256) {
		return RenewalBackupManifest{}, nil, nil, errors.New("gateway tls: renewal backup fingerprint mismatch")
	}
	return manifest, certificatePEM, privateKeyPEM, nil
}

func replaceRenewalLivePair(certificateFile, privateKeyFile string, certificatePEM, privateKeyPEM, rollbackCertificatePEM, rollbackPrivateKeyPEM []byte) error {
	keyTemp, err := writeRenewalTempSibling(privateKeyFile, privateKeyPEM)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(keyTemp) }()
	certTemp, err := writeRenewalTempSibling(certificateFile, certificatePEM)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(certTemp) }()

	if err := os.Rename(keyTemp, privateKeyFile); err != nil {
		return fmt.Errorf("gateway tls: replace live private key: %w", err)
	}
	if err := os.Rename(certTemp, certificateFile); err != nil {
		if rollbackErr := restoreRenewalFile(privateKeyFile, rollbackPrivateKeyPEM); rollbackErr != nil {
			return fmt.Errorf("gateway tls: replace live certificate failed: %v; private-key rollback failed: %w", err, rollbackErr)
		}
		return fmt.Errorf("gateway tls: replace live certificate: %w", err)
	}
	if err := os.Chmod(privateKeyFile, 0o600); err != nil {
		_ = restoreRenewalFile(certificateFile, rollbackCertificatePEM)
		_ = restoreRenewalFile(privateKeyFile, rollbackPrivateKeyPEM)
		return fmt.Errorf("gateway tls: protect live private key: %w", err)
	}
	return nil
}

func writeRenewalTempSibling(destination string, data []byte) (string, error) {
	dir := filepath.Dir(destination)
	tmp, err := os.CreateTemp(dir, ".renewal-publication-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	failed := true
	defer func() {
		if failed {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	failed = false
	return name, nil
}

func writeRenewalFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func restoreRenewalFile(destination string, data []byte) error {
	tmp, err := writeRenewalTempSibling(destination, data)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := os.Rename(tmp, destination); err != nil {
		return err
	}
	return os.Chmod(destination, 0o600)
}
