package tlsconfig

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ACMEAccountRolloverBundleSchemaV1 = "goreecloud-gateway-acme-account-rollover-bundle/v1"
	maxACMEAccountRolloverBundleBytes = 256 << 10
)

type ACMEAccountRolloverBundle struct {
	Schema                      string `json:"schema"`
	DirectoryURL                string `json:"directory_url"`
	PreparedAt                  string `json:"prepared_at"`
	Algorithm                   string `json:"algorithm"`
	OldAccountPublicKeySHA256   string `json:"old_account_public_key_sha256"`
	NewKeyType                  string `json:"new_key_type"`
	NewAccountPublicKeySHA256   string `json:"new_account_public_key_sha256"`
	NonceBase64                 string `json:"nonce_base64"`
	CiphertextBase64            string `json:"ciphertext_base64"`
	ProductionCutoverAuthorized bool   `json:"production_cutover_authorized"`
}

// PrepareACMEAccountKeyRollover creates a fresh account key and persists it as
// an immutable encrypted rollover bundle before any CA-side key-change request
// is allowed. The bundle is cryptographically bound to the currently active
// account-key fingerprint and exact ACME directory.
func PrepareACMEAccountKeyRollover(root string, wrappingKey []byte, directoryURL string, now time.Time) (string, ACMEAccountRolloverBundle, error) {
	var bundle ACMEAccountRolloverBundle
	if len(wrappingKey) != 32 {
		return "", bundle, errors.New("gateway tls: ACME account wrapping key must be exactly 32 bytes")
	}
	if now.IsZero() {
		return "", bundle, errors.New("gateway tls: ACME account rollover preparation time is required")
	}
	directory, err := normalizeACMEDirectoryURL(directoryURL)
	if err != nil {
		return "", bundle, err
	}
	_, activeEnvelope, err := LoadEncryptedACMEAccountKey(root, wrappingKey, directory)
	if err != nil {
		return "", bundle, fmt.Errorf("gateway tls: load active ACME account key before rollover preparation: %w", err)
	}

	newKey, err := GenerateACMEAccountKey()
	if err != nil {
		return "", bundle, fmt.Errorf("gateway tls: generate replacement ACME account key: %w", err)
	}
	newKeyType, newFingerprint, err := describeACMEAccountSigner(newKey)
	if err != nil {
		return "", bundle, err
	}
	if newFingerprint == activeEnvelope.PublicKeySHA256 {
		return "", bundle, errors.New("gateway tls: replacement ACME account key unexpectedly matches active account key")
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(newKey)
	if err != nil {
		return "", bundle, fmt.Errorf("gateway tls: encode replacement ACME account key: %w", err)
	}
	defer clear(privateDER)

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return "", bundle, fmt.Errorf("gateway tls: initialize ACME rollover envelope cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", bundle, fmt.Errorf("gateway tls: initialize ACME rollover envelope AEAD: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", bundle, fmt.Errorf("gateway tls: generate ACME rollover envelope nonce: %w", err)
	}

	bundle = ACMEAccountRolloverBundle{
		Schema:                      ACMEAccountRolloverBundleSchemaV1,
		DirectoryURL:                directory,
		PreparedAt:                  now.UTC().Format(time.RFC3339Nano),
		Algorithm:                   acmeAccountEnvelopeAlgorithm,
		OldAccountPublicKeySHA256:   activeEnvelope.PublicKeySHA256,
		NewKeyType:                  newKeyType,
		NewAccountPublicKeySHA256:   newFingerprint,
		NonceBase64:                 base64.RawStdEncoding.EncodeToString(nonce),
		ProductionCutoverAuthorized: false,
	}
	ciphertext := aead.Seal(nil, nonce, privateDER, acmeAccountRolloverAAD(bundle))
	bundle.CiphertextBase64 = base64.RawStdEncoding.EncodeToString(ciphertext)
	clear(ciphertext)

	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", ACMEAccountRolloverBundle{}, fmt.Errorf("gateway tls: encode ACME rollover bundle: %w", err)
	}
	encoded = append(encoded, '\n')

	stateRoot, err := prepareACMEAccountStateRoot(root, false)
	if err != nil {
		return "", ACMEAccountRolloverBundle{}, err
	}
	path := acmeAccountRolloverBundlePath(stateRoot, directory, newFingerprint)
	if err := writeExclusivePrivateFile(path, encoded); err != nil {
		return "", ACMEAccountRolloverBundle{}, err
	}
	return path, bundle, nil
}

// LoadPreparedACMEAccountKeyRollover authenticates and decrypts one prepared
// rollover bundle only if the active account-key envelope still has the exact
// fingerprint recorded when the bundle was prepared. This prevents a stale
// bundle from being used after account-state drift.
func LoadPreparedACMEAccountKeyRollover(root, bundlePath string, wrappingKey []byte, directoryURL string) (crypto.Signer, ACMEAccountRolloverBundle, error) {
	var bundle ACMEAccountRolloverBundle
	if len(wrappingKey) != 32 {
		return nil, bundle, errors.New("gateway tls: ACME account wrapping key must be exactly 32 bytes")
	}
	directory, err := normalizeACMEDirectoryURL(directoryURL)
	if err != nil {
		return nil, bundle, err
	}
	stateRoot, err := prepareACMEAccountStateRoot(root, false)
	if err != nil {
		return nil, bundle, err
	}
	path, err := validateRolloverBundlePath(stateRoot, bundlePath)
	if err != nil {
		return nil, bundle, err
	}

	_, activeEnvelope, err := LoadEncryptedACMEAccountKey(stateRoot, wrappingKey, directory)
	if err != nil {
		return nil, bundle, fmt.Errorf("gateway tls: load active ACME account key before rollover use: %w", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return nil, bundle, fmt.Errorf("gateway tls: inspect ACME rollover bundle: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, bundle, errors.New("gateway tls: ACME rollover bundle must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o100 != 0 {
		return nil, bundle, errors.New("gateway tls: ACME rollover bundle permissions are too broad")
	}
	if info.Size() <= 0 || info.Size() > maxACMEAccountRolloverBundleBytes {
		return nil, bundle, errors.New("gateway tls: ACME rollover bundle size is invalid")
	}

	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, bundle, fmt.Errorf("gateway tls: read ACME rollover bundle: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return nil, ACMEAccountRolloverBundle{}, fmt.Errorf("gateway tls: decode ACME rollover bundle: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ACMEAccountRolloverBundle{}, errors.New("gateway tls: ACME rollover bundle contains trailing data")
	}
	if err := validateACMEAccountRolloverBundle(bundle, directory); err != nil {
		return nil, ACMEAccountRolloverBundle{}, err
	}
	if bundle.OldAccountPublicKeySHA256 != activeEnvelope.PublicKeySHA256 {
		return nil, ACMEAccountRolloverBundle{}, errors.New("gateway tls: ACME rollover bundle is stale because active account key changed")
	}

	nonce, err := base64.RawStdEncoding.DecodeString(bundle.NonceBase64)
	if err != nil {
		return nil, ACMEAccountRolloverBundle{}, errors.New("gateway tls: ACME rollover bundle nonce is invalid")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(bundle.CiphertextBase64)
	if err != nil {
		return nil, ACMEAccountRolloverBundle{}, errors.New("gateway tls: ACME rollover bundle ciphertext is invalid")
	}
	defer clear(ciphertext)

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, ACMEAccountRolloverBundle{}, fmt.Errorf("gateway tls: initialize ACME rollover envelope cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ACMEAccountRolloverBundle{}, fmt.Errorf("gateway tls: initialize ACME rollover envelope AEAD: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ACMEAccountRolloverBundle{}, errors.New("gateway tls: ACME rollover bundle nonce length is invalid")
	}
	privateDER, err := aead.Open(nil, nonce, ciphertext, acmeAccountRolloverAAD(bundle))
	if err != nil {
		return nil, ACMEAccountRolloverBundle{}, errors.New("gateway tls: ACME rollover bundle authentication failed")
	}
	defer clear(privateDER)

	parsed, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, ACMEAccountRolloverBundle{}, errors.New("gateway tls: ACME rollover private key payload is invalid")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, ACMEAccountRolloverBundle{}, errors.New("gateway tls: ACME rollover private key payload is not a signer")
	}
	keyType, fingerprint, err := describeACMEAccountSigner(signer)
	if err != nil {
		return nil, ACMEAccountRolloverBundle{}, err
	}
	if keyType != bundle.NewKeyType || fingerprint != bundle.NewAccountPublicKeySHA256 {
		return nil, ACMEAccountRolloverBundle{}, errors.New("gateway tls: ACME rollover bundle replacement key identity mismatch")
	}
	return signer, bundle, nil
}

func validateACMEAccountRolloverBundle(bundle ACMEAccountRolloverBundle, expectedDirectory string) error {
	if bundle.Schema != ACMEAccountRolloverBundleSchemaV1 {
		return errors.New("gateway tls: unsupported ACME rollover bundle schema")
	}
	if bundle.DirectoryURL != expectedDirectory {
		return errors.New("gateway tls: ACME rollover bundle directory does not match requested CA")
	}
	if _, err := time.Parse(time.RFC3339Nano, bundle.PreparedAt); err != nil {
		return errors.New("gateway tls: ACME rollover bundle preparation time is invalid")
	}
	if bundle.Algorithm != acmeAccountEnvelopeAlgorithm {
		return errors.New("gateway tls: unsupported ACME rollover bundle algorithm")
	}
	for _, fingerprint := range []string{bundle.OldAccountPublicKeySHA256, bundle.NewAccountPublicKeySHA256} {
		if len(fingerprint) != 64 {
			return errors.New("gateway tls: ACME rollover bundle fingerprint is invalid")
		}
		if _, err := hex.DecodeString(fingerprint); err != nil || fingerprint != strings.ToLower(fingerprint) {
			return errors.New("gateway tls: ACME rollover bundle fingerprint is invalid")
		}
	}
	if bundle.OldAccountPublicKeySHA256 == bundle.NewAccountPublicKeySHA256 {
		return errors.New("gateway tls: ACME rollover bundle old and new account identities must differ")
	}
	if strings.TrimSpace(bundle.NewKeyType) == "" {
		return errors.New("gateway tls: ACME rollover bundle replacement key type is required")
	}
	if bundle.NonceBase64 == "" || bundle.CiphertextBase64 == "" {
		return errors.New("gateway tls: ACME rollover bundle encrypted payload is incomplete")
	}
	if bundle.ProductionCutoverAuthorized {
		return errors.New("gateway tls: ACME rollover bundle cannot authorize production cutover")
	}
	return nil
}

func validateRolloverBundlePath(root, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("gateway tls: ACME rollover bundle path is required")
	}
	absolute, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("gateway tls: resolve ACME rollover bundle path: %w", err)
	}
	if filepath.Dir(absolute) != root {
		return "", errors.New("gateway tls: ACME rollover bundle must be a direct child of the account state root")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("gateway tls: resolve ACME rollover bundle symlinks: %w", err)
	}
	if filepath.Clean(resolved) != filepath.Clean(absolute) {
		return "", errors.New("gateway tls: ACME rollover bundle path contains a symbolic link")
	}
	return absolute, nil
}

func acmeAccountRolloverBundlePath(root, directoryURL, newFingerprint string) string {
	directoryDigest := sha256.Sum256([]byte(directoryURL))
	return filepath.Join(
		root,
		"rollover-"+hex.EncodeToString(directoryDigest[:8])+"-"+newFingerprint[:16]+".json",
	)
}

func acmeAccountRolloverAAD(bundle ACMEAccountRolloverBundle) []byte {
	return []byte(strings.Join([]string{
		bundle.Schema,
		bundle.DirectoryURL,
		bundle.PreparedAt,
		bundle.Algorithm,
		bundle.OldAccountPublicKeySHA256,
		bundle.NewKeyType,
		bundle.NewAccountPublicKeySHA256,
	}, "\n"))
}
