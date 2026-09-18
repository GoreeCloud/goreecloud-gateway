package tlsconfig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ACMEAccountKeyEnvelopeSchemaV1 = "goreecloud-gateway-acme-account-key-envelope/v1"
	acmeAccountEnvelopeAlgorithm   = "AES-256-GCM"
	maxACMEAccountEnvelopeBytes    = 256 << 10
)

type ACMEAccountKeyEnvelope struct {
	Schema                      string `json:"schema"`
	DirectoryURL                string `json:"directory_url"`
	CreatedAt                   string `json:"created_at"`
	Algorithm                   string `json:"algorithm"`
	KeyType                     string `json:"key_type"`
	PublicKeySHA256             string `json:"public_key_sha256"`
	NonceBase64                 string `json:"nonce_base64"`
	CiphertextBase64            string `json:"ciphertext_base64"`
	ProductionCutoverAuthorized bool   `json:"production_cutover_authorized"`
}

// GenerateACMEAccountKey returns a new account signer without persisting it.
// Persistence is intentionally separate so callers must supply an external
// high-entropy wrapping key and a protected account-state directory.
func GenerateACMEAccountKey() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// SaveEncryptedACMEAccountKey creates one immutable encrypted account-key
// envelope. Existing account state is never overwritten: account replacement
// and ACME key rollover require a separate, explicit operation.
func SaveEncryptedACMEAccountKey(root string, accountKey crypto.Signer, wrappingKey []byte, directoryURL string, now time.Time) (string, ACMEAccountKeyEnvelope, error) {
	var envelope ACMEAccountKeyEnvelope
	if len(wrappingKey) != 32 {
		return "", envelope, errors.New("gateway tls: ACME account wrapping key must be exactly 32 bytes")
	}
	if now.IsZero() {
		return "", envelope, errors.New("gateway tls: ACME account key creation time is required")
	}
	directory, err := normalizeACMEDirectoryURL(directoryURL)
	if err != nil {
		return "", envelope, err
	}
	keyType, fingerprint, err := describeACMEAccountSigner(accountKey)
	if err != nil {
		return "", envelope, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(accountKey)
	if err != nil {
		return "", envelope, fmt.Errorf("gateway tls: encode ACME account private key: %w", err)
	}
	defer clear(privateDER)

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return "", envelope, fmt.Errorf("gateway tls: initialize ACME account envelope cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", envelope, fmt.Errorf("gateway tls: initialize ACME account envelope AEAD: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", envelope, fmt.Errorf("gateway tls: generate ACME account envelope nonce: %w", err)
	}

	envelope = ACMEAccountKeyEnvelope{
		Schema:                      ACMEAccountKeyEnvelopeSchemaV1,
		DirectoryURL:                directory,
		CreatedAt:                   now.UTC().Format(time.RFC3339Nano),
		Algorithm:                   acmeAccountEnvelopeAlgorithm,
		KeyType:                     keyType,
		PublicKeySHA256:             fingerprint,
		NonceBase64:                 base64.RawStdEncoding.EncodeToString(nonce),
		ProductionCutoverAuthorized: false,
	}
	ciphertext := aead.Seal(nil, nonce, privateDER, acmeAccountEnvelopeAAD(envelope))
	envelope.CiphertextBase64 = base64.RawStdEncoding.EncodeToString(ciphertext)
	clear(ciphertext)

	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return "", ACMEAccountKeyEnvelope{}, fmt.Errorf("gateway tls: encode ACME account key envelope: %w", err)
	}
	encoded = append(encoded, '\n')

	stateRoot, err := prepareACMEAccountStateRoot(root, true)
	if err != nil {
		return "", ACMEAccountKeyEnvelope{}, err
	}
	path := acmeAccountEnvelopePath(stateRoot, directory)
	if err := writeExclusivePrivateFile(path, encoded); err != nil {
		return "", ACMEAccountKeyEnvelope{}, err
	}
	return path, envelope, nil
}

// LoadEncryptedACMEAccountKey loads only the envelope bound to directoryURL.
// The wrapping key is never persisted by this package.
func LoadEncryptedACMEAccountKey(root string, wrappingKey []byte, directoryURL string) (crypto.Signer, ACMEAccountKeyEnvelope, error) {
	var envelope ACMEAccountKeyEnvelope
	if len(wrappingKey) != 32 {
		return nil, envelope, errors.New("gateway tls: ACME account wrapping key must be exactly 32 bytes")
	}
	directory, err := normalizeACMEDirectoryURL(directoryURL)
	if err != nil {
		return nil, envelope, err
	}
	stateRoot, err := prepareACMEAccountStateRoot(root, false)
	if err != nil {
		return nil, envelope, err
	}
	path := acmeAccountEnvelopePath(stateRoot, directory)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, envelope, fmt.Errorf("gateway tls: inspect ACME account key envelope: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, envelope, errors.New("gateway tls: ACME account key envelope must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o100 != 0 {
		return nil, envelope, errors.New("gateway tls: ACME account key envelope permissions are too broad")
	}
	if info.Size() <= 0 || info.Size() > maxACMEAccountEnvelopeBytes {
		return nil, envelope, errors.New("gateway tls: ACME account key envelope size is invalid")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, envelope, fmt.Errorf("gateway tls: read ACME account key envelope: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, ACMEAccountKeyEnvelope{}, fmt.Errorf("gateway tls: decode ACME account key envelope: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ACMEAccountKeyEnvelope{}, errors.New("gateway tls: ACME account key envelope contains trailing data")
	}
	if err := validateACMEAccountKeyEnvelope(envelope, directory); err != nil {
		return nil, ACMEAccountKeyEnvelope{}, err
	}

	nonce, err := base64.RawStdEncoding.DecodeString(envelope.NonceBase64)
	if err != nil {
		return nil, ACMEAccountKeyEnvelope{}, errors.New("gateway tls: ACME account envelope nonce is invalid")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(envelope.CiphertextBase64)
	if err != nil {
		return nil, ACMEAccountKeyEnvelope{}, errors.New("gateway tls: ACME account envelope ciphertext is invalid")
	}
	defer clear(ciphertext)

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, ACMEAccountKeyEnvelope{}, fmt.Errorf("gateway tls: initialize ACME account envelope cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ACMEAccountKeyEnvelope{}, fmt.Errorf("gateway tls: initialize ACME account envelope AEAD: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ACMEAccountKeyEnvelope{}, errors.New("gateway tls: ACME account envelope nonce length is invalid")
	}
	privateDER, err := aead.Open(nil, nonce, ciphertext, acmeAccountEnvelopeAAD(envelope))
	if err != nil {
		return nil, ACMEAccountKeyEnvelope{}, errors.New("gateway tls: ACME account key envelope authentication failed")
	}
	defer clear(privateDER)

	parsed, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, ACMEAccountKeyEnvelope{}, errors.New("gateway tls: ACME account private key payload is invalid")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, ACMEAccountKeyEnvelope{}, errors.New("gateway tls: ACME account private key payload is not a signer")
	}
	keyType, fingerprint, err := describeACMEAccountSigner(signer)
	if err != nil {
		return nil, ACMEAccountKeyEnvelope{}, err
	}
	if keyType != envelope.KeyType || fingerprint != envelope.PublicKeySHA256 {
		return nil, ACMEAccountKeyEnvelope{}, errors.New("gateway tls: ACME account key envelope public identity mismatch")
	}
	return signer, envelope, nil
}

func normalizeACMEDirectoryURL(raw string) (string, error) {
	directory, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || directory.Scheme != "https" || directory.Host == "" || directory.User != nil || directory.RawQuery != "" || directory.Fragment != "" {
		return "", errors.New("gateway tls: ACME directory must be an absolute HTTPS URL")
	}
	return directory.String(), nil
}

func describeACMEAccountSigner(accountKey crypto.Signer) (string, string, error) {
	if accountKey == nil {
		return "", "", errors.New("gateway tls: ACME account key is required")
	}
	var keyType string
	switch key := accountKey.Public().(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			keyType = "ECDSA-P256"
		case elliptic.P384():
			keyType = "ECDSA-P384"
		case elliptic.P521():
			keyType = "ECDSA-P521"
		default:
			return "", "", errors.New("gateway tls: ACME account ECDSA curve is unsupported")
		}
	case *rsa.PublicKey:
		if key.N == nil || key.N.BitLen() < 2048 {
			return "", "", errors.New("gateway tls: ACME account RSA key must be at least 2048 bits")
		}
		keyType = fmt.Sprintf("RSA-%d", key.N.BitLen())
	default:
		return "", "", errors.New("gateway tls: ACME account key must be ECDSA or RSA")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(accountKey.Public())
	if err != nil {
		return "", "", fmt.Errorf("gateway tls: encode ACME account public key: %w", err)
	}
	digest := sha256.Sum256(publicDER)
	return keyType, hex.EncodeToString(digest[:]), nil
}

func validateACMEAccountKeyEnvelope(envelope ACMEAccountKeyEnvelope, expectedDirectory string) error {
	if envelope.Schema != ACMEAccountKeyEnvelopeSchemaV1 {
		return errors.New("gateway tls: unsupported ACME account key envelope schema")
	}
	if envelope.DirectoryURL != expectedDirectory {
		return errors.New("gateway tls: ACME account key envelope directory does not match requested CA")
	}
	if _, err := time.Parse(time.RFC3339Nano, envelope.CreatedAt); err != nil {
		return errors.New("gateway tls: ACME account key envelope creation time is invalid")
	}
	if envelope.Algorithm != acmeAccountEnvelopeAlgorithm {
		return errors.New("gateway tls: unsupported ACME account key envelope algorithm")
	}
	if strings.TrimSpace(envelope.KeyType) == "" {
		return errors.New("gateway tls: ACME account key envelope key type is required")
	}
	if len(envelope.PublicKeySHA256) != 64 {
		return errors.New("gateway tls: ACME account key envelope public fingerprint is invalid")
	}
	if _, err := hex.DecodeString(envelope.PublicKeySHA256); err != nil || envelope.PublicKeySHA256 != strings.ToLower(envelope.PublicKeySHA256) {
		return errors.New("gateway tls: ACME account key envelope public fingerprint is invalid")
	}
	if envelope.NonceBase64 == "" || envelope.CiphertextBase64 == "" {
		return errors.New("gateway tls: ACME account key envelope encrypted payload is incomplete")
	}
	if envelope.ProductionCutoverAuthorized {
		return errors.New("gateway tls: ACME account key envelope cannot authorize production cutover")
	}
	return nil
}

func acmeAccountEnvelopeAAD(envelope ACMEAccountKeyEnvelope) []byte {
	return []byte(strings.Join([]string{
		envelope.Schema,
		envelope.DirectoryURL,
		envelope.CreatedAt,
		envelope.Algorithm,
		envelope.KeyType,
		envelope.PublicKeySHA256,
	}, "\n"))
}

func acmeAccountEnvelopePath(root, directoryURL string) string {
	digest := sha256.Sum256([]byte(directoryURL))
	return filepath.Join(root, "account-"+hex.EncodeToString(digest[:8])+".json")
}

func prepareACMEAccountStateRoot(root string, create bool) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", errors.New("gateway tls: ACME account state root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("gateway tls: resolve ACME account state root: %w", err)
	}
	if create {
		if err := os.MkdirAll(absolute, 0o700); err != nil {
			return "", fmt.Errorf("gateway tls: create ACME account state root: %w", err)
		}
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("gateway tls: inspect ACME account state root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("gateway tls: ACME account state root must be a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("gateway tls: ACME account state root permissions are too broad")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("gateway tls: resolve ACME account state root symlinks: %w", err)
	}
	if filepath.Clean(resolved) != filepath.Clean(absolute) {
		return "", errors.New("gateway tls: ACME account state root path contains a symbolic link")
	}
	return absolute, nil
}

func writeExclusivePrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("gateway tls: ACME account key envelope already exists; replacement requires explicit key rollover")
		}
		return fmt.Errorf("gateway tls: create ACME account key envelope: %w", err)
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("gateway tls: write ACME account key envelope: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("gateway tls: sync ACME account key envelope: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("gateway tls: close ACME account key envelope: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("gateway tls: open ACME account state directory for sync: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("gateway tls: sync ACME account state directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("gateway tls: close ACME account state directory: %w", err)
	}
	complete = true
	return nil
}
