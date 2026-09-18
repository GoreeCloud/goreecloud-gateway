package tlsconfig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ACMEAccountKeyRolloverReceiptSchemaV1 = "goreecloud-gateway-acme-account-key-rollover-receipt/v1"

type ACMEAccountKeyRolloverReceipt struct {
	Schema                      string `json:"schema"`
	DirectoryURL                string `json:"directory_url"`
	CompletedAt                 string `json:"completed_at"`
	OldAccountPublicKeySHA256   string `json:"old_account_public_key_sha256"`
	NewAccountPublicKeySHA256   string `json:"new_account_public_key_sha256"`
	RetiredEnvelopeFile         string `json:"retired_envelope_file"`
	PreparedBundleFile          string `json:"prepared_bundle_file"`
	ProductionCutoverAuthorized bool   `json:"production_cutover_authorized"`
}

type acmeAccountKeyRolloverClient interface {
	AccountKeyRollover(context.Context, crypto.Signer) error
}

// ExecutePreparedACMEAccountKeyRollover performs the RFC 8555 account-key
// rollover using an already prepared encrypted replacement-key bundle.
//
// Before any CA mutation, Gateway writes two recoverable local artifacts:
// an immutable encrypted copy of the old active envelope and a complete staged
// replacement active envelope. Only then is the CA rollover request sent.
// CA failure removes the staged replacement and leaves the active envelope
// unchanged. CA success is followed by an atomic same-directory rename over
// the active envelope.
//
// This function does not authorize production cutover and it does not delete
// the prepared bundle or retired envelope after success.
func ExecutePreparedACMEAccountKeyRollover(
	ctx context.Context,
	root string,
	bundlePath string,
	wrappingKey []byte,
	directoryURL string,
	httpClient *http.Client,
	now time.Time,
) (ACMEAccountKeyRolloverReceipt, error) {
	var receipt ACMEAccountKeyRolloverReceipt
	if ctx == nil {
		return receipt, errors.New("gateway tls: ACME account-key rollover context is required")
	}
	if err := ctx.Err(); err != nil {
		return receipt, fmt.Errorf("gateway tls: ACME account-key rollover context unavailable: %w", err)
	}
	activeKey, _, err := LoadEncryptedACMEAccountKey(root, wrappingKey, directoryURL)
	if err != nil {
		return receipt, fmt.Errorf("gateway tls: load active ACME account key for rollover client: %w", err)
	}
	client, err := newACMEProtocolClient(activeKey, directoryURL, httpClient)
	if err != nil {
		return receipt, err
	}
	return executePreparedACMEAccountKeyRollover(ctx, root, bundlePath, wrappingKey, directoryURL, client, now)
}

func executePreparedACMEAccountKeyRollover(
	ctx context.Context,
	root string,
	bundlePath string,
	wrappingKey []byte,
	directoryURL string,
	client acmeAccountKeyRolloverClient,
	now time.Time,
) (ACMEAccountKeyRolloverReceipt, error) {
	var receipt ACMEAccountKeyRolloverReceipt
	if client == nil {
		return receipt, errors.New("gateway tls: ACME account-key rollover client is required")
	}
	if ctx == nil {
		return receipt, errors.New("gateway tls: ACME account-key rollover context is required")
	}
	if err := ctx.Err(); err != nil {
		return receipt, fmt.Errorf("gateway tls: ACME account-key rollover context unavailable: %w", err)
	}
	if len(wrappingKey) != 32 {
		return receipt, errors.New("gateway tls: ACME account wrapping key must be exactly 32 bytes")
	}
	if now.IsZero() {
		return receipt, errors.New("gateway tls: ACME account-key rollover completion time is required")
	}

	directory, err := normalizeACMEDirectoryURL(directoryURL)
	if err != nil {
		return receipt, err
	}
	stateRoot, err := prepareACMEAccountStateRoot(root, false)
	if err != nil {
		return receipt, err
	}

	newKey, bundle, err := LoadPreparedACMEAccountKeyRollover(stateRoot, bundlePath, wrappingKey, directory)
	if err != nil {
		return receipt, err
	}
	activePath := acmeAccountEnvelopePath(stateRoot, directory)
	activeBytes, activeEnvelope, err := readActiveAccountEnvelopeBytes(activePath, directory)
	if err != nil {
		return receipt, err
	}
	if activeEnvelope.PublicKeySHA256 != bundle.OldAccountPublicKeySHA256 {
		return receipt, errors.New("gateway tls: active ACME account identity changed before rollover staging")
	}

	retiredPath := acmeRetiredAccountEnvelopePath(stateRoot, directory, bundle.OldAccountPublicKeySHA256, bundle.NewAccountPublicKeySHA256)
	if err := ensureEncryptedRetiredAccountSnapshot(retiredPath, activeBytes); err != nil {
		return receipt, err
	}

	pendingPath := acmePendingAccountEnvelopePath(stateRoot, directory, bundle.NewAccountPublicKeySHA256)
	if _, err := os.Lstat(pendingPath); err == nil {
		return receipt, errors.New("gateway tls: pending ACME account activation already exists; recover or remove it before another CA rollover attempt")
	} else if !errors.Is(err, os.ErrNotExist) {
		return receipt, fmt.Errorf("gateway tls: inspect pending ACME account activation: %w", err)
	}

	pendingEnvelope, pendingBytes, err := buildEncryptedACMEAccountEnvelope(newKey, wrappingKey, directory, now)
	if err != nil {
		return receipt, err
	}
	if pendingEnvelope.PublicKeySHA256 != bundle.NewAccountPublicKeySHA256 {
		return receipt, errors.New("gateway tls: prepared replacement key does not match staged active envelope")
	}
	if err := writeExclusivePrivateFile(pendingPath, pendingBytes); err != nil {
		return receipt, fmt.Errorf("gateway tls: stage replacement ACME account envelope: %w", err)
	}

	caSucceeded := false
	defer func() {
		if !caSucceeded {
			_ = os.Remove(pendingPath)
		}
	}()

	if err := client.AccountKeyRollover(ctx, newKey); err != nil {
		return receipt, fmt.Errorf("gateway tls: ACME account-key rollover rejected by CA: %w", err)
	}
	caSucceeded = true

	if err := os.Rename(pendingPath, activePath); err != nil {
		return receipt, fmt.Errorf("gateway tls: CA account-key rollover succeeded but local active-envelope activation failed; prepared and pending replacement state remain for recovery: %w", err)
	}
	if err := syncDirectory(stateRoot); err != nil {
		return receipt, fmt.Errorf("gateway tls: CA account-key rollover succeeded and active envelope was replaced, but directory durability confirmation failed: %w", err)
	}

	return ACMEAccountKeyRolloverReceipt{
		Schema:                      ACMEAccountKeyRolloverReceiptSchemaV1,
		DirectoryURL:                directory,
		CompletedAt:                 now.UTC().Format(time.RFC3339Nano),
		OldAccountPublicKeySHA256:   bundle.OldAccountPublicKeySHA256,
		NewAccountPublicKeySHA256:   bundle.NewAccountPublicKeySHA256,
		RetiredEnvelopeFile:         filepath.Base(retiredPath),
		PreparedBundleFile:          filepath.Base(bundlePath),
		ProductionCutoverAuthorized: false,
	}, nil
}

func buildEncryptedACMEAccountEnvelope(accountKey crypto.Signer, wrappingKey []byte, directory string, createdAt time.Time) (ACMEAccountKeyEnvelope, []byte, error) {
	var envelope ACMEAccountKeyEnvelope
	if len(wrappingKey) != 32 {
		return envelope, nil, errors.New("gateway tls: ACME account wrapping key must be exactly 32 bytes")
	}
	if createdAt.IsZero() {
		return envelope, nil, errors.New("gateway tls: ACME account envelope creation time is required")
	}
	keyType, fingerprint, err := describeACMEAccountSigner(accountKey)
	if err != nil {
		return envelope, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(accountKey)
	if err != nil {
		return envelope, nil, fmt.Errorf("gateway tls: encode ACME account private key: %w", err)
	}
	defer clear(privateDER)

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return envelope, nil, fmt.Errorf("gateway tls: initialize ACME account envelope cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return envelope, nil, fmt.Errorf("gateway tls: initialize ACME account envelope AEAD: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return envelope, nil, fmt.Errorf("gateway tls: generate ACME account envelope nonce: %w", err)
	}

	envelope = ACMEAccountKeyEnvelope{
		Schema:                      ACMEAccountKeyEnvelopeSchemaV1,
		DirectoryURL:                directory,
		CreatedAt:                   createdAt.UTC().Format(time.RFC3339Nano),
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
		return ACMEAccountKeyEnvelope{}, nil, fmt.Errorf("gateway tls: encode ACME account envelope: %w", err)
	}
	return envelope, append(encoded, '\n'), nil
}

func readActiveAccountEnvelopeBytes(path, directory string) ([]byte, ACMEAccountKeyEnvelope, error) {
	var envelope ACMEAccountKeyEnvelope
	info, err := os.Lstat(path)
	if err != nil {
		return nil, envelope, fmt.Errorf("gateway tls: inspect active ACME account envelope: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, envelope, errors.New("gateway tls: active ACME account envelope must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o100 != 0 {
		return nil, envelope, errors.New("gateway tls: active ACME account envelope permissions are too broad")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, envelope, fmt.Errorf("gateway tls: read active ACME account envelope: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, envelope, fmt.Errorf("gateway tls: decode active ACME account envelope: %w", err)
	}
	if err := validateACMEAccountKeyEnvelope(envelope, directory); err != nil {
		return nil, envelope, err
	}
	return data, envelope, nil
}

func ensureEncryptedRetiredAccountSnapshot(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o100 != 0 {
			return errors.New("gateway tls: existing retired ACME account envelope is not a protected regular file")
		}
		existing, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("gateway tls: read existing retired ACME account envelope: %w", err)
		}
		if !bytes.Equal(existing, data) {
			return errors.New("gateway tls: existing retired ACME account envelope does not match current active envelope")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("gateway tls: inspect retired ACME account envelope: %w", err)
	}
	if err := writeExclusivePrivateFile(path, data); err != nil {
		return fmt.Errorf("gateway tls: persist retired ACME account envelope: %w", err)
	}
	return nil
}

func acmeRetiredAccountEnvelopePath(root, directory, oldFingerprint, newFingerprint string) string {
	digest := accountDirectoryDigest(directory)
	return filepath.Join(root, "retired-"+digest+"-"+oldFingerprint[:12]+"-to-"+newFingerprint[:12]+".json")
}

func acmePendingAccountEnvelopePath(root, directory, newFingerprint string) string {
	digest := accountDirectoryDigest(directory)
	return filepath.Join(root, "pending-active-"+digest+"-"+newFingerprint[:16]+".json")
}

func accountDirectoryDigest(directory string) string {
	sum := sha256Sum([]byte(directory))
	return sum[:16]
}

func sha256Sum(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("gateway tls: open ACME account state directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("gateway tls: sync ACME account state directory: %w", err)
	}
	return nil
}
