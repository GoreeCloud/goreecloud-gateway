package tlsconfig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func wrappingKey(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, 32)
}

func TestEncryptedACMEAccountKeyRoundTrip(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	key, err := GenerateACMEAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	path, envelope, err := SaveEncryptedACMEAccountKey(
		root,
		key,
		wrappingKey(0x41),
		"https://acme.example/directory",
		time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.ProductionCutoverAuthorized {
		t.Fatal("account envelope unexpectedly authorized production cutover")
	}
	if filepath.Dir(path) != root {
		t.Fatalf("account envelope path escaped root: %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("account envelope mode=%o", info.Mode().Perm())
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("PRIVATE KEY")) {
		t.Fatal("account envelope contains plaintext PEM material")
	}

	loaded, loadedEnvelope, err := LoadEncryptedACMEAccountKey(root, wrappingKey(0x41), "https://acme.example/directory")
	if err != nil {
		t.Fatal(err)
	}
	_, originalFingerprint, err := describeACMEAccountSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	_, loadedFingerprint, err := describeACMEAccountSigner(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if originalFingerprint != loadedFingerprint || loadedEnvelope.PublicKeySHA256 != originalFingerprint {
		t.Fatal("loaded ACME account key identity mismatch")
	}
}

func TestEncryptedACMEAccountKeyNeverOverwritesExistingState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	first, _ := GenerateACMEAccountKey()
	second, _ := GenerateACMEAccountKey()
	now := time.Now().UTC()

	if _, _, err := SaveEncryptedACMEAccountKey(root, first, wrappingKey(1), "https://acme.example/directory", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SaveEncryptedACMEAccountKey(root, second, wrappingKey(1), "https://acme.example/directory", now.Add(time.Second)); err == nil {
		t.Fatal("existing ACME account state was unexpectedly overwritable")
	}
	loaded, _, err := LoadEncryptedACMEAccountKey(root, wrappingKey(1), "https://acme.example/directory")
	if err != nil {
		t.Fatal(err)
	}
	_, firstFingerprint, _ := describeACMEAccountSigner(first)
	_, loadedFingerprint, _ := describeACMEAccountSigner(loaded)
	if firstFingerprint != loadedFingerprint {
		t.Fatal("failed overwrite changed persisted account key")
	}
}

func TestEncryptedACMEAccountKeyRejectsWrongWrappingKey(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	key, _ := GenerateACMEAccountKey()
	if _, _, err := SaveEncryptedACMEAccountKey(root, key, wrappingKey(2), "https://acme.example/directory", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadEncryptedACMEAccountKey(root, wrappingKey(3), "https://acme.example/directory"); err == nil {
		t.Fatal("wrong wrapping key unexpectedly decrypted ACME account state")
	}
}

func TestEncryptedACMEAccountKeyIsBoundToDirectoryURL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	key, _ := GenerateACMEAccountKey()
	if _, _, err := SaveEncryptedACMEAccountKey(root, key, wrappingKey(4), "https://acme.example/directory", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadEncryptedACMEAccountKey(root, wrappingKey(4), "https://other.example/directory"); err == nil {
		t.Fatal("ACME account state unexpectedly loaded for a different CA directory")
	}
}

func TestEncryptedACMEAccountKeyRejectsTampering(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	key, _ := GenerateACMEAccountKey()
	path, _, err := SaveEncryptedACMEAccountKey(root, key, wrappingKey(5), "https://acme.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope ACMEAccountKeyEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.CreatedAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	modified, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadEncryptedACMEAccountKey(root, wrappingKey(5), "https://acme.example/directory"); err == nil {
		t.Fatal("tampered ACME account envelope unexpectedly authenticated")
	}
}

func TestEncryptedACMEAccountKeyRejectsBroadPermissions(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	key, _ := GenerateACMEAccountKey()
	path, _, err := SaveEncryptedACMEAccountKey(root, key, wrappingKey(6), "https://acme.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadEncryptedACMEAccountKey(root, wrappingKey(6), "https://acme.example/directory"); err == nil {
		t.Fatal("broad ACME account envelope permissions unexpectedly accepted")
	}
}

func TestEncryptedACMEAccountKeyRejectsSymlinkEnvelope(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	key, _ := GenerateACMEAccountKey()
	path, _, err := SaveEncryptedACMEAccountKey(root, key, wrappingKey(7), "https://acme.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	realPath := path + ".real"
	if err := os.Rename(path, realPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := LoadEncryptedACMEAccountKey(root, wrappingKey(7), "https://acme.example/directory"); err == nil {
		t.Fatal("symlink ACME account envelope unexpectedly accepted")
	}
}

func TestSaveEncryptedACMEAccountKeyRejectsInsecureStateRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "accounts")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	key, _ := GenerateACMEAccountKey()
	if _, _, err := SaveEncryptedACMEAccountKey(root, key, wrappingKey(8), "https://acme.example/directory", time.Now().UTC()); err == nil {
		t.Fatal("insecure ACME account state root unexpectedly accepted")
	}
}

func TestDescribeACMEAccountSignerAcceptsP256AndRejectsWeakRSA(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := describeACMEAccountSigner(p256); err != nil {
		t.Fatalf("P-256 account key rejected: %v", err)
	}
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := describeACMEAccountSigner(weakRSA); err == nil {
		t.Fatal("1024-bit RSA ACME account key unexpectedly accepted")
	}
}

func TestEncryptedACMEAccountKeyEnvelopeSupportsOfflineBackupRestore(t *testing.T) {
	sourceRoot := filepath.Join(t.TempDir(), "source")
	restoreRoot := filepath.Join(t.TempDir(), "restore")
	key, err := GenerateACMEAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapping := wrappingKey(0x55)
	defer clear(wrapping)
	sourcePath, _, err := SaveEncryptedACMEAccountKey(
		sourceRoot,
		key,
		wrapping,
		"https://acme.example/directory",
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	backupBytes, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(restoreRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	restorePath := filepath.Join(restoreRoot, filepath.Base(sourcePath))
	if err := os.WriteFile(restorePath, backupBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	restored, _, err := LoadEncryptedACMEAccountKey(restoreRoot, wrapping, "https://acme.example/directory")
	if err != nil {
		t.Fatal(err)
	}
	_, originalFingerprint, err := describeACMEAccountSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	_, restoredFingerprint, err := describeACMEAccountSigner(restored)
	if err != nil {
		t.Fatal(err)
	}
	if originalFingerprint != restoredFingerprint {
		t.Fatal("offline restored ACME account key identity mismatch")
	}
}
