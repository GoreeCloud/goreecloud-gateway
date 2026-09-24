package tlsconfig

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrepareAndLoadACMEAccountKeyRolloverRoundTrip(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x71)
	defer clear(wrapping)
	activeKey, err := GenerateACMEAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	_, activeEnvelope, err := SaveEncryptedACMEAccountKey(
		root,
		activeKey,
		wrapping,
		"https://acme.example/directory",
		time.Date(2026, 9, 18, 18, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}

	path, bundle, err := PrepareACMEAccountKeyRollover(
		root,
		wrapping,
		"https://acme.example/directory",
		time.Date(2026, 9, 18, 18, 5, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.OldAccountPublicKeySHA256 != activeEnvelope.PublicKeySHA256 {
		t.Fatal("rollover bundle did not bind active account identity")
	}
	if bundle.NewAccountPublicKeySHA256 == activeEnvelope.PublicKeySHA256 || bundle.ProductionCutoverAuthorized {
		t.Fatalf("unexpected rollover bundle: %+v", bundle)
	}
	if filepath.Dir(path) != root {
		t.Fatalf("rollover bundle escaped state root: %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("rollover bundle mode=%o", info.Mode().Perm())
	}

	newKey, loaded, err := LoadPreparedACMEAccountKeyRollover(
		root,
		path,
		wrapping,
		"https://acme.example/directory",
	)
	if err != nil {
		t.Fatal(err)
	}
	_, fingerprint, err := describeACMEAccountSigner(newKey)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != loaded.NewAccountPublicKeySHA256 {
		t.Fatal("decrypted rollover key fingerprint mismatch")
	}
}

func TestPreparedACMERolloverRejectsActiveAccountDrift(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x72)
	defer clear(wrapping)
	activeKey, _ := GenerateACMEAccountKey()
	activePath, _, err := SaveEncryptedACMEAccountKey(root, activeKey, wrapping, "https://acme.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	bundlePath, _, err := PrepareACMEAccountKeyRollover(root, wrapping, "https://acme.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(activePath); err != nil {
		t.Fatal(err)
	}
	replacementActive, _ := GenerateACMEAccountKey()
	if _, _, err := SaveEncryptedACMEAccountKey(root, replacementActive, wrapping, "https://acme.example/directory", time.Now().UTC().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPreparedACMEAccountKeyRollover(root, bundlePath, wrapping, "https://acme.example/directory"); err == nil {
		t.Fatal("stale rollover bundle unexpectedly accepted after active account drift")
	}
}

func TestPreparedACMERolloverRejectsWrongWrappingKey(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x73)
	activeKey, _ := GenerateACMEAccountKey()
	if _, _, err := SaveEncryptedACMEAccountKey(root, activeKey, wrapping, "https://acme.example/directory", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	path, _, err := PrepareACMEAccountKeyRollover(root, wrapping, "https://acme.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	wrong := wrappingKey(0x74)
	defer clear(wrong)
	if _, _, err := LoadPreparedACMEAccountKeyRollover(root, path, wrong, "https://acme.example/directory"); err == nil {
		t.Fatal("wrong wrapping key unexpectedly loaded rollover bundle")
	}
}

func TestPreparedACMERolloverRejectsTamperedMetadata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x75)
	defer clear(wrapping)
	activeKey, _ := GenerateACMEAccountKey()
	if _, _, err := SaveEncryptedACMEAccountKey(root, activeKey, wrapping, "https://acme.example/directory", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	path, _, err := PrepareACMEAccountKeyRollover(root, wrapping, "https://acme.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var bundle ACMEAccountRolloverBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle.PreparedAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	modified, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPreparedACMEAccountKeyRollover(root, path, wrapping, "https://acme.example/directory"); err == nil {
		t.Fatal("tampered rollover bundle unexpectedly authenticated")
	}
}

func TestPreparedACMERolloverRejectsBundleOutsideStateRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x76)
	defer clear(wrapping)
	activeKey, _ := GenerateACMEAccountKey()
	if _, _, err := SaveEncryptedACMEAccountKey(root, activeKey, wrapping, "https://acme.example/directory", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	path, _, err := PrepareACMEAccountKeyRollover(root, wrapping, "https://acme.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "rollover.json")
	if err := os.WriteFile(outside, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPreparedACMEAccountKeyRollover(root, outside, wrapping, "https://acme.example/directory"); err == nil {
		t.Fatal("rollover bundle outside state root unexpectedly accepted")
	}
}

func TestPreparedACMERolloverRejectsBroadPermissionsAndSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x77)
	defer clear(wrapping)
	activeKey, _ := GenerateACMEAccountKey()
	if _, _, err := SaveEncryptedACMEAccountKey(root, activeKey, wrapping, "https://acme.example/directory", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	path, _, err := PrepareACMEAccountKeyRollover(root, wrapping, "https://acme.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPreparedACMEAccountKeyRollover(root, path, wrapping, "https://acme.example/directory"); err == nil {
		t.Fatal("broad rollover bundle permissions unexpectedly accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	realPath := path + ".real"
	if err := os.Rename(path, realPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := LoadPreparedACMEAccountKeyRollover(root, path, wrapping, "https://acme.example/directory"); err == nil {
		t.Fatal("symlink rollover bundle unexpectedly accepted")
	}
}

func TestPreparedACMERolloverCiphertextDoesNotContainPlainPrivateKeyMarker(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x78)
	defer clear(wrapping)
	activeKey, _ := GenerateACMEAccountKey()
	if _, _, err := SaveEncryptedACMEAccountKey(root, activeKey, wrapping, "https://acme.example/directory", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	path, _, err := PrepareACMEAccountKeyRollover(root, wrapping, "https://acme.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		t.Fatal("rollover bundle contains plaintext private-key marker")
	}
}
