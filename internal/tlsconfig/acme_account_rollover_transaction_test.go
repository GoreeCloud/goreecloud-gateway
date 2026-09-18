package tlsconfig

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeAccountKeyRolloverClient struct {
	calls       int
	err         error
	onRollover  func(crypto.Signer)
}

func (c *fakeAccountKeyRolloverClient) AccountKeyRollover(_ context.Context, newKey crypto.Signer) error {
	c.calls++
	if c.onRollover != nil {
		c.onRollover(newKey)
	}
	return c.err
}

func TestExecutePreparedACMEAccountKeyRolloverStagesRecoveryBeforeCAAndActivatesAtomically(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x81)
	defer clear(wrapping)
	directory := "https://acme.example/directory"
	oldKey, _ := GenerateACMEAccountKey()
	activePath, oldEnvelope, err := SaveEncryptedACMEAccountKey(root, oldKey, wrapping, directory, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	oldBytes, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath, bundle, err := PrepareACMEAccountKeyRollover(root, wrapping, directory, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	client := &fakeAccountKeyRolloverClient{}
	client.onRollover = func(newKey crypto.Signer) {
		pending := acmePendingAccountEnvelopePath(root, directory, bundle.NewAccountPublicKeySHA256)
		if info, err := os.Stat(pending); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("replacement active envelope was not staged before CA mutation: info=%v err=%v", info, err)
		}
		retired := acmeRetiredAccountEnvelopePath(root, directory, bundle.OldAccountPublicKeySHA256, bundle.NewAccountPublicKeySHA256)
		data, err := os.ReadFile(retired)
		if err != nil {
			t.Fatalf("retired envelope missing before CA mutation: %v", err)
		}
		if !bytes.Equal(data, oldBytes) {
			t.Fatal("retired envelope did not preserve exact old encrypted state")
		}
		_, fingerprint, err := describeACMEAccountSigner(newKey)
		if err != nil {
			t.Fatal(err)
		}
		if fingerprint != bundle.NewAccountPublicKeySHA256 {
			t.Fatal("CA rollover received unexpected replacement key")
		}
	}

	receipt, err := executePreparedACMEAccountKeyRollover(
		context.Background(),
		root,
		bundlePath,
		wrapping,
		directory,
		client,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if client.calls != 1 || receipt.ProductionCutoverAuthorized {
		t.Fatalf("unexpected rollover receipt/calls: %+v calls=%d", receipt, client.calls)
	}
	if receipt.OldAccountPublicKeySHA256 != oldEnvelope.PublicKeySHA256 || receipt.NewAccountPublicKeySHA256 != bundle.NewAccountPublicKeySHA256 {
		t.Fatalf("rollover receipt identity mismatch: %+v", receipt)
	}
	activeKey, activeEnvelope, err := LoadEncryptedACMEAccountKey(root, wrapping, directory)
	if err != nil {
		t.Fatal(err)
	}
	_, activeFingerprint, _ := describeACMEAccountSigner(activeKey)
	if activeFingerprint != bundle.NewAccountPublicKeySHA256 || activeEnvelope.PublicKeySHA256 != bundle.NewAccountPublicKeySHA256 {
		t.Fatal("replacement ACME account key was not activated")
	}
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatal("prepared rollover bundle was removed after success")
	}
	retiredPath := filepath.Join(root, receipt.RetiredEnvelopeFile)
	if data, err := os.ReadFile(retiredPath); err != nil || !bytes.Equal(data, oldBytes) {
		t.Fatalf("retired envelope unavailable after success: err=%v", err)
	}
}

func TestExecutePreparedACMEAccountKeyRolloverCAErrorLeavesActiveOldAndRetainsPendingForRecovery(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x82)
	defer clear(wrapping)
	directory := "https://acme.example/directory"
	oldKey, _ := GenerateACMEAccountKey()
	_, oldEnvelope, err := SaveEncryptedACMEAccountKey(root, oldKey, wrapping, directory, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	bundlePath, bundle, err := PrepareACMEAccountKeyRollover(root, wrapping, directory, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	client := &fakeAccountKeyRolloverClient{err: errors.New("CA rejected rollover")}
	if _, err := executePreparedACMEAccountKeyRollover(context.Background(), root, bundlePath, wrapping, directory, client, time.Now().UTC()); err == nil {
		t.Fatal("CA failure unexpectedly succeeded")
	}
	if client.calls != 1 {
		t.Fatalf("CA rollover calls=%d", client.calls)
	}
	_, activeEnvelope, err := LoadEncryptedACMEAccountKey(root, wrapping, directory)
	if err != nil {
		t.Fatal(err)
	}
	if activeEnvelope.PublicKeySHA256 != oldEnvelope.PublicKeySHA256 {
		t.Fatal("CA failure changed active account key")
	}
	pending := acmePendingAccountEnvelopePath(root, directory, bundle.NewAccountPublicKeySHA256)
	if info, err := os.Stat(pending); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("pending replacement was not retained after uncertain CA outcome: info=%v err=%v", info, err)
	}
	if _, err := executePreparedACMEAccountKeyRollover(context.Background(), root, bundlePath, wrapping, directory, client, time.Now().UTC()); err == nil {
		t.Fatal("unresolved pending activation unexpectedly allowed blind rollover replay")
	}
	if client.calls != 1 {
		t.Fatalf("CA rollover was replayed despite unresolved outcome: calls=%d", client.calls)
	}
}

func TestExecutePreparedACMEAccountKeyRolloverRefusesExistingPendingBeforeCA(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x83)
	defer clear(wrapping)
	directory := "https://acme.example/directory"
	oldKey, _ := GenerateACMEAccountKey()
	if _, _, err := SaveEncryptedACMEAccountKey(root, oldKey, wrapping, directory, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	bundlePath, bundle, err := PrepareACMEAccountKeyRollover(root, wrapping, directory, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	pending := acmePendingAccountEnvelopePath(root, directory, bundle.NewAccountPublicKeySHA256)
	if err := os.WriteFile(pending, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &fakeAccountKeyRolloverClient{}
	if _, err := executePreparedACMEAccountKeyRollover(context.Background(), root, bundlePath, wrapping, directory, client, time.Now().UTC()); err == nil {
		t.Fatal("existing pending activation unexpectedly allowed a CA call")
	}
	if client.calls != 0 {
		t.Fatalf("CA was called despite unresolved pending activation: %d", client.calls)
	}
}

func TestExecutePreparedACMEAccountKeyRolloverReusesMatchingRetiredSnapshot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x84)
	defer clear(wrapping)
	directory := "https://acme.example/directory"
	oldKey, _ := GenerateACMEAccountKey()
	activePath, _, err := SaveEncryptedACMEAccountKey(root, oldKey, wrapping, directory, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	activeBytes, _ := os.ReadFile(activePath)
	bundlePath, bundle, err := PrepareACMEAccountKeyRollover(root, wrapping, directory, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	retired := acmeRetiredAccountEnvelopePath(root, directory, bundle.OldAccountPublicKeySHA256, bundle.NewAccountPublicKeySHA256)
	if err := os.WriteFile(retired, activeBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	client := &fakeAccountKeyRolloverClient{}
	if _, err := executePreparedACMEAccountKeyRollover(context.Background(), root, bundlePath, wrapping, directory, client, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if client.calls != 1 {
		t.Fatalf("CA rollover calls=%d", client.calls)
	}
}

func TestExecutePreparedACMEAccountKeyRolloverRejectsConflictingRetiredSnapshotBeforeCA(t *testing.T) {
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x85)
	defer clear(wrapping)
	directory := "https://acme.example/directory"
	oldKey, _ := GenerateACMEAccountKey()
	if _, _, err := SaveEncryptedACMEAccountKey(root, oldKey, wrapping, directory, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	bundlePath, bundle, err := PrepareACMEAccountKeyRollover(root, wrapping, directory, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	retired := acmeRetiredAccountEnvelopePath(root, directory, bundle.OldAccountPublicKeySHA256, bundle.NewAccountPublicKeySHA256)
	if err := os.WriteFile(retired, []byte("conflict"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &fakeAccountKeyRolloverClient{}
	if _, err := executePreparedACMEAccountKeyRollover(context.Background(), root, bundlePath, wrapping, directory, client, time.Now().UTC()); err == nil {
		t.Fatal("conflicting retired snapshot unexpectedly accepted")
	}
	if client.calls != 0 {
		t.Fatalf("CA was called despite conflicting retired snapshot: %d", client.calls)
	}
}
