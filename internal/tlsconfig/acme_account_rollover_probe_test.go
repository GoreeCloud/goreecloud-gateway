package tlsconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

type fakeACMERecognitionClient struct {
	account *acme.Account
	err     error
	calls   int
}

func (c *fakeACMERecognitionClient) GetReg(context.Context, string) (*acme.Account, error) {
	c.calls++
	return c.account, c.err
}

func makeRolloverProbeState(t *testing.T) (string, []byte, string, string, ACMEAccountRolloverBundle) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "accounts")
	wrapping := wrappingKey(0x91)
	directory := "https://acme.example/directory"
	oldKey, err := GenerateACMEAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := SaveEncryptedACMEAccountKey(root, oldKey, wrapping, directory, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	bundlePath, bundle, err := PrepareACMEAccountKeyRollover(root, wrapping, directory, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	newKey, loadedBundle, err := LoadPreparedACMEAccountKeyRollover(root, bundlePath, wrapping, directory)
	if err != nil {
		t.Fatal(err)
	}
	pendingEnvelope, pendingBytes, err := buildEncryptedACMEAccountEnvelope(newKey, wrapping, directory, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if pendingEnvelope.PublicKeySHA256 != loadedBundle.NewAccountPublicKeySHA256 {
		t.Fatal("pending envelope identity mismatch in fixture")
	}
	pendingPath := acmePendingAccountEnvelopePath(root, directory, bundle.NewAccountPublicKeySHA256)
	if err := writeExclusivePrivateFile(pendingPath, pendingBytes); err != nil {
		t.Fatal(err)
	}
	return root, wrapping, directory, bundlePath, bundle
}

func TestRolloverProbeClassifiesOldAuthoritative(t *testing.T) {
	state := acmeAccountRolloverProbeState{
		directory:   "https://acme.example/directory",
		bundle:      ACMEAccountRolloverBundle{OldAccountPublicKeySHA256: "old", NewAccountPublicKeySHA256: "new"},
		pendingPath: "/state/pending.json",
		bundlePath:  "/state/bundle.json",
	}
	oldClient := &fakeACMERecognitionClient{account: &acme.Account{Status: acme.StatusValid}}
	newClient := &fakeACMERecognitionClient{err: acme.ErrNoAccount}
	report, err := probeACMEAccountRolloverAuthority(context.Background(), state, oldClient, newClient, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome != ACMERolloverAuthorityOld || report.OldKeyProbe != ACMEAccountProbeRecognized || report.NewKeyProbe != ACMEAccountProbeNotRecognized {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestRolloverProbeClassifiesNewAuthoritative(t *testing.T) {
	state := acmeAccountRolloverProbeState{
		directory:   "https://acme.example/directory",
		bundle:      ACMEAccountRolloverBundle{OldAccountPublicKeySHA256: "old", NewAccountPublicKeySHA256: "new"},
		pendingPath: "/state/pending.json",
		bundlePath:  "/state/bundle.json",
	}
	oldClient := &fakeACMERecognitionClient{err: acme.ErrNoAccount}
	newClient := &fakeACMERecognitionClient{account: &acme.Account{Status: acme.StatusValid}}
	report, err := probeACMEAccountRolloverAuthority(context.Background(), state, oldClient, newClient, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome != ACMERolloverAuthorityNew {
		t.Fatalf("outcome=%q", report.Outcome)
	}
}

func TestRolloverProbeClassifiesBothAndNeitherWithoutGuessing(t *testing.T) {
	for _, tc := range []struct {
		name string
		old  *fakeACMERecognitionClient
		new  *fakeACMERecognitionClient
		want string
	}{
		{
			name: "both",
			old:  &fakeACMERecognitionClient{account: &acme.Account{Status: acme.StatusValid}},
			new:  &fakeACMERecognitionClient{account: &acme.Account{Status: acme.StatusValid}},
			want: ACMERolloverAuthorityBoth,
		},
		{
			name: "neither",
			old:  &fakeACMERecognitionClient{err: acme.ErrNoAccount},
			new:  &fakeACMERecognitionClient{err: acme.ErrNoAccount},
			want: ACMERolloverAuthorityNeither,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := acmeAccountRolloverProbeState{
				directory:   "https://acme.example/directory",
				bundle:      ACMEAccountRolloverBundle{OldAccountPublicKeySHA256: "old", NewAccountPublicKeySHA256: "new"},
				pendingPath: "/state/pending.json",
				bundlePath:  "/state/bundle.json",
			}
			report, err := probeACMEAccountRolloverAuthority(context.Background(), state, tc.old, tc.new, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if report.Outcome != tc.want {
				t.Fatalf("outcome=%q want=%q", report.Outcome, tc.want)
			}
		})
	}
}

func TestRolloverProbeTransportErrorIsInconclusive(t *testing.T) {
	state := acmeAccountRolloverProbeState{
		directory:   "https://acme.example/directory",
		bundle:      ACMEAccountRolloverBundle{OldAccountPublicKeySHA256: "old", NewAccountPublicKeySHA256: "new"},
		pendingPath: "/state/pending.json",
		bundlePath:  "/state/bundle.json",
	}
	oldClient := &fakeACMERecognitionClient{err: errors.New("network unavailable")}
	newClient := &fakeACMERecognitionClient{account: &acme.Account{Status: acme.StatusValid}}
	report, err := probeACMEAccountRolloverAuthority(context.Background(), state, oldClient, newClient, time.Now().UTC())
	if err == nil {
		t.Fatal("transport failure unexpectedly produced authoritative result")
	}
	if report.Outcome != ACMERolloverAuthorityUnknown || report.OldKeyProbe != ACMEAccountProbeInconclusive {
		t.Fatalf("unexpected report: %+v", report)
	}
	if oldClient.calls != 1 || newClient.calls != 1 {
		t.Fatalf("probe did not collect both sides: old=%d new=%d", oldClient.calls, newClient.calls)
	}
}

func TestRolloverProbeStateRequiresMatchingPendingEnvelope(t *testing.T) {
	root, wrapping, directory, bundlePath, bundle := makeRolloverProbeState(t)
	defer clear(wrapping)
	state, err := loadACMEAccountRolloverProbeState(root, bundlePath, wrapping, directory)
	if err != nil {
		t.Fatal(err)
	}
	if state.bundle.NewAccountPublicKeySHA256 != bundle.NewAccountPublicKeySHA256 || state.pendingEnvelope.PublicKeySHA256 != bundle.NewAccountPublicKeySHA256 {
		t.Fatal("probe state did not preserve replacement identity")
	}
}

func TestRolloverProbeStateRejectsMissingPendingEnvelope(t *testing.T) {
	root, wrapping, directory, bundlePath, bundle := makeRolloverProbeState(t)
	defer clear(wrapping)
	pending := acmePendingAccountEnvelopePath(root, directory, bundle.NewAccountPublicKeySHA256)
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	if _, err := loadACMEAccountRolloverProbeState(root, bundlePath, wrapping, directory); err == nil {
		t.Fatal("probe state unexpectedly accepted missing pending envelope")
	}
}

func TestRolloverProbeStateRejectsPendingIdentityMismatch(t *testing.T) {
	root, wrapping, directory, bundlePath, bundle := makeRolloverProbeState(t)
	defer clear(wrapping)
	pending := acmePendingAccountEnvelopePath(root, directory, bundle.NewAccountPublicKeySHA256)
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	otherKey, err := GenerateACMEAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	_, pendingBytes, err := buildEncryptedACMEAccountEnvelope(otherKey, wrapping, directory, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := writeExclusivePrivateFile(pending, pendingBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := loadACMEAccountRolloverProbeState(root, bundlePath, wrapping, directory); err == nil {
		t.Fatal("probe state unexpectedly accepted mismatched pending identity")
	}
}
