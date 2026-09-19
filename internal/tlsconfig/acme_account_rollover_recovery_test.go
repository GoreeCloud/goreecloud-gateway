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

func TestRolloverRecoveryNewAuthoritativeActivatesPendingAfterFreshProbe(t *testing.T) {
	root, wrapping, directory, bundlePath, bundle := makeRolloverProbeState(t)
	defer clear(wrapping)
	state, err := loadACMEAccountRolloverProbeState(root, bundlePath, wrapping, directory)
	if err != nil {
		t.Fatal(err)
	}
	oldClient := &fakeACMERecognitionClient{err: acme.ErrNoAccount}
	newClient := &fakeACMERecognitionClient{account: &acme.Account{Status: acme.StatusValid}}

	report, receipt, err := recoverLoadedACMEAccountKeyRollover(
		context.Background(),
		state,
		wrapping,
		oldClient,
		newClient,
		ACMERolloverAuthorityNew,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome != ACMERolloverAuthorityNew || receipt.Action != ACMERolloverRecoveryActivateNew || receipt.ProductionCutoverAuthorized {
		t.Fatalf("unexpected recovery result: report=%+v receipt=%+v", report, receipt)
	}
	_, activeEnvelope, err := LoadEncryptedACMEAccountKey(root, wrapping, directory)
	if err != nil {
		t.Fatal(err)
	}
	if activeEnvelope.PublicKeySHA256 != bundle.NewAccountPublicKeySHA256 {
		t.Fatal("new-authoritative recovery did not activate replacement key")
	}
	if _, err := os.Stat(state.pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending envelope still exists after activation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, receipt.RetiredEnvelopeFile)); err != nil {
		t.Fatalf("retired old envelope missing after recovery: %v", err)
	}
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatal("prepared bundle was removed after recovery")
	}
}

func TestRolloverRecoveryOldAuthoritativeClearsPendingAndKeepsOld(t *testing.T) {
	root, wrapping, directory, bundlePath, bundle := makeRolloverProbeState(t)
	defer clear(wrapping)
	state, err := loadACMEAccountRolloverProbeState(root, bundlePath, wrapping, directory)
	if err != nil {
		t.Fatal(err)
	}
	oldClient := &fakeACMERecognitionClient{account: &acme.Account{Status: acme.StatusValid}}
	newClient := &fakeACMERecognitionClient{err: acme.ErrNoAccount}

	report, receipt, err := recoverLoadedACMEAccountKeyRollover(
		context.Background(),
		state,
		wrapping,
		oldClient,
		newClient,
		ACMERolloverAuthorityOld,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome != ACMERolloverAuthorityOld || receipt.Action != ACMERolloverRecoveryRetainOld {
		t.Fatalf("unexpected recovery result: report=%+v receipt=%+v", report, receipt)
	}
	_, activeEnvelope, err := LoadEncryptedACMEAccountKey(root, wrapping, directory)
	if err != nil {
		t.Fatal(err)
	}
	if activeEnvelope.PublicKeySHA256 != bundle.OldAccountPublicKeySHA256 {
		t.Fatal("old-authoritative recovery changed active account key")
	}
	if _, err := os.Stat(state.pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-authoritative pending envelope still exists: %v", err)
	}
}

func TestRolloverRecoveryRefusesAmbiguousProbeOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name string
		old  *fakeACMERecognitionClient
		new  *fakeACMERecognitionClient
	}{
		{
			name: "both",
			old:  &fakeACMERecognitionClient{account: &acme.Account{Status: acme.StatusValid}},
			new:  &fakeACMERecognitionClient{account: &acme.Account{Status: acme.StatusValid}},
		},
		{
			name: "neither",
			old:  &fakeACMERecognitionClient{err: acme.ErrNoAccount},
			new:  &fakeACMERecognitionClient{err: acme.ErrNoAccount},
		},
		{
			name: "inconclusive",
			old:  &fakeACMERecognitionClient{err: errors.New("network unavailable")},
			new:  &fakeACMERecognitionClient{account: &acme.Account{Status: acme.StatusValid}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, wrapping, directory, bundlePath, bundle := makeRolloverProbeState(t)
			defer clear(wrapping)
			state, err := loadACMEAccountRolloverProbeState(root, bundlePath, wrapping, directory)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = recoverLoadedACMEAccountKeyRollover(
				context.Background(),
				state,
				wrapping,
				tc.old,
				tc.new,
				ACMERolloverAuthorityNew,
				time.Now().UTC(),
			)
			if err == nil {
				t.Fatalf("%s outcome unexpectedly mutated recovery state", tc.name)
			}
			_, activeEnvelope, loadErr := LoadEncryptedACMEAccountKey(root, wrapping, directory)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if activeEnvelope.PublicKeySHA256 != bundle.OldAccountPublicKeySHA256 {
				t.Fatalf("%s outcome changed active account key", tc.name)
			}
			if _, statErr := os.Stat(state.pendingPath); statErr != nil {
				t.Fatalf("%s outcome removed pending state: %v", tc.name, statErr)
			}
		})
	}
}

func TestRolloverRecoveryRequiresExplicitExpectedOutcomeMatch(t *testing.T) {
	root, wrapping, directory, bundlePath, bundle := makeRolloverProbeState(t)
	defer clear(wrapping)
	state, err := loadACMEAccountRolloverProbeState(root, bundlePath, wrapping, directory)
	if err != nil {
		t.Fatal(err)
	}
	oldClient := &fakeACMERecognitionClient{err: acme.ErrNoAccount}
	newClient := &fakeACMERecognitionClient{account: &acme.Account{Status: acme.StatusValid}}

	report, _, err := recoverLoadedACMEAccountKeyRollover(
		context.Background(),
		state,
		wrapping,
		oldClient,
		newClient,
		ACMERolloverAuthorityOld,
		time.Now().UTC(),
	)
	if err == nil {
		t.Fatal("mismatched expected outcome unexpectedly allowed recovery")
	}
	if report.Outcome != ACMERolloverAuthorityNew {
		t.Fatalf("fresh probe outcome=%q", report.Outcome)
	}
	_, activeEnvelope, loadErr := LoadEncryptedACMEAccountKey(root, wrapping, directory)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if activeEnvelope.PublicKeySHA256 != bundle.OldAccountPublicKeySHA256 {
		t.Fatal("mismatched expected outcome changed active account key")
	}
	if _, statErr := os.Stat(state.pendingPath); statErr != nil {
		t.Fatalf("mismatched expected outcome removed pending state: %v", statErr)
	}
}

func TestRolloverRecoveryRejectsUnsupportedExpectedOutcomeBeforeProbe(t *testing.T) {
	root, wrapping, directory, bundlePath, _ := makeRolloverProbeState(t)
	defer clear(wrapping)
	state, err := loadACMEAccountRolloverProbeState(root, bundlePath, wrapping, directory)
	if err != nil {
		t.Fatal(err)
	}
	oldClient := &fakeACMERecognitionClient{account: &acme.Account{Status: acme.StatusValid}}
	newClient := &fakeACMERecognitionClient{err: acme.ErrNoAccount}
	if _, _, err := recoverLoadedACMEAccountKeyRollover(
		context.Background(),
		state,
		wrapping,
		oldClient,
		newClient,
		ACMERolloverAuthorityBoth,
		time.Now().UTC(),
	); err == nil {
		t.Fatal("ambiguous expected outcome unexpectedly accepted")
	}
	if oldClient.calls != 0 || newClient.calls != 0 {
		t.Fatal("unsupported expected outcome unexpectedly performed CA probes")
	}
}
