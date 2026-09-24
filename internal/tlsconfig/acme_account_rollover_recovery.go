package tlsconfig

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	ACMEAccountRolloverRecoveryReceiptSchemaV1 = "goreecloud-gateway-acme-account-rollover-recovery-receipt/v1"

	ACMERolloverRecoveryRetainOld = "retain-old-active-clear-pending"
	ACMERolloverRecoveryActivateNew = "activate-pending-new"
)

type ACMEAccountRolloverRecoveryReceipt struct {
	Schema                      string `json:"schema"`
	DirectoryURL                string `json:"directory_url"`
	RecoveredAt                 string `json:"recovered_at"`
	ObservedOutcome             string `json:"observed_outcome"`
	Action                      string `json:"action"`
	OldAccountPublicKeySHA256   string `json:"old_account_public_key_sha256"`
	NewAccountPublicKeySHA256   string `json:"new_account_public_key_sha256"`
	RetiredEnvelopeFile         string `json:"retired_envelope_file"`
	PreparedBundleFile          string `json:"prepared_bundle_file"`
	ProductionCutoverAuthorized bool   `json:"production_cutover_authorized"`
}

// RecoverPreparedACMEAccountKeyRollover resolves an uncertain rollover only
// after a fresh read-only authority probe. The caller must explicitly state the
// expected authoritative outcome; Gateway refuses automatic recovery for
// ambiguous or inconclusive probe results.
//
// This function never calls AccountKeyRollover. It mutates only protected local
// account state after the fresh probe exactly matches expectedOutcome.
func RecoverPreparedACMEAccountKeyRollover(
	ctx context.Context,
	root string,
	bundlePath string,
	wrappingKey []byte,
	directoryURL string,
	httpClient *http.Client,
	expectedOutcome string,
	now time.Time,
) (ACMEAccountRolloverProbeReport, ACMEAccountRolloverRecoveryReceipt, error) {
	var report ACMEAccountRolloverProbeReport
	var receipt ACMEAccountRolloverRecoveryReceipt

	state, err := loadACMEAccountRolloverProbeState(root, bundlePath, wrappingKey, directoryURL)
	if err != nil {
		return report, receipt, err
	}
	oldClient, err := newACMEProtocolClient(state.oldKey, state.directory, httpClient)
	if err != nil {
		return report, receipt, err
	}
	newClient, err := newACMEProtocolClient(state.newKey, state.directory, httpClient)
	if err != nil {
		return report, receipt, err
	}
	return recoverLoadedACMEAccountKeyRollover(ctx, state, wrappingKey, oldClient, newClient, expectedOutcome, now)
}

func recoverLoadedACMEAccountKeyRollover(
	ctx context.Context,
	state acmeAccountRolloverProbeState,
	wrappingKey []byte,
	oldClient acmeAccountRecognitionClient,
	newClient acmeAccountRecognitionClient,
	expectedOutcome string,
	now time.Time,
) (ACMEAccountRolloverProbeReport, ACMEAccountRolloverRecoveryReceipt, error) {
	var receipt ACMEAccountRolloverRecoveryReceipt
	if expectedOutcome != ACMERolloverAuthorityOld && expectedOutcome != ACMERolloverAuthorityNew {
		return ACMEAccountRolloverProbeReport{}, receipt, errors.New("gateway tls: rollover recovery expected outcome must be old-authoritative or new-authoritative")
	}

	report, err := probeACMEAccountRolloverAuthority(ctx, state, oldClient, newClient, now)
	if err != nil {
		return report, receipt, err
	}
	if report.Outcome != expectedOutcome {
		return report, receipt, fmt.Errorf("gateway tls: rollover recovery probe outcome %q did not match explicit expected outcome %q", report.Outcome, expectedOutcome)
	}

	activePath := acmeAccountEnvelopePath(state.stateRoot, state.directory)
	activeBytes, activeEnvelope, err := readActiveAccountEnvelopeBytes(activePath, state.directory)
	if err != nil {
		return report, receipt, err
	}
	if activeEnvelope.PublicKeySHA256 != state.bundle.OldAccountPublicKeySHA256 {
		return report, receipt, errors.New("gateway tls: active ACME account identity changed after recovery probe")
	}
	if _, pendingEnvelope, err := readActiveAccountEnvelopeBytes(state.pendingPath, state.directory); err != nil {
		return report, receipt, fmt.Errorf("gateway tls: reload pending ACME account envelope after recovery probe: %w", err)
	} else if pendingEnvelope.PublicKeySHA256 != state.bundle.NewAccountPublicKeySHA256 || pendingEnvelope.KeyType != state.bundle.NewKeyType {
		return report, receipt, errors.New("gateway tls: pending ACME account identity changed after recovery probe")
	}

	retiredPath := acmeRetiredAccountEnvelopePath(
		state.stateRoot,
		state.directory,
		state.bundle.OldAccountPublicKeySHA256,
		state.bundle.NewAccountPublicKeySHA256,
	)
	if err := ensureEncryptedRetiredAccountSnapshot(retiredPath, activeBytes); err != nil {
		return report, receipt, err
	}

	action := ""
	switch expectedOutcome {
	case ACMERolloverAuthorityOld:
		if err := os.Remove(state.pendingPath); err != nil {
			return report, receipt, fmt.Errorf("gateway tls: remove non-authoritative pending ACME account envelope: %w", err)
		}
		action = ACMERolloverRecoveryRetainOld
	case ACMERolloverAuthorityNew:
		if err := os.Rename(state.pendingPath, activePath); err != nil {
			return report, receipt, fmt.Errorf("gateway tls: activate authoritative pending ACME account envelope: %w", err)
		}
		action = ACMERolloverRecoveryActivateNew
	}

	receipt = ACMEAccountRolloverRecoveryReceipt{
		Schema:                      ACMEAccountRolloverRecoveryReceiptSchemaV1,
		DirectoryURL:                state.directory,
		RecoveredAt:                 now.UTC().Format(time.RFC3339Nano),
		ObservedOutcome:             report.Outcome,
		Action:                      action,
		OldAccountPublicKeySHA256:   state.bundle.OldAccountPublicKeySHA256,
		NewAccountPublicKeySHA256:   state.bundle.NewAccountPublicKeySHA256,
		RetiredEnvelopeFile:         filepath.Base(retiredPath),
		PreparedBundleFile:          filepath.Base(state.bundlePath),
		ProductionCutoverAuthorized: false,
	}

	if err := syncDirectory(state.stateRoot); err != nil {
		return report, receipt, fmt.Errorf("gateway tls: rollover recovery state changed but directory durability confirmation failed: %w", err)
	}

	activatedKey, activatedEnvelope, err := LoadEncryptedACMEAccountKey(state.stateRoot, wrappingKey, state.directory)
	if err != nil {
		return report, receipt, fmt.Errorf("gateway tls: verify recovered ACME account state: %w", err)
	}
	_, activatedFingerprint, err := describeACMEAccountSigner(activatedKey)
	if err != nil {
		return report, receipt, err
	}
	wantFingerprint := state.bundle.OldAccountPublicKeySHA256
	if expectedOutcome == ACMERolloverAuthorityNew {
		wantFingerprint = state.bundle.NewAccountPublicKeySHA256
	}
	if activatedEnvelope.PublicKeySHA256 != wantFingerprint || activatedFingerprint != wantFingerprint {
		return report, receipt, errors.New("gateway tls: recovered ACME account state did not match authoritative probe outcome")
	}
	return report, receipt, nil
}
