package tlsconfig

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	ACMEAccountRolloverProbeSchemaV1 = "goreecloud-gateway-acme-account-rollover-probe/v1"

	ACMEAccountProbeRecognized    = "recognized"
	ACMEAccountProbeNotRecognized = "not-recognized"
	ACMEAccountProbeInconclusive  = "inconclusive"

	ACMERolloverAuthorityOld     = "old-authoritative"
	ACMERolloverAuthorityNew     = "new-authoritative"
	ACMERolloverAuthorityBoth    = "both-recognized"
	ACMERolloverAuthorityNeither = "neither-recognized"
	ACMERolloverAuthorityUnknown = "inconclusive"
)

type ACMEAccountRolloverProbeReport struct {
	Schema                      string `json:"schema"`
	DirectoryURL                string `json:"directory_url"`
	ProbedAt                    string `json:"probed_at"`
	Outcome                     string `json:"outcome"`
	OldKeyProbe                 string `json:"old_key_probe"`
	NewKeyProbe                 string `json:"new_key_probe"`
	OldAccountStatus            string `json:"old_account_status,omitempty"`
	NewAccountStatus            string `json:"new_account_status,omitempty"`
	OldAccountPublicKeySHA256   string `json:"old_account_public_key_sha256"`
	NewAccountPublicKeySHA256   string `json:"new_account_public_key_sha256"`
	PendingEnvelopeFile         string `json:"pending_envelope_file"`
	PreparedBundleFile          string `json:"prepared_bundle_file"`
	ProductionCutoverAuthorized bool   `json:"production_cutover_authorized"`
}

type acmeAccountRecognitionClient interface {
	GetReg(context.Context, string) (*acme.Account, error)
}

type acmeAccountRolloverProbeState struct {
	directory       string
	oldKey          crypto.Signer
	newKey          crypto.Signer
	bundle          ACMEAccountRolloverBundle
	pendingEnvelope ACMEAccountKeyEnvelope
	pendingPath     string
	bundlePath      string
}

// ProbePreparedACMEAccountKeyRollover performs read-only ACME account
// recognition checks with the old and prepared replacement account keys. It
// never calls AccountKeyRollover and therefore cannot replay a key-change
// mutation while a distributed outcome is uncertain.
func ProbePreparedACMEAccountKeyRollover(
	ctx context.Context,
	root string,
	bundlePath string,
	wrappingKey []byte,
	directoryURL string,
	httpClient *http.Client,
	now time.Time,
) (ACMEAccountRolloverProbeReport, error) {
	var report ACMEAccountRolloverProbeReport
	state, err := loadACMEAccountRolloverProbeState(root, bundlePath, wrappingKey, directoryURL)
	if err != nil {
		return report, err
	}
	oldClient, err := newACMEProtocolClient(state.oldKey, state.directory, httpClient)
	if err != nil {
		return report, err
	}
	newClient, err := newACMEProtocolClient(state.newKey, state.directory, httpClient)
	if err != nil {
		return report, err
	}
	return probeACMEAccountRolloverAuthority(ctx, state, oldClient, newClient, now)
}

func loadACMEAccountRolloverProbeState(root, bundlePath string, wrappingKey []byte, directoryURL string) (acmeAccountRolloverProbeState, error) {
	var state acmeAccountRolloverProbeState
	if len(wrappingKey) != 32 {
		return state, errors.New("gateway tls: ACME account wrapping key must be exactly 32 bytes")
	}
	directory, err := normalizeACMEDirectoryURL(directoryURL)
	if err != nil {
		return state, err
	}
	stateRoot, err := prepareACMEAccountStateRoot(root, false)
	if err != nil {
		return state, err
	}

	oldKey, activeEnvelope, err := LoadEncryptedACMEAccountKey(stateRoot, wrappingKey, directory)
	if err != nil {
		return state, fmt.Errorf("gateway tls: load active ACME account key for rollover probe: %w", err)
	}
	newKey, bundle, err := LoadPreparedACMEAccountKeyRollover(stateRoot, bundlePath, wrappingKey, directory)
	if err != nil {
		return state, err
	}
	if activeEnvelope.PublicKeySHA256 != bundle.OldAccountPublicKeySHA256 {
		return state, errors.New("gateway tls: ACME rollover probe active account identity does not match prepared bundle")
	}

	pendingPath := acmePendingAccountEnvelopePath(stateRoot, directory, bundle.NewAccountPublicKeySHA256)
	_, pendingEnvelope, err := readActiveAccountEnvelopeBytes(pendingPath, directory)
	if err != nil {
		return state, fmt.Errorf("gateway tls: load pending ACME account envelope for rollover probe: %w", err)
	}
	if pendingEnvelope.PublicKeySHA256 != bundle.NewAccountPublicKeySHA256 || pendingEnvelope.KeyType != bundle.NewKeyType {
		return state, errors.New("gateway tls: pending ACME account envelope does not match prepared replacement identity")
	}

	return acmeAccountRolloverProbeState{
		directory:       directory,
		oldKey:          oldKey,
		newKey:          newKey,
		bundle:          bundle,
		pendingEnvelope: pendingEnvelope,
		pendingPath:     pendingPath,
		bundlePath:      bundlePath,
	}, nil
}

func probeACMEAccountRolloverAuthority(
	ctx context.Context,
	state acmeAccountRolloverProbeState,
	oldClient acmeAccountRecognitionClient,
	newClient acmeAccountRecognitionClient,
	now time.Time,
) (ACMEAccountRolloverProbeReport, error) {
	report := ACMEAccountRolloverProbeReport{
		Schema:                      ACMEAccountRolloverProbeSchemaV1,
		DirectoryURL:                state.directory,
		Outcome:                     ACMERolloverAuthorityUnknown,
		OldAccountPublicKeySHA256:   state.bundle.OldAccountPublicKeySHA256,
		NewAccountPublicKeySHA256:   state.bundle.NewAccountPublicKeySHA256,
		PendingEnvelopeFile:         filepath.Base(state.pendingPath),
		PreparedBundleFile:          filepath.Base(state.bundlePath),
		ProductionCutoverAuthorized: false,
	}
	if ctx == nil {
		return report, errors.New("gateway tls: ACME rollover probe context is required")
	}
	if err := ctx.Err(); err != nil {
		return report, fmt.Errorf("gateway tls: ACME rollover probe context unavailable: %w", err)
	}
	if oldClient == nil || newClient == nil {
		return report, errors.New("gateway tls: ACME rollover probe clients are required")
	}
	if now.IsZero() {
		return report, errors.New("gateway tls: ACME rollover probe time is required")
	}
	report.ProbedAt = now.UTC().Format(time.RFC3339Nano)

	oldProbe, oldStatus, oldErr := probeACMEAccountRecognition(ctx, oldClient)
	newProbe, newStatus, newErr := probeACMEAccountRecognition(ctx, newClient)
	report.OldKeyProbe = oldProbe
	report.NewKeyProbe = newProbe
	report.OldAccountStatus = oldStatus
	report.NewAccountStatus = newStatus

	if oldErr != nil || newErr != nil {
		report.Outcome = ACMERolloverAuthorityUnknown
		return report, errors.Join(oldErr, newErr)
	}

	switch {
	case oldProbe == ACMEAccountProbeRecognized && newProbe == ACMEAccountProbeNotRecognized:
		report.Outcome = ACMERolloverAuthorityOld
	case oldProbe == ACMEAccountProbeNotRecognized && newProbe == ACMEAccountProbeRecognized:
		report.Outcome = ACMERolloverAuthorityNew
	case oldProbe == ACMEAccountProbeRecognized && newProbe == ACMEAccountProbeRecognized:
		report.Outcome = ACMERolloverAuthorityBoth
	case oldProbe == ACMEAccountProbeNotRecognized && newProbe == ACMEAccountProbeNotRecognized:
		report.Outcome = ACMERolloverAuthorityNeither
	default:
		report.Outcome = ACMERolloverAuthorityUnknown
	}
	return report, nil
}

func probeACMEAccountRecognition(ctx context.Context, client acmeAccountRecognitionClient) (string, string, error) {
	account, err := client.GetReg(ctx, "")
	if errors.Is(err, acme.ErrNoAccount) {
		return ACMEAccountProbeNotRecognized, "", nil
	}
	if err != nil {
		return ACMEAccountProbeInconclusive, "", fmt.Errorf("gateway tls: ACME account recognition probe was inconclusive: %w", err)
	}
	if account == nil {
		return ACMEAccountProbeInconclusive, "", errors.New("gateway tls: ACME account recognition probe returned no account and no error")
	}
	return ACMEAccountProbeRecognized, account.Status, nil
}
