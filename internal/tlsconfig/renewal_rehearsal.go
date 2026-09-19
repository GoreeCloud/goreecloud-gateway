package tlsconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

const RenewalRehearsalReceiptSchemaV1 = "goreecloud-gateway-renewal-rehearsal-receipt/v1"

// RenewalRehearsalReceipt records a completed isolated renewal cycle without
// retaining certificate/key material or authorizing production cutover.
type RenewalRehearsalReceipt struct {
	Schema                      string `json:"schema"`
	CompletedAt                 string `json:"completed_at"`
	ProfileID                   string `json:"profile_id"`
	PreviousSerial              string `json:"previous_serial"`
	CandidateSerial             string `json:"candidate_serial"`
	CandidateActivated          bool   `json:"candidate_activated"`
	PreviousPairRestored        bool   `json:"previous_pair_restored"`
	PreviousRuntimeRestored     bool   `json:"previous_runtime_restored"`
	ProductionCutoverAuthorized bool   `json:"production_cutover_authorized"`
}

// RunIsolatedRenewalRehearsal exercises the complete renewal transaction only
// inside an explicitly bounded rehearsal root. It stages provider output,
// publishes it to rehearsal live files, activates the candidate in the supplied
// rehearsal runtime, then restores both the previous on-disk pair and previous
// runtime. The function refuses live/staging/backup paths outside rehearsalRoot
// and can never authorize production cutover.
func RunIsolatedRenewalRehearsal(
	ctx context.Context,
	issuer RenewalIssuer,
	request RenewalRequest,
	cfg *config.Config,
	reloader *Reloader,
	rehearsalRoot string,
	stagingRoot string,
	backupRoot string,
	now time.Time,
) (RenewalRehearsalReceipt, error) {
	if cfg == nil || reloader == nil {
		return RenewalRehearsalReceipt{}, errors.New("gateway tls: rehearsal config and reloader are required")
	}
	if now.IsZero() {
		return RenewalRehearsalReceipt{}, errors.New("gateway tls: rehearsal time is required")
	}
	if err := request.Validate(); err != nil {
		return RenewalRehearsalReceipt{}, err
	}
	profile, ok := cfg.CertificateProfile(request.ProfileID)
	if !ok || !profile.Enabled {
		return RenewalRehearsalReceipt{}, errors.New("gateway tls: rehearsal certificate profile is missing or disabled")
	}
	if err := validateRenewalRehearsalPaths(rehearsalRoot, profile.CertificateFile, profile.PrivateKeyFile, stagingRoot, backupRoot); err != nil {
		return RenewalRehearsalReceipt{}, err
	}

	issued, err := IssueValidateAndStageRenewal(ctx, issuer, request, stagingRoot, now)
	if err != nil {
		return RenewalRehearsalReceipt{}, err
	}
	plan, err := PrepareRenewalPublication(profile, issued.Stage, now.Add(time.Nanosecond))
	if err != nil {
		return RenewalRehearsalReceipt{}, err
	}
	publication, err := ExecuteRenewalPublication(plan, backupRoot, now.Add(2*time.Nanosecond))
	if err != nil {
		return RenewalRehearsalReceipt{}, err
	}
	activation, err := ActivateRenewalPublication(reloader, cfg, publication, now.Add(3*time.Nanosecond))
	if err != nil {
		return RenewalRehearsalReceipt{}, err
	}
	if activation.ProductionCutoverAuthorized {
		return RenewalRehearsalReceipt{}, errors.New("gateway tls: rehearsal activation unexpectedly authorized production cutover")
	}

	if err := RestoreRenewalPublicationBackup(publication, publication.CandidateSerial); err != nil {
		return RenewalRehearsalReceipt{}, fmt.Errorf("gateway tls: rehearsal could not restore previous on-disk pair: %w", err)
	}
	_, restoredLeaf, err := loadRenewalLivePair(profile.CertificateFile, profile.PrivateKeyFile)
	if err != nil {
		return RenewalRehearsalReceipt{}, fmt.Errorf("gateway tls: rehearsal restored pair is unreadable: %w", err)
	}
	if restoredLeaf.SerialNumber.String() != publication.PreviousSerial {
		return RenewalRehearsalReceipt{}, errors.New("gateway tls: rehearsal did not restore previous certificate serial")
	}
	if err := reloader.Reload(cfg); err != nil {
		return RenewalRehearsalReceipt{}, fmt.Errorf("gateway tls: rehearsal could not restore previous runtime: %w", err)
	}

	return RenewalRehearsalReceipt{
		Schema:                      RenewalRehearsalReceiptSchemaV1,
		CompletedAt:                 now.Add(4 * time.Nanosecond).UTC().Format(time.RFC3339Nano),
		ProfileID:                   publication.ProfileID,
		PreviousSerial:              publication.PreviousSerial,
		CandidateSerial:             publication.CandidateSerial,
		CandidateActivated:          true,
		PreviousPairRestored:        true,
		PreviousRuntimeRestored:     true,
		ProductionCutoverAuthorized: false,
	}, nil
}

func validateRenewalRehearsalPaths(rehearsalRoot string, paths ...string) error {
	rehearsalRoot = strings.TrimSpace(rehearsalRoot)
	if rehearsalRoot == "" {
		return errors.New("gateway tls: isolated rehearsal root is required")
	}
	info, err := os.Lstat(rehearsalRoot)
	if err != nil {
		return fmt.Errorf("gateway tls: inspect isolated rehearsal root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("gateway tls: isolated rehearsal root must be a real directory")
	}
	root, err := filepath.Abs(rehearsalRoot)
	if err != nil {
		return fmt.Errorf("gateway tls: resolve isolated rehearsal root: %w", err)
	}
	for _, candidate := range paths {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return errors.New("gateway tls: isolated rehearsal paths are required")
		}
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			return fmt.Errorf("gateway tls: resolve isolated rehearsal path: %w", err)
		}
		relative, err := filepath.Rel(root, absolute)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("gateway tls: renewal rehearsal path escapes isolated rehearsal root")
		}
	}
	return nil
}
