package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/tlsconfig"
	"golang.org/x/crypto/acme"
)

type fakeRegistrationManager struct {
	plan             tlsconfig.ACMEAccountRegistrationPlan
	receipt          tlsconfig.ACMEAccountRegistrationReceipt
	prepareCalls     int
	registerCalls    int
	registerContacts []string
	acceptance       tlsconfig.ACMETermsAcceptance
	eab              *acme.ExternalAccountBinding
}

func (m *fakeRegistrationManager) PrepareRegistration(_ context.Context, contacts []string, _ time.Time) (tlsconfig.ACMEAccountRegistrationPlan, error) {
	m.prepareCalls++
	m.registerContacts = append([]string(nil), contacts...)
	return m.plan, nil
}

func (m *fakeRegistrationManager) Register(
	_ context.Context,
	_ tlsconfig.ACMEAccountRegistrationPlan,
	contacts []string,
	acceptance tlsconfig.ACMETermsAcceptance,
	eab *acme.ExternalAccountBinding,
	_ time.Time,
) (tlsconfig.ACMEAccountRegistrationReceipt, error) {
	m.registerCalls++
	m.registerContacts = append([]string(nil), contacts...)
	m.acceptance = acceptance
	if eab != nil {
		m.eab = &acme.ExternalAccountBinding{KID: eab.KID, Key: append([]byte(nil), eab.Key...)}
	}
	return m.receipt, nil
}

func TestRunCreateKeyPersistsEncryptedStateWithoutPrivateMaterialOutput(t *testing.T) {
	now := time.Date(2026, 9, 18, 18, 0, 0, 0, time.UTC)
	stateRoot := filepath.Join(t.TempDir(), "accounts")
	wrappingFile := writePrivateFile(t, "wrapping-key", bytes.Repeat([]byte{0x44}, 32))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"-action", "create-key",
		"-directory", "https://ca.example/directory",
		"-state-root", stateRoot,
		"-wrapping-key-file", wrappingFile,
	}, &stdout, &stderr, dependencies{
		now: func() time.Time { return now },
		newManager: func(crypto.Signer, string, *http.Client) (registrationManager, error) {
			t.Fatal("create-key unexpectedly initialized registration manager")
			return nil, nil
		},
	})
	if code != 0 {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "PRIVATE KEY") || strings.Contains(stdout.String(), "ciphertext_base64") {
		t.Fatalf("create-key output exposed private/encrypted key payload: %s", stdout.String())
	}
	var receipt accountKeyCreateReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.ProductionCutoverAuthorized || receipt.AccountPublicKeySHA256 == "" || receipt.StateFile == "" {
		t.Fatalf("unexpected create-key receipt: %+v", receipt)
	}
	if _, err := os.Stat(receipt.StateFile); err != nil {
		t.Fatalf("encrypted account state not created: %v", err)
	}
}

func TestRunPlanUsesProtectedAccountStateAndDoesNotEmitContacts(t *testing.T) {
	manager := &fakeRegistrationManager{plan: tlsconfig.ACMEAccountRegistrationPlan{
		Schema:                      tlsconfig.ACMEAccountRegistrationPlanSchemaV1,
		DirectoryURL:                "https://ca.example/directory",
		PreparedAt:                  "2026-09-18T18:00:00Z",
		TermsURL:                    "https://ca.example/terms",
		TermsAcceptanceRequired:     true,
		AccountPublicKeySHA256:      strings.Repeat("a", 64),
		ContactSetSHA256:            strings.Repeat("b", 64),
		ContactCount:                1,
		ProductionCutoverAuthorized: false,
	}}
	stateRoot, wrappingFile := makeAccountState(t, "https://ca.example/directory")
	contactsFile := writeJSONPrivateFile(t, "contacts.json", []string{"mailto:admin@example.test"})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"-action", "plan",
		"-directory", "https://ca.example/directory",
		"-state-root", stateRoot,
		"-wrapping-key-file", wrappingFile,
		"-contacts-file", contactsFile,
	}, &stdout, &stderr, fakeDependencies(manager))
	if code != 0 {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
	if manager.prepareCalls != 1 {
		t.Fatalf("prepare calls=%d", manager.prepareCalls)
	}
	if strings.Contains(stdout.String(), "admin@example.test") {
		t.Fatalf("registration plan leaked raw contact: %s", stdout.String())
	}
}

func TestRunRegisterRequiresExactDirectoryConfirmationBeforeLoadingState(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"-action", "register",
		"-directory", "https://ca.example/directory",
		"-state-root", "/does/not/exist",
		"-wrapping-key-file", "/does/not/exist",
		"-contacts-file", "/does/not/exist",
		"-plan-file", "/does/not/exist",
		"-confirm-register-directory", "https://ca.example/other",
	}, &stdout, &stderr, fakeDependencies(&fakeRegistrationManager{}))
	if code != 2 {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "must exactly match") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunRegisterLoadsExplicitAcceptanceAndEABFromProtectedFiles(t *testing.T) {
	manager := &fakeRegistrationManager{receipt: tlsconfig.ACMEAccountRegistrationReceipt{
		Schema:                      tlsconfig.ACMEAccountRegistrationReceiptSchemaV1,
		DirectoryURL:                "https://ca.example/directory",
		RegisteredAt:                "2026-09-18T18:01:00Z",
		TermsURL:                    "https://ca.example/terms",
		TermsAccepted:               true,
		ExternalAccountBindingUsed:  true,
		AccountPublicKeySHA256:      strings.Repeat("a", 64),
		ContactSetSHA256:            strings.Repeat("b", 64),
		ContactCount:                1,
		AccountURLSHA256:            strings.Repeat("c", 64),
		ProductionCutoverAuthorized: false,
	}}
	stateRoot, wrappingFile := makeAccountState(t, "https://ca.example/directory")
	contactsFile := writeJSONPrivateFile(t, "contacts.json", []string{"mailto:admin@example.test"})
	planFile := writeJSONPrivateFile(t, "plan.json", tlsconfig.ACMEAccountRegistrationPlan{
		Schema:                  tlsconfig.ACMEAccountRegistrationPlanSchemaV1,
		DirectoryURL:            "https://ca.example/directory",
		PreparedAt:              "2026-09-18T18:00:00Z",
		TermsURL:                "https://ca.example/terms",
		TermsAcceptanceRequired: true,
	})
	acceptanceFile := writeJSONPrivateFile(t, "acceptance.json", tlsconfig.ACMETermsAcceptance{
		Accepted:   true,
		TermsURL:   "https://ca.example/terms",
		AcceptedAt: time.Date(2026, 9, 18, 18, 0, 30, 0, time.UTC),
	})
	eabSecret := []byte("operator-provisioned-eab-secret")
	eabFile := writePrivateFile(t, "eab-key", []byte(base64.RawURLEncoding.EncodeToString(eabSecret)+"\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"-action", "register",
		"-directory", "https://ca.example/directory",
		"-state-root", stateRoot,
		"-wrapping-key-file", wrappingFile,
		"-contacts-file", contactsFile,
		"-plan-file", planFile,
		"-terms-acceptance-file", acceptanceFile,
		"-eab-kid", "kid-123",
		"-eab-key-file", eabFile,
		"-confirm-register-directory", "https://ca.example/directory",
	}, &stdout, &stderr, fakeDependencies(manager))
	if code != 0 {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
	if manager.registerCalls != 1 || !manager.acceptance.Accepted || manager.acceptance.TermsURL != "https://ca.example/terms" {
		t.Fatalf("registration inputs not wired correctly: calls=%d acceptance=%+v", manager.registerCalls, manager.acceptance)
	}
	if manager.eab == nil || manager.eab.KID != "kid-123" || !bytes.Equal(manager.eab.Key, eabSecret) {
		t.Fatal("EAB material not decoded and wired correctly")
	}
	if strings.Contains(stdout.String(), "operator-provisioned-eab-secret") || strings.Contains(stdout.String(), "admin@example.test") {
		t.Fatalf("registration output leaked operator secret/contact: %s", stdout.String())
	}
}

func TestRunRejectsBroadProtectedInputPermissions(t *testing.T) {
	stateRoot, wrappingFile := makeAccountState(t, "https://ca.example/directory")
	contactsFile := filepath.Join(t.TempDir(), "contacts.json")
	if err := os.WriteFile(contactsFile, []byte("[\"mailto:admin@example.test\"]"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"-action", "plan",
		"-directory", "https://ca.example/directory",
		"-state-root", stateRoot,
		"-wrapping-key-file", wrappingFile,
		"-contacts-file", contactsFile,
	}, &stdout, &stderr, fakeDependencies(&fakeRegistrationManager{}))
	if code != 1 || !strings.Contains(stderr.String(), "permissions are too broad") {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
}

func fakeDependencies(manager registrationManager) dependencies {
	return dependencies{
		now: func() time.Time { return time.Date(2026, 9, 18, 18, 1, 0, 0, time.UTC) },
		newManager: func(crypto.Signer, string, *http.Client) (registrationManager, error) {
			return manager, nil
		},
	}
}

func makeAccountState(t *testing.T, directory string) (string, string) {
	t.Helper()
	stateRoot := filepath.Join(t.TempDir(), "accounts")
	wrapping := bytes.Repeat([]byte{0x31}, 32)
	wrappingFile := writePrivateFile(t, "wrapping-key", wrapping)
	key, err := tlsconfig.GenerateACMEAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tlsconfig.SaveEncryptedACMEAccountKey(
		stateRoot,
		key,
		wrapping,
		directory,
		time.Date(2026, 9, 18, 17, 55, 0, 0, time.UTC),
	); err != nil {
		t.Fatal(err)
	}
	return stateRoot, wrappingFile
}

func writeJSONPrivateFile(t *testing.T, name string, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return writePrivateFile(t, name, data)
}

func writePrivateFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunRolloverPrepareReturnsPrivacySafeReceipt(t *testing.T) {
	stateRoot, wrappingFile := makeAccountState(t, "https://ca.example/directory")
	deps := dependencies{
		now: func() time.Time { return time.Date(2026, 9, 18, 19, 0, 0, 0, time.UTC) },
		prepareRollover: tlsconfig.PrepareACMEAccountKeyRollover,
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"-action", "rollover-prepare",
		"-directory", "https://ca.example/directory",
		"-state-root", stateRoot,
		"-wrapping-key-file", wrappingFile,
	}, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "ciphertext_base64") || strings.Contains(stdout.String(), "nonce_base64") || strings.Contains(stdout.String(), "PRIVATE KEY") {
		t.Fatalf("rollover preparation output exposed protected key material: %s", stdout.String())
	}
	var receipt accountKeyRolloverPrepareReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.OldAccountPublicKeySHA256 == "" || receipt.NewAccountPublicKeySHA256 == "" || receipt.BundleFile == "" || receipt.ProductionCutoverAuthorized {
		t.Fatalf("unexpected rollover preparation receipt: %+v", receipt)
	}
	if _, err := os.Stat(receipt.BundleFile); err != nil {
		t.Fatalf("prepared rollover bundle missing: %v", err)
	}
}

func TestRunRolloverExecuteRequiresExactFingerprintConfirmationBeforeMutation(t *testing.T) {
	stateRoot, wrappingFile := makeAccountState(t, "https://ca.example/directory")
	wrapping, err := tlsconfig.LoadACMEAccountWrappingKey(wrappingFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wrapping)
	bundlePath, bundle, err := tlsconfig.PrepareACMEAccountKeyRollover(stateRoot, wrapping, "https://ca.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	deps := dependencies{
		now: func() time.Time { return time.Now().UTC() },
		executeRollover: func(context.Context, string, string, []byte, string, *http.Client, time.Time) (tlsconfig.ACMEAccountKeyRolloverReceipt, error) {
			calls++
			return tlsconfig.ACMEAccountKeyRolloverReceipt{}, nil
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"-action", "rollover-execute",
		"-directory", "https://ca.example/directory",
		"-state-root", stateRoot,
		"-wrapping-key-file", wrappingFile,
		"-rollover-bundle-file", bundlePath,
		"-confirm-rollover-directory", "https://ca.example/directory",
		"-confirm-old-account-sha256", bundle.OldAccountPublicKeySHA256,
		"-confirm-new-account-sha256", strings.Repeat("f", 64),
	}, &stdout, &stderr, deps)
	if code != 2 {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
	if calls != 0 {
		t.Fatalf("rollover mutation dependency called despite fingerprint mismatch: %d", calls)
	}
}

func TestRunRolloverProbeIsReadOnlyOperatorAction(t *testing.T) {
	stateRoot, wrappingFile := makeAccountState(t, "https://ca.example/directory")
	wrapping, err := tlsconfig.LoadACMEAccountWrappingKey(wrappingFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wrapping)
	bundlePath, _, err := tlsconfig.PrepareACMEAccountKeyRollover(stateRoot, wrapping, "https://ca.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	deps := dependencies{
		now: func() time.Time { return time.Date(2026, 9, 18, 19, 5, 0, 0, time.UTC) },
		probeRollover: func(context.Context, string, string, []byte, string, *http.Client, time.Time) (tlsconfig.ACMEAccountRolloverProbeReport, error) {
			calls++
			return tlsconfig.ACMEAccountRolloverProbeReport{
				Schema:                      tlsconfig.ACMEAccountRolloverProbeSchemaV1,
				DirectoryURL:                "https://ca.example/directory",
				Outcome:                     tlsconfig.ACMERolloverAuthorityOld,
				OldKeyProbe:                 tlsconfig.ACMEAccountProbeRecognized,
				NewKeyProbe:                 tlsconfig.ACMEAccountProbeNotRecognized,
				ProductionCutoverAuthorized: false,
			}, nil
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"-action", "rollover-probe",
		"-directory", "https://ca.example/directory",
		"-state-root", stateRoot,
		"-wrapping-key-file", wrappingFile,
		"-rollover-bundle-file", bundlePath,
	}, &stdout, &stderr, deps)
	if code != 0 || calls != 1 {
		t.Fatalf("run code=%d calls=%d stderr=%q", code, calls, stderr.String())
	}
	if !strings.Contains(stdout.String(), tlsconfig.ACMERolloverAuthorityOld) {
		t.Fatalf("probe output=%q", stdout.String())
	}
}

func TestRunRolloverRecoverRequiresExpectedOutcomeAndIdentityConfirmation(t *testing.T) {
	stateRoot, wrappingFile := makeAccountState(t, "https://ca.example/directory")
	wrapping, err := tlsconfig.LoadACMEAccountWrappingKey(wrappingFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wrapping)
	bundlePath, bundle, err := tlsconfig.PrepareACMEAccountKeyRollover(stateRoot, wrapping, "https://ca.example/directory", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	deps := dependencies{
		now: func() time.Time { return time.Date(2026, 9, 18, 19, 10, 0, 0, time.UTC) },
		recoverRollover: func(_ context.Context, _, _ string, _ []byte, _ string, _ *http.Client, expected string, _ time.Time) (tlsconfig.ACMEAccountRolloverProbeReport, tlsconfig.ACMEAccountRolloverRecoveryReceipt, error) {
			calls++
			if expected != tlsconfig.ACMERolloverAuthorityOld {
				t.Fatalf("expected outcome=%q", expected)
			}
			return tlsconfig.ACMEAccountRolloverProbeReport{
					Schema: tlsconfig.ACMEAccountRolloverProbeSchemaV1,
					Outcome: tlsconfig.ACMERolloverAuthorityOld,
				},
				tlsconfig.ACMEAccountRolloverRecoveryReceipt{
					Schema:                      tlsconfig.ACMEAccountRolloverRecoveryReceiptSchemaV1,
					ObservedOutcome:             tlsconfig.ACMERolloverAuthorityOld,
					Action:                      tlsconfig.ACMERolloverRecoveryRetainOld,
					ProductionCutoverAuthorized: false,
				},
				nil
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"-action", "rollover-recover",
		"-directory", "https://ca.example/directory",
		"-state-root", stateRoot,
		"-wrapping-key-file", wrappingFile,
		"-rollover-bundle-file", bundlePath,
		"-confirm-rollover-directory", "https://ca.example/directory",
		"-confirm-old-account-sha256", bundle.OldAccountPublicKeySHA256,
		"-confirm-new-account-sha256", bundle.NewAccountPublicKeySHA256,
		"-expected-rollover-outcome", tlsconfig.ACMERolloverAuthorityOld,
	}, &stdout, &stderr, deps)
	if code != 0 || calls != 1 {
		t.Fatalf("run code=%d calls=%d stderr=%q", code, calls, stderr.String())
	}
	if !strings.Contains(stdout.String(), tlsconfig.ACMERolloverRecoveryRetainOld) {
		t.Fatalf("recovery output=%q", stdout.String())
	}
}

func TestRunRolloverRecoverRejectsAmbiguousExpectedOutcomeBeforeMutation(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"-action", "rollover-recover",
		"-directory", "https://ca.example/directory",
		"-state-root", "/does/not/exist",
		"-wrapping-key-file", "/does/not/exist",
		"-rollover-bundle-file", "/does/not/exist",
		"-confirm-rollover-directory", "https://ca.example/directory",
		"-confirm-old-account-sha256", strings.Repeat("a", 64),
		"-confirm-new-account-sha256", strings.Repeat("b", 64),
		"-expected-rollover-outcome", tlsconfig.ACMERolloverAuthorityBoth,
	}, &stdout, &stderr, dependencies{now: time.Now, recoverRollover: func(context.Context, string, string, []byte, string, *http.Client, string, time.Time) (tlsconfig.ACMEAccountRolloverProbeReport, tlsconfig.ACMEAccountRolloverRecoveryReceipt, error) {
		t.Fatal("ambiguous recovery unexpectedly reached mutation dependency")
		return tlsconfig.ACMEAccountRolloverProbeReport{}, tlsconfig.ACMEAccountRolloverRecoveryReceipt{}, nil
	}})
	if code != 2 || !strings.Contains(stderr.String(), "old-authoritative or new-authoritative") {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
}
