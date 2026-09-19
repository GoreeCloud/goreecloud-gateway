package tlsconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

type fakeACMEAccountRegistrationClient struct {
	directory     acme.Directory
	existing      *acme.Account
	getRegErr     error
	registerReply *acme.Account
	registerErr   error
	registerCalls int
	promptURL     string
	lastAccount   *acme.Account
}

func (c *fakeACMEAccountRegistrationClient) Discover(context.Context) (acme.Directory, error) {
	return c.directory, nil
}

func (c *fakeACMEAccountRegistrationClient) GetReg(context.Context, string) (*acme.Account, error) {
	if c.getRegErr != nil {
		return nil, c.getRegErr
	}
	if c.existing != nil {
		return c.existing, nil
	}
	return nil, acme.ErrNoAccount
}

func (c *fakeACMEAccountRegistrationClient) Register(_ context.Context, account *acme.Account, prompt func(string) bool) (*acme.Account, error) {
	c.registerCalls++
	c.lastAccount = account
	if c.directory.Terms != "" {
		if !prompt(c.promptURL) {
			return nil, errors.New("terms rejected")
		}
	}
	if c.registerErr != nil {
		return nil, c.registerErr
	}
	if c.registerReply != nil {
		return c.registerReply, nil
	}
	return &acme.Account{URI: "https://ca.example/acct/1", Status: acme.StatusValid}, nil
}

func registrationFixture(t *testing.T) (*ACMEAccountRegistrationManager, *fakeACMEAccountRegistrationClient, []string, time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	terms := "https://ca.example/terms/v1"
	client := &fakeACMEAccountRegistrationClient{
		directory: acme.Directory{
			RegURL:                  "https://ca.example/acme/new-account",
			OrderURL:                "https://ca.example/acme/new-order",
			Terms:                   terms,
			ExternalAccountRequired: false,
		},
		promptURL: terms,
	}
	manager, err := newACMEAccountRegistrationManager(client, key, "https://ca.example/directory")
	if err != nil {
		t.Fatal(err)
	}
	return manager, client, []string{"mailto:admin@example.test"}, time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
}

func TestACMEAccountRegistrationRequiresExactTermsAcceptance(t *testing.T) {
	manager, client, contacts, now := registrationFixture(t)
	plan, err := manager.PrepareRegistration(context.Background(), contacts, now)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.TermsAcceptanceRequired || plan.TermsURL != client.directory.Terms {
		t.Fatalf("unexpected registration plan: %+v", plan)
	}
	if _, err := manager.Register(context.Background(), plan, contacts, ACMETermsAcceptance{}, nil, now.Add(time.Minute)); err == nil {
		t.Fatal("registration unexpectedly accepted without explicit terms acceptance")
	}
	if client.registerCalls != 0 {
		t.Fatal("registration network mutation occurred before terms acceptance validation")
	}

	acceptance := ACMETermsAcceptance{Accepted: true, TermsURL: plan.TermsURL, AcceptedAt: now.Add(30 * time.Second)}
	receipt, err := manager.Register(context.Background(), plan, contacts, acceptance, nil, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if client.registerCalls != 1 || !receipt.TermsAccepted || receipt.ProductionCutoverAuthorized {
		t.Fatalf("unexpected registration receipt: %+v calls=%d", receipt, client.registerCalls)
	}
	if receipt.ContactSetSHA256 == "" || receipt.AccountURLSHA256 == "" {
		t.Fatal("registration receipt did not retain privacy-safe identity hashes")
	}
}

func TestACMEAccountRegistrationRejectsMismatchedTermsURLBeforeMutation(t *testing.T) {
	manager, client, contacts, now := registrationFixture(t)
	plan, err := manager.PrepareRegistration(context.Background(), contacts, now)
	if err != nil {
		t.Fatal(err)
	}
	acceptance := ACMETermsAcceptance{Accepted: true, TermsURL: "https://ca.example/terms/other", AcceptedAt: now}
	if _, err := manager.Register(context.Background(), plan, contacts, acceptance, nil, now.Add(time.Minute)); err == nil {
		t.Fatal("mismatched terms URL unexpectedly accepted")
	}
	if client.registerCalls != 0 {
		t.Fatal("registration was attempted after mismatched terms acceptance")
	}
}

func TestACMEAccountRegistrationRequiresEABWhenDirectoryRequiresIt(t *testing.T) {
	manager, client, contacts, now := registrationFixture(t)
	client.directory.ExternalAccountRequired = true
	plan, err := manager.PrepareRegistration(context.Background(), contacts, now)
	if err != nil {
		t.Fatal(err)
	}
	acceptance := ACMETermsAcceptance{Accepted: true, TermsURL: plan.TermsURL, AcceptedAt: now}
	if _, err := manager.Register(context.Background(), plan, contacts, acceptance, nil, now.Add(time.Minute)); err == nil {
		t.Fatal("required EAB unexpectedly omitted")
	}
	if client.registerCalls != 0 {
		t.Fatal("registration attempted before EAB validation")
	}

	eab := &acme.ExternalAccountBinding{KID: "kid-1", Key: []byte("symmetric-secret")}
	receipt, err := manager.Register(context.Background(), plan, contacts, acceptance, eab, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.ExternalAccountBindingUsed {
		t.Fatal("EAB use was not recorded")
	}
	if client.lastAccount == nil || client.lastAccount.ExternalAccountBinding == nil {
		t.Fatal("EAB was not provided to ACME registration")
	}
}

func TestACMEAccountRegistrationRejectsExistingAccount(t *testing.T) {
	manager, client, contacts, now := registrationFixture(t)
	client.existing = &acme.Account{URI: "https://ca.example/acct/existing", Status: acme.StatusValid}
	if _, err := manager.PrepareRegistration(context.Background(), contacts, now); err == nil {
		t.Fatal("existing ACME account unexpectedly produced a registration plan")
	}
}

func TestACMEAccountRegistrationRejectsStalePlan(t *testing.T) {
	manager, client, contacts, now := registrationFixture(t)
	plan, err := manager.PrepareRegistration(context.Background(), contacts, now)
	if err != nil {
		t.Fatal(err)
	}
	acceptance := ACMETermsAcceptance{Accepted: true, TermsURL: plan.TermsURL, AcceptedAt: now}
	if _, err := manager.Register(context.Background(), plan, contacts, acceptance, nil, now.Add(acmeRegistrationPlanLifetime+time.Second)); err == nil {
		t.Fatal("stale ACME registration plan unexpectedly accepted")
	}
	if client.registerCalls != 0 {
		t.Fatal("stale plan caused a registration attempt")
	}
}

func TestACMEAccountRegistrationRejectsChangedContacts(t *testing.T) {
	manager, client, contacts, now := registrationFixture(t)
	plan, err := manager.PrepareRegistration(context.Background(), contacts, now)
	if err != nil {
		t.Fatal(err)
	}
	acceptance := ACMETermsAcceptance{Accepted: true, TermsURL: plan.TermsURL, AcceptedAt: now}
	if _, err := manager.Register(context.Background(), plan, []string{"mailto:other@example.test"}, acceptance, nil, now.Add(time.Minute)); err == nil {
		t.Fatal("changed ACME contacts unexpectedly accepted")
	}
	if client.registerCalls != 0 {
		t.Fatal("changed contacts caused a registration attempt")
	}
}

func TestACMEAccountRegistrationRejectsDirectoryRequirementDrift(t *testing.T) {
	manager, client, contacts, now := registrationFixture(t)
	plan, err := manager.PrepareRegistration(context.Background(), contacts, now)
	if err != nil {
		t.Fatal(err)
	}
	client.directory.Terms = "https://ca.example/terms/v2"
	acceptance := ACMETermsAcceptance{Accepted: true, TermsURL: plan.TermsURL, AcceptedAt: now}
	if _, err := manager.Register(context.Background(), plan, contacts, acceptance, nil, now.Add(time.Minute)); err == nil {
		t.Fatal("changed ACME directory terms unexpectedly accepted")
	}
	if client.registerCalls != 0 {
		t.Fatal("directory drift caused a registration attempt")
	}
}

func TestACMERegistrationReceiptDoesNotContainContactOrEABSecret(t *testing.T) {
	manager, client, contacts, now := registrationFixture(t)
	client.directory.ExternalAccountRequired = true
	plan, err := manager.PrepareRegistration(context.Background(), contacts, now)
	if err != nil {
		t.Fatal(err)
	}
	acceptance := ACMETermsAcceptance{Accepted: true, TermsURL: plan.TermsURL, AcceptedAt: now}
	eab := &acme.ExternalAccountBinding{KID: "kid-1", Key: []byte("super-secret-eab-key")}
	receipt, err := manager.Register(context.Background(), plan, contacts, acceptance, eab, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ContactSetSHA256 == contacts[0] || receipt.AccountURLSHA256 == "https://ca.example/acct/1" {
		t.Fatal("receipt exposed raw account registration identity")
	}
}

func TestACMEAccountRegistrationWithoutTermsRejectsSpuriousAcceptance(t *testing.T) {
	manager, client, contacts, now := registrationFixture(t)
	client.directory.Terms = ""
	client.promptURL = ""
	plan, err := manager.PrepareRegistration(context.Background(), contacts, now)
	if err != nil {
		t.Fatal(err)
	}
	if plan.TermsAcceptanceRequired {
		t.Fatal("terms acceptance unexpectedly required")
	}
	spurious := ACMETermsAcceptance{Accepted: true, TermsURL: "https://ca.example/terms/v1", AcceptedAt: now}
	if _, err := manager.Register(context.Background(), plan, contacts, spurious, nil, now.Add(time.Minute)); err == nil {
		t.Fatal("spurious terms acceptance unexpectedly accepted")
	}
	if client.registerCalls != 0 {
		t.Fatal("spurious terms acceptance caused registration")
	}
}

func TestNormalizeACMEContactsIsOrderIndependentAndDeduplicated(t *testing.T) {
	a, digestA, err := normalizeACMEContacts([]string{"mailto:b@example.test", "mailto:a@example.test", "mailto:a@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	b, digestB, err := normalizeACMEContacts([]string{"mailto:a@example.test", "mailto:b@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 2 || len(b) != 2 || digestA != digestB {
		t.Fatalf("contact normalization mismatch: %v %v %s %s", a, b, digestA, digestB)
	}
}
