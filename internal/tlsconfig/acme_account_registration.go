package tlsconfig

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	ACMEAccountRegistrationPlanSchemaV1    = "goreecloud-gateway-acme-account-registration-plan/v1"
	ACMEAccountRegistrationReceiptSchemaV1 = "goreecloud-gateway-acme-account-registration-receipt/v1"
	acmeRegistrationPlanLifetime            = 15 * time.Minute
)

type ACMEAccountRegistrationPlan struct {
	Schema                      string `json:"schema"`
	DirectoryURL                string `json:"directory_url"`
	PreparedAt                  string `json:"prepared_at"`
	TermsURL                    string `json:"terms_url,omitempty"`
	TermsAcceptanceRequired     bool   `json:"terms_acceptance_required"`
	ExternalAccountRequired     bool   `json:"external_account_required"`
	AccountPublicKeySHA256      string `json:"account_public_key_sha256"`
	ContactSetSHA256            string `json:"contact_set_sha256"`
	ContactCount                int    `json:"contact_count"`
	ProductionCutoverAuthorized bool   `json:"production_cutover_authorized"`
}

type ACMETermsAcceptance struct {
	Accepted   bool
	TermsURL   string
	AcceptedAt time.Time
}

type ACMEAccountRegistrationReceipt struct {
	Schema                      string `json:"schema"`
	DirectoryURL                string `json:"directory_url"`
	RegisteredAt                string `json:"registered_at"`
	TermsURL                    string `json:"terms_url,omitempty"`
	TermsAccepted               bool   `json:"terms_accepted"`
	ExternalAccountBindingUsed  bool   `json:"external_account_binding_used"`
	AccountPublicKeySHA256      string `json:"account_public_key_sha256"`
	ContactSetSHA256            string `json:"contact_set_sha256"`
	ContactCount                int    `json:"contact_count"`
	AccountURLSHA256            string `json:"account_url_sha256"`
	ProductionCutoverAuthorized bool   `json:"production_cutover_authorized"`
}

type acmeAccountRegistrationClient interface {
	Discover(context.Context) (acme.Directory, error)
	GetReg(context.Context, string) (*acme.Account, error)
	Register(context.Context, *acme.Account, func(string) bool) (*acme.Account, error)
}

// ACMEAccountRegistrationManager owns explicit account discovery and
// registration. It never accepts CA terms implicitly and never persists
// account-key, contact, or EAB secret material.
type ACMEAccountRegistrationManager struct {
	client       acmeAccountRegistrationClient
	accountKey   crypto.Signer
	directoryURL string
}

func NewACMEAccountRegistrationManager(accountKey crypto.Signer, directoryURL string, httpClient *http.Client) (*ACMEAccountRegistrationManager, error) {
	client, err := newACMEProtocolClient(accountKey, directoryURL, httpClient)
	if err != nil {
		return nil, err
	}
	directory, err := normalizeACMEDirectoryURL(directoryURL)
	if err != nil {
		return nil, err
	}
	return &ACMEAccountRegistrationManager{
		client:       client,
		accountKey:   accountKey,
		directoryURL: directory,
	}, nil
}

func newACMEAccountRegistrationManager(client acmeAccountRegistrationClient, accountKey crypto.Signer, directoryURL string) (*ACMEAccountRegistrationManager, error) {
	if client == nil {
		return nil, errors.New("gateway tls: ACME account registration client is required")
	}
	if _, _, err := describeACMEAccountSigner(accountKey); err != nil {
		return nil, err
	}
	directory, err := normalizeACMEDirectoryURL(directoryURL)
	if err != nil {
		return nil, err
	}
	return &ACMEAccountRegistrationManager{client: client, accountKey: accountKey, directoryURL: directory}, nil
}

// PrepareRegistration performs discovery only. It creates a short-lived,
// privacy-safe plan bound to the exact account key, CA directory, terms URL,
// EAB requirement, and normalized contact set.
func (m *ACMEAccountRegistrationManager) PrepareRegistration(ctx context.Context, contacts []string, now time.Time) (ACMEAccountRegistrationPlan, error) {
	if m == nil || m.client == nil || m.accountKey == nil {
		return ACMEAccountRegistrationPlan{}, errors.New("gateway tls: ACME account registration manager is incomplete")
	}
	if ctx == nil {
		return ACMEAccountRegistrationPlan{}, errors.New("gateway tls: ACME account registration context is required")
	}
	if err := ctx.Err(); err != nil {
		return ACMEAccountRegistrationPlan{}, fmt.Errorf("gateway tls: ACME account registration context unavailable: %w", err)
	}
	if now.IsZero() {
		return ACMEAccountRegistrationPlan{}, errors.New("gateway tls: ACME account registration preparation time is required")
	}
	normalizedContacts, contactDigest, err := normalizeACMEContacts(contacts)
	if err != nil {
		return ACMEAccountRegistrationPlan{}, err
	}
	_, fingerprint, err := describeACMEAccountSigner(m.accountKey)
	if err != nil {
		return ACMEAccountRegistrationPlan{}, err
	}

	directory, err := m.client.Discover(ctx)
	if err != nil {
		return ACMEAccountRegistrationPlan{}, fmt.Errorf("gateway tls: ACME directory discovery failed: %w", err)
	}
	termsURL, err := validateACMETermsURL(directory.Terms)
	if err != nil {
		return ACMEAccountRegistrationPlan{}, err
	}
	if err := validateACMERegistrationEndpoint(directory.RegURL); err != nil {
		return ACMEAccountRegistrationPlan{}, err
	}
	if existing, err := m.client.GetReg(ctx, ""); err == nil {
		if existing != nil {
			return ACMEAccountRegistrationPlan{}, errors.New("gateway tls: ACME account is already registered")
		}
		return ACMEAccountRegistrationPlan{}, errors.New("gateway tls: ACME account lookup returned no account and no error")
	} else if !errors.Is(err, acme.ErrNoAccount) {
		return ACMEAccountRegistrationPlan{}, fmt.Errorf("gateway tls: ACME account lookup failed: %w", err)
	}

	return ACMEAccountRegistrationPlan{
		Schema:                      ACMEAccountRegistrationPlanSchemaV1,
		DirectoryURL:                m.directoryURL,
		PreparedAt:                  now.UTC().Format(time.RFC3339Nano),
		TermsURL:                    termsURL,
		TermsAcceptanceRequired:     termsURL != "",
		ExternalAccountRequired:     directory.ExternalAccountRequired,
		AccountPublicKeySHA256:      fingerprint,
		ContactSetSHA256:            contactDigest,
		ContactCount:                len(normalizedContacts),
		ProductionCutoverAuthorized: false,
	}, nil
}

// Register consumes one short-lived plan. The terms acceptance must match the
// exact discovered terms URL and be explicit. If the CA requires EAB, a
// complete binding must be supplied. The returned receipt contains hashes only
// for account URL and contact identity.
func (m *ACMEAccountRegistrationManager) Register(
	ctx context.Context,
	plan ACMEAccountRegistrationPlan,
	contacts []string,
	acceptance ACMETermsAcceptance,
	eab *acme.ExternalAccountBinding,
	now time.Time,
) (ACMEAccountRegistrationReceipt, error) {
	if m == nil || m.client == nil || m.accountKey == nil {
		return ACMEAccountRegistrationReceipt{}, errors.New("gateway tls: ACME account registration manager is incomplete")
	}
	if ctx == nil {
		return ACMEAccountRegistrationReceipt{}, errors.New("gateway tls: ACME account registration context is required")
	}
	if err := ctx.Err(); err != nil {
		return ACMEAccountRegistrationReceipt{}, fmt.Errorf("gateway tls: ACME account registration context unavailable: %w", err)
	}
	if now.IsZero() {
		return ACMEAccountRegistrationReceipt{}, errors.New("gateway tls: ACME account registration time is required")
	}
	normalizedContacts, contactDigest, err := normalizeACMEContacts(contacts)
	if err != nil {
		return ACMEAccountRegistrationReceipt{}, err
	}
	_, fingerprint, err := describeACMEAccountSigner(m.accountKey)
	if err != nil {
		return ACMEAccountRegistrationReceipt{}, err
	}
	if err := validateACMERegistrationPlan(plan, m.directoryURL, fingerprint, contactDigest, len(normalizedContacts), now); err != nil {
		return ACMEAccountRegistrationReceipt{}, err
	}
	if err := validateACMETermsAcceptance(plan, acceptance, now); err != nil {
		return ACMEAccountRegistrationReceipt{}, err
	}
	if plan.ExternalAccountRequired && !validExternalAccountBinding(eab) {
		return ACMEAccountRegistrationReceipt{}, errors.New("gateway tls: ACME CA requires a complete external account binding")
	}

	currentDirectory, err := m.client.Discover(ctx)
	if err != nil {
		return ACMEAccountRegistrationReceipt{}, fmt.Errorf("gateway tls: ACME directory rediscovery failed: %w", err)
	}
	currentTerms, err := validateACMETermsURL(currentDirectory.Terms)
	if err != nil {
		return ACMEAccountRegistrationReceipt{}, err
	}
	if currentTerms != plan.TermsURL || currentDirectory.ExternalAccountRequired != plan.ExternalAccountRequired {
		return ACMEAccountRegistrationReceipt{}, errors.New("gateway tls: ACME directory registration requirements changed after plan preparation")
	}
	if err := validateACMERegistrationEndpoint(currentDirectory.RegURL); err != nil {
		return ACMEAccountRegistrationReceipt{}, err
	}
	if existing, err := m.client.GetReg(ctx, ""); err == nil {
		if existing != nil {
			return ACMEAccountRegistrationReceipt{}, errors.New("gateway tls: ACME account became registered after plan preparation")
		}
		return ACMEAccountRegistrationReceipt{}, errors.New("gateway tls: ACME account lookup returned no account and no error")
	} else if !errors.Is(err, acme.ErrNoAccount) {
		return ACMEAccountRegistrationReceipt{}, fmt.Errorf("gateway tls: ACME account lookup failed before registration: %w", err)
	}

	promptCalled := false
	promptMatched := true
	prompt := func(tosURL string) bool {
		promptCalled = true
		if tosURL != plan.TermsURL || !acceptance.Accepted {
			promptMatched = false
			return false
		}
		return true
	}
	account, err := m.client.Register(ctx, &acme.Account{
		Contact:                append([]string(nil), normalizedContacts...),
		ExternalAccountBinding: cloneExternalAccountBinding(eab),
	}, prompt)
	if err != nil {
		return ACMEAccountRegistrationReceipt{}, fmt.Errorf("gateway tls: ACME account registration failed: %w", err)
	}
	if plan.TermsAcceptanceRequired && (!promptCalled || !promptMatched) {
		return ACMEAccountRegistrationReceipt{}, errors.New("gateway tls: ACME account registration did not consume the exact approved terms")
	}
	if account == nil || account.Status != acme.StatusValid {
		return ACMEAccountRegistrationReceipt{}, errors.New("gateway tls: ACME registration did not return a valid account")
	}
	accountURL, err := validateACMEAccountURL(account.URI)
	if err != nil {
		return ACMEAccountRegistrationReceipt{}, err
	}
	accountURLDigest := sha256.Sum256([]byte(accountURL))

	return ACMEAccountRegistrationReceipt{
		Schema:                      ACMEAccountRegistrationReceiptSchemaV1,
		DirectoryURL:                plan.DirectoryURL,
		RegisteredAt:                now.UTC().Format(time.RFC3339Nano),
		TermsURL:                    plan.TermsURL,
		TermsAccepted:               plan.TermsAcceptanceRequired,
		ExternalAccountBindingUsed:  validExternalAccountBinding(eab),
		AccountPublicKeySHA256:      plan.AccountPublicKeySHA256,
		ContactSetSHA256:            plan.ContactSetSHA256,
		ContactCount:                plan.ContactCount,
		AccountURLSHA256:            hex.EncodeToString(accountURLDigest[:]),
		ProductionCutoverAuthorized: false,
	}, nil
}

func normalizeACMEContacts(contacts []string) ([]string, string, error) {
	normalized := make([]string, 0, len(contacts))
	seen := make(map[string]struct{}, len(contacts))
	for _, raw := range contacts {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, "", errors.New("gateway tls: ACME account contact entries cannot be empty")
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Fragment != "" {
			return nil, "", errors.New("gateway tls: ACME account contacts must be absolute URI values without fragments")
		}
		if parsed.Scheme == "http" || parsed.Scheme == "https" {
			if parsed.Host == "" || parsed.User != nil {
				return nil, "", errors.New("gateway tls: ACME HTTP contact URI is invalid")
			}
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	digest := sha256.Sum256([]byte(strings.Join(normalized, "\n")))
	return normalized, hex.EncodeToString(digest[:]), nil
}

func validateACMETermsURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("gateway tls: ACME terms URL must be an absolute HTTPS URL")
	}
	return parsed.String(), nil
}

func validateACMERegistrationEndpoint(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("gateway tls: ACME registration endpoint must be an absolute HTTPS URL")
	}
	return nil
}

func validateACMEAccountURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("gateway tls: ACME account URL must be an absolute HTTPS URL")
	}
	return parsed.String(), nil
}

func validateACMERegistrationPlan(plan ACMEAccountRegistrationPlan, directoryURL, fingerprint, contactDigest string, contactCount int, now time.Time) error {
	if plan.Schema != ACMEAccountRegistrationPlanSchemaV1 {
		return errors.New("gateway tls: unsupported ACME account registration plan schema")
	}
	if plan.ProductionCutoverAuthorized {
		return errors.New("gateway tls: ACME account registration plan cannot authorize production cutover")
	}
	if plan.DirectoryURL != directoryURL || plan.AccountPublicKeySHA256 != fingerprint || plan.ContactSetSHA256 != contactDigest || plan.ContactCount != contactCount {
		return errors.New("gateway tls: ACME account registration plan no longer matches account identity or contacts")
	}
	preparedAt, err := time.Parse(time.RFC3339Nano, plan.PreparedAt)
	if err != nil || preparedAt.IsZero() {
		return errors.New("gateway tls: ACME account registration plan preparation time is invalid")
	}
	age := now.UTC().Sub(preparedAt.UTC())
	if age < 0 || age > acmeRegistrationPlanLifetime {
		return errors.New("gateway tls: ACME account registration plan is outside its allowed lifetime")
	}
	if plan.TermsAcceptanceRequired != (strings.TrimSpace(plan.TermsURL) != "") {
		return errors.New("gateway tls: ACME account registration plan terms state is inconsistent")
	}
	if _, err := validateACMETermsURL(plan.TermsURL); err != nil {
		return err
	}
	return nil
}

func validateACMETermsAcceptance(plan ACMEAccountRegistrationPlan, acceptance ACMETermsAcceptance, now time.Time) error {
	if !plan.TermsAcceptanceRequired {
		if acceptance.Accepted || strings.TrimSpace(acceptance.TermsURL) != "" || !acceptance.AcceptedAt.IsZero() {
			return errors.New("gateway tls: terms acceptance was supplied when the ACME directory exposes no terms URL")
		}
		return nil
	}
	if !acceptance.Accepted {
		return errors.New("gateway tls: explicit ACME terms acceptance is required")
	}
	if acceptance.TermsURL != plan.TermsURL {
		return errors.New("gateway tls: ACME terms acceptance URL does not match the prepared plan")
	}
	if acceptance.AcceptedAt.IsZero() || acceptance.AcceptedAt.After(now) {
		return errors.New("gateway tls: ACME terms acceptance time is invalid")
	}
	if acceptance.AcceptedAt.Before(now.Add(-acmeRegistrationPlanLifetime)) {
		return errors.New("gateway tls: ACME terms acceptance is too old for this registration plan")
	}
	return nil
}

func validExternalAccountBinding(eab *acme.ExternalAccountBinding) bool {
	return eab != nil && strings.TrimSpace(eab.KID) != "" && len(eab.Key) > 0
}

func cloneExternalAccountBinding(eab *acme.ExternalAccountBinding) *acme.ExternalAccountBinding {
	if eab == nil {
		return nil
	}
	return &acme.ExternalAccountBinding{KID: eab.KID, Key: append([]byte(nil), eab.Key...)}
}
