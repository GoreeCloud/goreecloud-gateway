package tlsconfig

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	defaultDNS01PropagationPollInterval = 2 * time.Second
	defaultDNS01PropagationTimeout      = 2 * time.Minute
	dns01CleanupTimeout                 = 15 * time.Second
)

// TXTResolver is the minimum DNS lookup boundary required to verify that an
// ACME DNS-01 TXT value is observable before asking a CA to validate it.
type TXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

// DNS01PropagationWaiter confirms that the exact challenge value is observable.
// Implementations must not mutate DNS.
type DNS01PropagationWaiter interface {
	WaitTXT(context.Context, string, string) error
}

// ResolverDNS01PropagationWaiter polls a DNS resolver for exact TXT-value
// visibility. It does not log challenge values or resolver responses.
type ResolverDNS01PropagationWaiter struct {
	Resolver     TXTResolver
	PollInterval time.Duration
	Timeout      time.Duration
}

func (w ResolverDNS01PropagationWaiter) WaitTXT(ctx context.Context, name, value string) error {
	if ctx == nil {
		return errors.New("gateway tls: DNS-01 propagation context is required")
	}
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	value = strings.TrimSpace(value)
	if name == "" || value == "" {
		return errors.New("gateway tls: DNS-01 propagation name and value are required")
	}

	resolver := w.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	poll := w.PollInterval
	if poll <= 0 {
		poll = defaultDNS01PropagationPollInterval
	}
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = defaultDNS01PropagationTimeout
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		records, lookupErr := resolver.LookupTXT(waitCtx, name)
		if lookupErr == nil {
			for _, record := range records {
				if record == value {
					return nil
				}
			}
		}

		timer := time.NewTimer(poll)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return errors.New("gateway tls: DNS-01 propagation was not observed before timeout")
		case <-timer.C:
		}
	}
}

type acmeOrderClient interface {
	GetReg(context.Context, string) (*acme.Account, error)
	AuthorizeOrder(context.Context, []acme.AuthzID, ...acme.OrderOption) (*acme.Order, error)
	GetAuthorization(context.Context, string) (*acme.Authorization, error)
	DNS01ChallengeRecord(string) (string, error)
	Accept(context.Context, *acme.Challenge) (*acme.Challenge, error)
	WaitAuthorization(context.Context, string) (*acme.Authorization, error)
	WaitOrder(context.Context, string) (*acme.Order, error)
	CreateOrderCert(context.Context, string, []byte, bool) ([][]byte, string, error)
}

// ACMERenewalIssuer implements RenewalIssuer using the RFC 8555 order flow and
// a bounded DNS01Provider. Account registration and terms-of-service approval
// remain separate, explicit operations: this issuer requires an existing
// registered ACME account.
type ACMERenewalIssuer struct {
	client            acmeOrderClient
	dns               DNS01Provider
	propagation       DNS01PropagationWaiter
	certificateKeyGen func() (crypto.Signer, error)
}

// NewACMERenewalIssuer creates a production-shaped RFC 8555 issuer without
// registering an ACME account or accepting terms automatically. accountKey must
// already correspond to a registered account at directoryURL.
func NewACMERenewalIssuer(accountKey crypto.Signer, directoryURL string, dns DNS01Provider, propagation DNS01PropagationWaiter, httpClient *http.Client) (*ACMERenewalIssuer, error) {
	if accountKey == nil {
		return nil, errors.New("gateway tls: ACME account key is required")
	}
	switch accountKey.Public().(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
	default:
		return nil, errors.New("gateway tls: ACME account key must be ECDSA or RSA")
	}
	if dns == nil {
		return nil, errors.New("gateway tls: DNS-01 provider is required")
	}

	directory, err := url.Parse(strings.TrimSpace(directoryURL))
	if err != nil || directory.Scheme != "https" || directory.Host == "" || directory.User != nil || directory.RawQuery != "" || directory.Fragment != "" {
		return nil, errors.New("gateway tls: ACME directory must be an absolute HTTPS URL")
	}

	if propagation == nil {
		propagation = ResolverDNS01PropagationWaiter{}
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	safeHTTPClient := *httpClient
	safeHTTPClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := &acme.Client{
		Key:          accountKey,
		HTTPClient:   &safeHTTPClient,
		DirectoryURL: directory.String(),
		UserAgent:    "GoreeCloud-Gateway/Development",
	}
	return newACMERenewalIssuer(client, dns, propagation), nil
}

func newACMERenewalIssuer(client acmeOrderClient, dns DNS01Provider, propagation DNS01PropagationWaiter) *ACMERenewalIssuer {
	return &ACMERenewalIssuer{
		client:            client,
		dns:               dns,
		propagation:       propagation,
		certificateKeyGen: generateCertificateKey,
	}
}

// IssueRenewal obtains a certificate only after every pending authorization is
// satisfied through DNS-01 and its exact challenge record is cleaned up.
// Returned key material is subsequently validated and staged by
// IssueValidateAndStageRenewal.
func (i *ACMERenewalIssuer) IssueRenewal(ctx context.Context, request RenewalRequest) ([]byte, []byte, error) {
	if i == nil || i.client == nil || i.dns == nil || i.propagation == nil {
		return nil, nil, errors.New("gateway tls: ACME renewal issuer is incomplete")
	}
	if ctx == nil {
		return nil, nil, errors.New("gateway tls: ACME renewal context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("gateway tls: ACME renewal context unavailable: %w", err)
	}
	if err := request.Validate(); err != nil {
		return nil, nil, err
	}

	account, err := i.client.GetReg(ctx, "")
	if err != nil {
		if errors.Is(err, acme.ErrNoAccount) {
			return nil, nil, errors.New("gateway tls: registered ACME account is required; account registration and terms approval are separate")
		}
		return nil, nil, fmt.Errorf("gateway tls: ACME account lookup failed: %w", err)
	}
	if account == nil || account.Status != acme.StatusValid {
		return nil, nil, errors.New("gateway tls: ACME account is not valid")
	}

	order, err := i.client.AuthorizeOrder(ctx, acme.DomainIDs(request.DNSNames...))
	if err != nil {
		return nil, nil, fmt.Errorf("gateway tls: ACME order creation failed: %w", err)
	}
	if err := validateACMEOrder(order, request.DNSNames); err != nil {
		return nil, nil, err
	}

	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := i.client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			return nil, nil, fmt.Errorf("gateway tls: ACME authorization retrieval failed: %w", err)
		}
		requestedName, err := requestedNameForAuthorization(authorization, request.DNSNames)
		if err != nil {
			return nil, nil, err
		}
		switch authorization.Status {
		case acme.StatusValid:
			continue
		case acme.StatusPending:
			if err := i.completeDNS01Authorization(ctx, authorization, requestedName); err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, fmt.Errorf("gateway tls: ACME authorization has unsupported status %q", authorization.Status)
		}
	}

	ready, err := i.client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, nil, fmt.Errorf("gateway tls: ACME order did not become ready: %w", err)
	}
	if ready == nil || ready.Status != acme.StatusReady {
		return nil, nil, errors.New("gateway tls: ACME order was not ready for Gateway-owned finalization")
	}

	finalizeURL := strings.TrimSpace(ready.FinalizeURL)
	if finalizeURL == "" {
		finalizeURL = strings.TrimSpace(order.FinalizeURL)
	}
	if finalizeURL == "" {
		return nil, nil, errors.New("gateway tls: ACME order omitted finalize URL")
	}

	keyGen := i.certificateKeyGen
	if keyGen == nil {
		keyGen = generateCertificateKey
	}
	certificateKey, err := keyGen()
	if err != nil {
		return nil, nil, fmt.Errorf("gateway tls: certificate key generation failed: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: append([]string(nil), request.DNSNames...)}, certificateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("gateway tls: certificate request generation failed: %w", err)
	}

	chainDER, _, err := i.client.CreateOrderCert(ctx, finalizeURL, csrDER, true)
	if err != nil {
		return nil, nil, fmt.Errorf("gateway tls: ACME certificate issuance failed: %w", err)
	}
	if len(chainDER) == 0 {
		return nil, nil, errors.New("gateway tls: ACME issuer returned an empty certificate chain")
	}

	var certificatePEM []byte
	for _, der := range chainDER {
		if len(der) == 0 {
			return nil, nil, errors.New("gateway tls: ACME issuer returned an empty certificate in the chain")
		}
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(certificateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("gateway tls: certificate private key encoding failed: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	return certificatePEM, privateKeyPEM, nil
}

func (i *ACMERenewalIssuer) completeDNS01Authorization(ctx context.Context, authorization *acme.Authorization, requestedName string) (err error) {
	if authorization == nil || strings.TrimSpace(authorization.URI) == "" {
		return errors.New("gateway tls: ACME authorization identity is incomplete")
	}

	var challenge *acme.Challenge
	for _, candidate := range authorization.Challenges {
		if candidate != nil && candidate.Type == "dns-01" && candidate.Status == acme.StatusPending {
			challenge = candidate
			break
		}
	}
	if challenge == nil || strings.TrimSpace(challenge.Token) == "" || strings.TrimSpace(challenge.URI) == "" {
		return errors.New("gateway tls: pending ACME authorization did not provide a usable DNS-01 challenge")
	}

	value, err := i.client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return fmt.Errorf("gateway tls: ACME DNS-01 value derivation failed: %w", err)
	}
	record, err := i.dns.Present(ctx, requestedName, value)
	if err != nil {
		return fmt.Errorf("gateway tls: ACME DNS-01 presentation failed: %w", err)
	}

	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dns01CleanupTimeout)
		defer cancel()
		if cleanupErr := i.dns.Cleanup(cleanupCtx, record); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("gateway tls: ACME DNS-01 cleanup failed: %w", cleanupErr))
		}
	}()

	fqdn, err := dns01ChallengeFQDN(requestedName)
	if err != nil {
		return err
	}
	if err := i.propagation.WaitTXT(ctx, fqdn, value); err != nil {
		return fmt.Errorf("gateway tls: ACME DNS-01 propagation failed: %w", err)
	}
	if _, err := i.client.Accept(ctx, challenge); err != nil {
		return fmt.Errorf("gateway tls: ACME DNS-01 challenge acceptance failed: %w", err)
	}
	validated, err := i.client.WaitAuthorization(ctx, authorization.URI)
	if err != nil {
		return fmt.Errorf("gateway tls: ACME DNS-01 authorization failed: %w", err)
	}
	if validated == nil || validated.Status != acme.StatusValid {
		return errors.New("gateway tls: ACME DNS-01 authorization did not become valid")
	}
	return nil
}

func validateACMEOrder(order *acme.Order, requested []string) error {
	if order == nil || strings.TrimSpace(order.URI) == "" {
		return errors.New("gateway tls: ACME order identity is incomplete")
	}
	if order.Status != acme.StatusPending && order.Status != acme.StatusReady {
		return fmt.Errorf("gateway tls: ACME order has unsupported initial status %q", order.Status)
	}
	if len(order.AuthzURLs) == 0 && order.Status == acme.StatusPending {
		return errors.New("gateway tls: pending ACME order contains no authorizations")
	}

	want := make(map[string]struct{}, len(requested))
	for _, name := range requested {
		want[strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))] = struct{}{}
	}
	if len(order.Identifiers) != len(want) {
		return errors.New("gateway tls: ACME order identifiers do not match the renewal request")
	}
	for _, identifier := range order.Identifiers {
		if identifier.Type != "dns" {
			return errors.New("gateway tls: ACME order contains a non-DNS identifier")
		}
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(identifier.Value), "."))
		if _, ok := want[name]; !ok {
			return errors.New("gateway tls: ACME order contains an unexpected DNS identifier")
		}
	}
	return nil
}

func requestedNameForAuthorization(authorization *acme.Authorization, requested []string) (string, error) {
	if authorization == nil || authorization.Identifier.Type != "dns" {
		return "", errors.New("gateway tls: ACME authorization is not a DNS authorization")
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(authorization.Identifier.Value), "."))
	if name == "" {
		return "", errors.New("gateway tls: ACME authorization DNS identifier is empty")
	}
	if authorization.Wildcard {
		name = "*." + name
	}
	for _, requestedName := range requested {
		candidate := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(requestedName), "."))
		if candidate == name {
			return candidate, nil
		}
	}
	return "", errors.New("gateway tls: ACME authorization does not belong to the renewal request")
}

func dns01ChallengeFQDN(dnsName string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dnsName), "."))
	if strings.HasPrefix(name, "*.") {
		name = strings.TrimPrefix(name, "*.")
	}
	if name == "" || strings.ContainsAny(name, " */\\") || strings.Contains(name, "*") {
		return "", errors.New("gateway tls: DNS-01 propagation name is invalid")
	}
	return "_acme-challenge." + name, nil
}

func generateCertificateKey() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
