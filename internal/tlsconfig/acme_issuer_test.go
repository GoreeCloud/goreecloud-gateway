package tlsconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

type fakeDNS01Provider struct {
	presentName  string
	presentValue string
	record       DNS01ChallengeRecord
	presentCalls int
	cleanupCalls int
	cleanupErr   error
}

func (p *fakeDNS01Provider) Present(_ context.Context, name, value string) (DNS01ChallengeRecord, error) {
	p.presentCalls++
	p.presentName = name
	p.presentValue = value
	if p.record.ID == "" {
		p.record = DNS01ChallengeRecord{Provider: "fake", Zone: "example.test", Name: "_acme-challenge", ID: "1"}
	}
	return p.record, nil
}

func (p *fakeDNS01Provider) Cleanup(_ context.Context, record DNS01ChallengeRecord) error {
	p.cleanupCalls++
	if record != p.record {
		return errors.New("unexpected cleanup record")
	}
	return p.cleanupErr
}

type fakePropagationWaiter struct {
	name  string
	value string
	calls int
	err   error
}

func (w *fakePropagationWaiter) WaitTXT(_ context.Context, name, value string) error {
	w.calls++
	w.name = name
	w.value = value
	return w.err
}

type fakeACMEOrderClient struct {
	account       *acme.Account
	order         *acme.Order
	authorization *acme.Authorization
	waitOrder     *acme.Order
	recordValue   string

	accepted  int
	finalized int
}

func (c *fakeACMEOrderClient) GetReg(context.Context, string) (*acme.Account, error) {
	if c.account == nil {
		return nil, acme.ErrNoAccount
	}
	return c.account, nil
}

func (c *fakeACMEOrderClient) AuthorizeOrder(_ context.Context, identifiers []acme.AuthzID, _ ...acme.OrderOption) (*acme.Order, error) {
	if c.order == nil {
		c.order = &acme.Order{
			URI:         "https://ca.example/order/1",
			Status:      acme.StatusPending,
			Identifiers: append([]acme.AuthzID(nil), identifiers...),
			AuthzURLs:   []string{"https://ca.example/authz/1"},
			FinalizeURL: "https://ca.example/order/1/finalize",
		}
	}
	return c.order, nil
}

func (c *fakeACMEOrderClient) GetAuthorization(context.Context, string) (*acme.Authorization, error) {
	return c.authorization, nil
}

func (c *fakeACMEOrderClient) DNS01ChallengeRecord(string) (string, error) {
	if c.recordValue == "" {
		return "dns-record-value", nil
	}
	return c.recordValue, nil
}

func (c *fakeACMEOrderClient) Accept(_ context.Context, _ *acme.Challenge) (*acme.Challenge, error) {
	c.accepted++
	return &acme.Challenge{Type: "dns-01", Status: acme.StatusProcessing}, nil
}

func (c *fakeACMEOrderClient) WaitAuthorization(_ context.Context, uri string) (*acme.Authorization, error) {
	return &acme.Authorization{URI: uri, Status: acme.StatusValid}, nil
}

func (c *fakeACMEOrderClient) WaitOrder(context.Context, string) (*acme.Order, error) {
	if c.waitOrder != nil {
		return c.waitOrder, nil
	}
	return &acme.Order{
		URI:         "https://ca.example/order/1",
		Status:      acme.StatusReady,
		FinalizeURL: "https://ca.example/order/1/finalize",
	}, nil
}

func (c *fakeACMEOrderClient) CreateOrderCert(_ context.Context, _ string, csrDER []byte, _ bool) ([][]byte, string, error) {
	c.finalized++
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(9001),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, "", err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, "", err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(9002),
		Subject:      csr.Subject,
		DNSNames:     append([]string(nil), csr.DNSNames...),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, "", err
	}
	return [][]byte{leafDER, caDER}, "https://ca.example/cert/1", nil
}

func baseACMEIssuerFixture() (*ACMERenewalIssuer, *fakeACMEOrderClient, *fakeDNS01Provider, *fakePropagationWaiter, RenewalRequest) {
	client := &fakeACMEOrderClient{
		account: &acme.Account{Status: acme.StatusValid},
		authorization: &acme.Authorization{
			URI:        "https://ca.example/authz/1",
			Status:     acme.StatusPending,
			Identifier: acme.AuthzID{Type: "dns", Value: "gateway.example.test"},
			Challenges: []*acme.Challenge{{
				Type:   "dns-01",
				URI:    "https://ca.example/challenge/1",
				Token:  "token-1",
				Status: acme.StatusPending,
			}},
		},
	}
	dns := &fakeDNS01Provider{}
	propagation := &fakePropagationWaiter{}
	issuer := newACMERenewalIssuer(client, dns, propagation)
	request := RenewalRequest{
		ProfileID:     "primary",
		CurrentSerial: "0",
		DNSNames:      []string{"gateway.example.test"},
		RequestedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Reason:        "certificate-renewal-window-reached",
	}
	return issuer, client, dns, propagation, request
}

func TestACMERenewalIssuerCompletesDNS01CleansUpAndReturnsMatchingMaterial(t *testing.T) {
	issuer, client, dns, propagation, request := baseACMEIssuerFixture()

	certPEM, keyPEM, err := issuer.IssueRenewal(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if dns.presentCalls != 1 || dns.cleanupCalls != 1 {
		t.Fatalf("DNS present/cleanup calls = %d/%d", dns.presentCalls, dns.cleanupCalls)
	}
	if dns.presentName != "gateway.example.test" || dns.presentValue != "dns-record-value" {
		t.Fatalf("unexpected DNS presentation: name=%q value=%q", dns.presentName, dns.presentValue)
	}
	if propagation.calls != 1 || propagation.name != "_acme-challenge.gateway.example.test" || propagation.value != "dns-record-value" {
		t.Fatalf("unexpected propagation wait: %+v", propagation)
	}
	if client.accepted != 1 || client.finalized != 1 {
		t.Fatalf("ACME accepted/finalized = %d/%d", client.accepted, client.finalized)
	}
	if _, _, err := ValidateRenewalCandidate(request, certPEM, keyPEM, time.Now().UTC()); err != nil {
		t.Fatalf("issued material failed Gateway candidate validation: %v", err)
	}
}

func TestACMERenewalIssuerFailsClosedWhenChallengeCleanupFails(t *testing.T) {
	issuer, client, dns, _, request := baseACMEIssuerFixture()
	dns.cleanupErr = errors.New("cleanup unavailable")

	if _, _, err := issuer.IssueRenewal(context.Background(), request); err == nil {
		t.Fatal("cleanup failure unexpectedly allowed issuance")
	}
	if client.finalized != 0 {
		t.Fatalf("certificate finalized despite cleanup failure: %d", client.finalized)
	}
	if dns.cleanupCalls != 1 {
		t.Fatalf("cleanup calls=%d", dns.cleanupCalls)
	}
}

func TestACMERenewalIssuerRejectsAuthorizationOutsideRequestedNames(t *testing.T) {
	issuer, client, dns, _, request := baseACMEIssuerFixture()
	client.authorization.Identifier.Value = "unexpected.example.test"

	if _, _, err := issuer.IssueRenewal(context.Background(), request); err == nil {
		t.Fatal("unexpected authorization identity accepted")
	}
	if dns.presentCalls != 0 || client.finalized != 0 {
		t.Fatal("out-of-scope authorization caused side effects")
	}
}

func TestACMERenewalIssuerRequiresDNS01ForPendingAuthorization(t *testing.T) {
	issuer, client, dns, _, request := baseACMEIssuerFixture()
	client.authorization.Challenges = []*acme.Challenge{{
		Type:   "http-01",
		URI:    "https://ca.example/challenge/1",
		Token:  "token-1",
		Status: acme.StatusPending,
	}}

	if _, _, err := issuer.IssueRenewal(context.Background(), request); err == nil {
		t.Fatal("pending authorization without DNS-01 unexpectedly accepted")
	}
	if dns.presentCalls != 0 || client.finalized != 0 {
		t.Fatal("unsupported challenge caused side effects")
	}
}

func TestACMERenewalIssuerSkipsAlreadyValidAuthorization(t *testing.T) {
	issuer, client, dns, propagation, request := baseACMEIssuerFixture()
	client.authorization.Status = acme.StatusValid

	if _, _, err := issuer.IssueRenewal(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if dns.presentCalls != 0 || dns.cleanupCalls != 0 || propagation.calls != 0 || client.accepted != 0 {
		t.Fatal("already-valid authorization triggered DNS challenge work")
	}
	if client.finalized != 1 {
		t.Fatalf("finalized=%d", client.finalized)
	}
}

func TestACMERenewalIssuerPreservesWildcardRequestIdentity(t *testing.T) {
	issuer, client, dns, propagation, request := baseACMEIssuerFixture()
	request.DNSNames = []string{"*.goreecloud.com"}
	client.order = &acme.Order{
		URI:         "https://ca.example/order/1",
		Status:      acme.StatusPending,
		Identifiers: []acme.AuthzID{{Type: "dns", Value: "*.goreecloud.com"}},
		AuthzURLs:   []string{"https://ca.example/authz/1"},
		FinalizeURL: "https://ca.example/order/1/finalize",
	}
	client.authorization.Identifier.Value = "goreecloud.com"
	client.authorization.Wildcard = true

	if _, _, err := issuer.IssueRenewal(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if dns.presentName != "*.goreecloud.com" {
		t.Fatalf("wildcard presentation name=%q", dns.presentName)
	}
	if propagation.name != "_acme-challenge.goreecloud.com" {
		t.Fatalf("wildcard propagation name=%q", propagation.name)
	}
}

func TestNewACMERenewalIssuerRejectsUnsafeConstruction(t *testing.T) {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dns := &fakeDNS01Provider{}
	for _, directory := range []string{"", "http://ca.example/directory", "https://user@ca.example/directory", "https://ca.example/directory?secret=x"} {
		if _, err := NewACMERenewalIssuer(accountKey, directory, dns, &fakePropagationWaiter{}, &http.Client{}); err == nil {
			t.Fatalf("unsafe ACME directory %q unexpectedly accepted", directory)
		}
	}
	if _, err := NewACMERenewalIssuer(nil, "https://ca.example/directory", dns, &fakePropagationWaiter{}, nil); err == nil {
		t.Fatal("nil ACME account key unexpectedly accepted")
	}
}

type fakeTXTResolver struct {
	responses [][]string
	calls     int
}

func (r *fakeTXTResolver) LookupTXT(context.Context, string) ([]string, error) {
	index := r.calls
	r.calls++
	if index >= len(r.responses) {
		index = len(r.responses) - 1
	}
	return r.responses[index], nil
}

func TestResolverDNS01PropagationWaiterWaitsForExactValue(t *testing.T) {
	resolver := &fakeTXTResolver{responses: [][]string{{"old"}, {"old", "expected"}}}
	waiter := ResolverDNS01PropagationWaiter{
		Resolver:     resolver,
		PollInterval: time.Millisecond,
		Timeout:      time.Second,
	}
	if err := waiter.WaitTXT(context.Background(), "_acme-challenge.example.test", "expected"); err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 2 {
		t.Fatalf("resolver calls=%d", resolver.calls)
	}
}
