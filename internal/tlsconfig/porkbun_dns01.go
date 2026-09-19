package tlsconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	porkbunAPIBaseURL       = "https://api.porkbun.com/api/json/v3"
	porkbunDNS01TTL         = "600"
	porkbunMaxResponseBytes = 64 << 10
)

var porkbunRecordIDPattern = regexp.MustCompile(`^[0-9]+$`)

// PorkbunDNS01Provider presents and removes ACME DNS-01 TXT records in one
// explicitly configured Porkbun-managed zone. It is intentionally not a
// general-purpose DNS client.
type PorkbunDNS01Provider struct {
	domain       string
	apiKey       string
	secretAPIKey string
	baseURL      *url.URL
	httpClient   *http.Client
}

// NewPorkbunDNS01Provider creates a provider fixed to Porkbun's official API
// endpoint. Credentials remain in process memory and are never serialized into
// Gateway configuration, evidence, or logs.
func NewPorkbunDNS01Provider(domain, apiKey, secretAPIKey string, client *http.Client) (*PorkbunDNS01Provider, error) {
	return newPorkbunDNS01Provider(domain, apiKey, secretAPIKey, porkbunAPIBaseURL, client)
}

func newPorkbunDNS01Provider(domain, apiKey, secretAPIKey, baseURL string, client *http.Client) (*PorkbunDNS01Provider, error) {
	zone, err := normalizeDNSZone(domain)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(apiKey) == "" || strings.TrimSpace(secretAPIKey) == "" {
		return nil, errors.New("gateway tls: Porkbun DNS-01 credentials are required")
	}

	endpoint, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("gateway tls: Porkbun DNS-01 endpoint must be an absolute HTTPS URL")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/")

	if client == nil {
		client = &http.Client{}
	}
	safeClient := *client
	safeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &PorkbunDNS01Provider{
		domain:       zone,
		apiKey:       strings.TrimSpace(apiKey),
		secretAPIKey: strings.TrimSpace(secretAPIKey),
		baseURL:      endpoint,
		httpClient:   &safeClient,
	}, nil
}

// Present creates exactly one TXT record under _acme-challenge for a DNS name
// inside the provider's configured zone. It returns only the state required for
// exact-record cleanup.
func (p *PorkbunDNS01Provider) Present(ctx context.Context, dnsName, value string) (DNS01ChallengeRecord, error) {
	if p == nil {
		return DNS01ChallengeRecord{}, errors.New("gateway tls: Porkbun DNS-01 provider is required")
	}
	if ctx == nil {
		return DNS01ChallengeRecord{}, errors.New("gateway tls: Porkbun DNS-01 context is required")
	}
	if err := ctx.Err(); err != nil {
		return DNS01ChallengeRecord{}, fmt.Errorf("gateway tls: Porkbun DNS-01 context unavailable: %w", err)
	}
	challengeValue := strings.TrimSpace(value)
	if challengeValue == "" || len(challengeValue) > 2048 || strings.ContainsAny(challengeValue, "\r\n") {
		return DNS01ChallengeRecord{}, errors.New("gateway tls: Porkbun DNS-01 challenge value is invalid")
	}

	recordName, err := challengeRecordName(dnsName, p.domain)
	if err != nil {
		return DNS01ChallengeRecord{}, err
	}
	body := struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Content string `json:"content"`
		TTL     string `json:"ttl"`
	}{
		Name:    recordName,
		Type:    "TXT",
		Content: challengeValue,
		TTL:     porkbunDNS01TTL,
	}

	response, err := p.write(ctx, "/dns/create/"+url.PathEscape(p.domain), body, porkbunIdempotencyKey("create", p.domain, recordName, challengeValue))
	if err != nil {
		return DNS01ChallengeRecord{}, err
	}
	id, err := parsePorkbunRecordID(response.ID)
	if err != nil {
		return DNS01ChallengeRecord{}, err
	}
	return DNS01ChallengeRecord{
		Provider: DNS01ProviderPorkbun,
		Zone:     p.domain,
		Name:     recordName,
		ID:       id,
	}, nil
}

// Cleanup deletes only the exact Porkbun record ID returned by Present.
func (p *PorkbunDNS01Provider) Cleanup(ctx context.Context, record DNS01ChallengeRecord) error {
	if p == nil {
		return errors.New("gateway tls: Porkbun DNS-01 provider is required")
	}
	if ctx == nil {
		return errors.New("gateway tls: Porkbun DNS-01 context is required")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gateway tls: Porkbun DNS-01 context unavailable: %w", err)
	}
	if record.Provider != DNS01ProviderPorkbun {
		return errors.New("gateway tls: Porkbun DNS-01 cleanup record belongs to a different provider")
	}
	if record.Zone != p.domain {
		return errors.New("gateway tls: Porkbun DNS-01 cleanup record belongs to a different zone")
	}
	if !validChallengeRecordName(record.Name) {
		return errors.New("gateway tls: Porkbun DNS-01 cleanup record name is outside the challenge namespace")
	}
	if !porkbunRecordIDPattern.MatchString(record.ID) {
		return errors.New("gateway tls: Porkbun DNS-01 cleanup record id is invalid")
	}

	path := "/dns/delete/" + url.PathEscape(p.domain) + "/" + url.PathEscape(record.ID)
	_, err := p.write(ctx, path, struct{}{}, porkbunIdempotencyKey("delete", p.domain, record.Name, record.ID))
	return err
}

type porkbunAPIResponse struct {
	Status string          `json:"status"`
	Code   string          `json:"code,omitempty"`
	ID     json.RawMessage `json:"id,omitempty"`
}

func (p *PorkbunDNS01Provider) write(ctx context.Context, path string, payload any, idempotencyKey string) (porkbunAPIResponse, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return porkbunAPIResponse{}, fmt.Errorf("gateway tls: encode Porkbun DNS-01 request: %w", err)
	}

	endpoint := *p.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return porkbunAPIResponse{}, fmt.Errorf("gateway tls: build Porkbun DNS-01 request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-API-Key", p.apiKey)
	request.Header.Set("X-Secret-API-Key", p.secretAPIKey)
	request.Header.Set("Idempotency-Key", idempotencyKey)

	response, err := p.httpClient.Do(request)
	if err != nil {
		return porkbunAPIResponse{}, fmt.Errorf("gateway tls: Porkbun DNS-01 request failed: %w", err)
	}
	defer response.Body.Close()

	reader := io.LimitReader(response.Body, porkbunMaxResponseBytes+1)
	body, err := io.ReadAll(reader)
	if err != nil {
		return porkbunAPIResponse{}, fmt.Errorf("gateway tls: read Porkbun DNS-01 response: %w", err)
	}
	if len(body) > porkbunMaxResponseBytes {
		return porkbunAPIResponse{}, errors.New("gateway tls: Porkbun DNS-01 response exceeded size limit")
	}

	var parsed porkbunAPIResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return porkbunAPIResponse{}, errors.New("gateway tls: Porkbun DNS-01 response was not valid JSON")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 || !strings.EqualFold(parsed.Status, "SUCCESS") {
		code := strings.TrimSpace(parsed.Code)
		if code == "" {
			code = "unspecified"
		}
		if len(code) > 80 {
			code = code[:80]
		}
		return porkbunAPIResponse{}, fmt.Errorf("gateway tls: Porkbun DNS-01 request rejected (http=%d code=%s)", response.StatusCode, code)
	}
	return parsed, nil
}

func normalizeDNSZone(value string) (string, error) {
	zone := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if zone == "" || strings.ContainsAny(zone, " */\\") || !strings.Contains(zone, ".") {
		return "", errors.New("gateway tls: Porkbun DNS-01 zone is invalid")
	}
	for _, label := range strings.Split(zone, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("gateway tls: Porkbun DNS-01 zone is invalid")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", errors.New("gateway tls: Porkbun DNS-01 zone is invalid")
			}
		}
	}
	return zone, nil
}

func challengeRecordName(dnsName, zone string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dnsName), "."))
	if strings.HasPrefix(name, "*.") {
		name = strings.TrimPrefix(name, "*.")
	}
	if name == "" || strings.Contains(name, "*") {
		return "", errors.New("gateway tls: DNS-01 name is invalid")
	}

	var relative string
	switch {
	case name == zone:
		relative = ""
	case strings.HasSuffix(name, "."+zone):
		relative = strings.TrimSuffix(name, "."+zone)
	default:
		return "", errors.New("gateway tls: DNS-01 name is outside the configured Porkbun zone")
	}

	recordName := "_acme-challenge"
	if relative != "" {
		recordName += "." + relative
	}
	if !validChallengeRecordName(recordName) {
		return "", errors.New("gateway tls: DNS-01 challenge name is invalid")
	}
	return recordName, nil
}

func validChallengeRecordName(name string) bool {
	if name == "_acme-challenge" {
		return true
	}
	if !strings.HasPrefix(name, "_acme-challenge.") {
		return false
	}
	suffix := strings.TrimPrefix(name, "_acme-challenge.")
	return suffix != "" && !strings.ContainsAny(suffix, " */\\") && !strings.Contains(suffix, "..")
}

func parsePorkbunRecordID(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("gateway tls: Porkbun DNS-01 response omitted record id")
	}
	var asString string
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &asString); err != nil {
			return "", errors.New("gateway tls: Porkbun DNS-01 response record id is invalid")
		}
	} else {
		var asNumber json.Number
		if err := json.Unmarshal(raw, &asNumber); err != nil {
			return "", errors.New("gateway tls: Porkbun DNS-01 response record id is invalid")
		}
		asString = asNumber.String()
	}
	if !porkbunRecordIDPattern.MatchString(asString) {
		return "", errors.New("gateway tls: Porkbun DNS-01 response record id is invalid")
	}
	return asString, nil
}

func porkbunIdempotencyKey(operation, domain, name, value string) string {
	sum := sha256.Sum256([]byte(operation + "\x00" + domain + "\x00" + name + "\x00" + value))
	return fmt.Sprintf("goreecloud-gateway-dns01-%s-%x", operation, sum[:16])
}
