package tlsconfig

import (
	"crypto"
	"net/http"

	"golang.org/x/crypto/acme"
)

// newACMEProtocolClient centralizes the transport and identity constraints used
// by ACME account and issuance flows. Redirects are refused so signed ACME
// requests are never silently replayed to an unexpected origin.
func newACMEProtocolClient(accountKey crypto.Signer, directoryURL string, httpClient *http.Client) (*acme.Client, error) {
	if _, _, err := describeACMEAccountSigner(accountKey); err != nil {
		return nil, err
	}
	directory, err := normalizeACMEDirectoryURL(directoryURL)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	safeHTTPClient := *httpClient
	safeHTTPClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &acme.Client{
		Key:          accountKey,
		HTTPClient:   &safeHTTPClient,
		DirectoryURL: directory,
		UserAgent:    "GoreeCloud-Gateway/Development",
	}, nil
}
