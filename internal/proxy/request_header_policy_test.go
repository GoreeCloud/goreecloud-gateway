package proxy

import (
	"net/http"
	"testing"
)

func TestSanitizeInboundProxyHeadersRemovesForwardingIdentity(t *testing.T) {
	header := http.Header{}
	header.Set("Forwarded", "for=203.0.113.9;proto=https")
	header.Set("X-Forwarded-For", "203.0.113.9")
	header.Set("X-Forwarded-Host", "spoofed.example")
	header.Set("X-Forwarded-Proto", "https")
	header.Set("X-Forwarded-Port", "443")
	header.Set("X-Real-IP", "203.0.113.9")
	header.Set("CF-Connecting-IP", "203.0.113.9")
	header.Set("True-Client-IP", "203.0.113.9")

	SanitizeInboundProxyHeaders(header)

	for _, name := range untrustedForwardingRequestHeaders {
		if got := header.Get(name); got != "" {
			t.Fatalf("header %s survived sanitization: %q", name, got)
		}
	}
}

func TestSanitizeInboundProxyHeadersRemovesConnectionNamedHeaders(t *testing.T) {
	header := http.Header{}
	header.Set("Connection", "X-Remove-Me, keep-alive")
	header.Set("X-Remove-Me", "client-controlled")
	header.Set("Keep-Alive", "timeout=5")
	header.Set("Upgrade", "websocket")

	SanitizeInboundProxyHeaders(header)

	for _, name := range []string{"Connection", "X-Remove-Me", "Keep-Alive", "Upgrade"} {
		if got := header.Get(name); got != "" {
			t.Fatalf("header %s survived sanitization: %q", name, got)
		}
	}
}

func TestSanitizeInboundProxyHeadersPreservesApplicationHeaders(t *testing.T) {
	header := http.Header{}
	header.Set("Authorization", "Bearer application-token")
	header.Set("Cookie", "session=application-session")
	header.Set("X-GoreeCloud-App", "vault")

	SanitizeInboundProxyHeaders(header)

	if got := header.Get("Authorization"); got != "Bearer application-token" {
		t.Fatalf("authorization header changed: %q", got)
	}
	if got := header.Get("Cookie"); got != "session=application-session" {
		t.Fatalf("cookie header changed: %q", got)
	}
	if got := header.Get("X-GoreeCloud-App"); got != "vault" {
		t.Fatalf("application header changed: %q", got)
	}
}

func TestSanitizeInboundProxyHeadersAcceptsNil(t *testing.T) {
	SanitizeInboundProxyHeaders(nil)
}
