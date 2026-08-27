package routing

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

func TestTLSRequiredRouteDoesNotResolveOverPlaintext(t *testing.T) {
	cfg := tlsRouteConfig("required")
	req := httptest.NewRequest(http.MethodGet, "http://service.goreecloud.com/", nil)
	if _, ok := ResolveCandidates(cfg, req); ok {
		t.Fatal("TLS-required route resolved over plaintext HTTP")
	}
}

func TestTLSRequiredRouteResolvesForTLSRequest(t *testing.T) {
	cfg := tlsRouteConfig("required")
	req := httptest.NewRequest(http.MethodGet, "https://service.goreecloud.com/", nil)
	req.TLS = &tls.ConnectionState{}
	if _, ok := ResolveCandidates(cfg, req); !ok {
		t.Fatal("TLS-required route did not resolve for TLS request")
	}
}

func TestTLSDisabledRouteCanResolveOverPlaintext(t *testing.T) {
	cfg := tlsRouteConfig("disabled")
	req := httptest.NewRequest(http.MethodGet, "http://service.goreecloud.com/", nil)
	if _, ok := ResolveCandidates(cfg, req); !ok {
		t.Fatal("TLS-disabled route did not resolve over plaintext")
	}
}

func tlsRouteConfig(mode string) *config.Config {
	profile := ""
	if mode == "required" {
		profile = "default-private"
	}
	return &config.Config{
		Schema: "goreecloud-gateway-config/v1",
		Services: []config.Service{{
			ID:         "svc",
			Name:       "Service",
			BackendIDs: []string{"backend"},
		}},
		Routes: []config.Route{{
			ID:         "route",
			ServiceID:  "svc",
			Hostname:   "service.goreecloud.com",
			PathPrefix: "/",
			Enabled:    true,
			TLS: config.RouteTLS{
				Mode:               mode,
				CertificateProfile: profile,
			},
		}},
		Backends: []config.Backend{{ID: "backend", URL: "http://127.0.0.1:8080", Enabled: true}},
	}
}
