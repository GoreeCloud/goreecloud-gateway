package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

func TestForwardingRuntimeStripsSpoofedIdentityAndEmitsObservedContext(t *testing.T) {
	observed := make(chan http.Header, 1)
	observedHost := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Header.Clone()
		observedHost <- r.Host
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	cfg := testConfig([]config.Backend{{ID: "one", URL: upstream.URL, Enabled: true}}, []string{"one"})
	handler := New(cfg)
	defer handler.Close()
	handler.checker = &fakeChecker{healthy: map[string]bool{"one": true}}

	req := httptest.NewRequest(http.MethodGet, "https://app.goreecloud.com/probe", nil)
	req.RemoteAddr = "203.0.113.9:43210"
	req.Header.Set("X-Forwarded-For", "198.51.100.77")
	req.Header.Set("X-Forwarded-Host", "spoofed.example")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Real-IP", "198.51.100.77")
	req.Header.Set("CF-Connecting-IP", "198.51.100.77")
	req.Header.Set("True-Client-IP", "198.51.100.77")

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rw.Code, rw.Body.String())
	}

	headers := <-observed
	host := <-observedHost
	if got := headers.Get("X-Forwarded-For"); got != "203.0.113.9" {
		t.Fatalf("X-Forwarded-For=%q want observed peer", got)
	}
	if got := headers.Get("X-Forwarded-Host"); got != "app.goreecloud.com" {
		t.Fatalf("X-Forwarded-Host=%q", got)
	}
	if got := headers.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("X-Forwarded-Proto=%q", got)
	}
	if host != "app.goreecloud.com" {
		t.Fatalf("upstream Host=%q", host)
	}
	for _, name := range []string{"X-Real-IP", "CF-Connecting-IP", "True-Client-IP"} {
		if got := headers.Get(name); got != "" {
			t.Fatalf("untrusted header %s survived: %q", name, got)
		}
	}
}

func TestForwardingRuntimeUsesReviewedTrustedProxyChain(t *testing.T) {
	observed := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Header.Get("X-Forwarded-For")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	cfg := testConfig([]config.Backend{{ID: "one", URL: upstream.URL, Enabled: true}}, []string{"one"})
	cfg.TrustedProxies = []string{"10.0.0.0/8"}
	handler := New(cfg)
	defer handler.Close()
	handler.checker = &fakeChecker{healthy: map[string]bool{"one": true}}

	req := httptest.NewRequest(http.MethodGet, "http://app.goreecloud.com/", nil)
	req.RemoteAddr = "10.0.0.5:43210"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.9")

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rw.Code, rw.Body.String())
	}
	if got := <-observed; got != "198.51.100.7" {
		t.Fatalf("X-Forwarded-For=%q want resolved client", got)
	}
}

func TestForwardingRuntimeRejectsMalformedTrustedProxyChain(t *testing.T) {
	cfg := testConfig([]config.Backend{{ID: "one", URL: "http://127.0.0.1:1", Enabled: true}}, []string{"one"})
	cfg.TrustedProxies = []string{"10.0.0.0/8"}
	handler := New(cfg)
	defer handler.Close()

	req := httptest.NewRequest(http.MethodGet, "http://app.goreecloud.com/", nil)
	req.RemoteAddr = "10.0.0.5:43210"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, not-an-ip")

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q", rw.Code, strings.TrimSpace(rw.Body.String()))
	}
}
