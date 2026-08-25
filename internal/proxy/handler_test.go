package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
	"github.com/GoreeCloud/goreecloud-gateway/internal/health"
)

type fakeChecker struct {
	healthy map[string]bool
}

func (f fakeChecker) Check(_ context.Context, backend config.Backend) health.Result {
	return health.Result{BackendID: backend.ID, Healthy: f.healthy[backend.ID]}
}

func TestProxyRoutesAndStreams(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "proxied:"+r.URL.Path)
	}))
	defer upstream.Close()

	cfg := testConfig([]config.Backend{{ID: "b", URL: upstream.URL, Enabled: true, HealthPath: "/"}}, []string{"b"})
	handler := New(cfg)
	handler.checker = fakeChecker{healthy: map[string]bool{"b": true}}

	req := httptest.NewRequest(http.MethodGet, "http://app.goreecloud.com/stream", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d", rw.Code)
	}
	if got := strings.TrimSpace(rw.Body.String()); got != "proxied:/stream" {
		t.Fatalf("body=%q", got)
	}
}

func TestHealthAwareSelectionSkipsUnhealthyBackend(t *testing.T) {
	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("unhealthy backend received routed request")
	}))
	defer unhealthy.Close()
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ready")
	}))
	defer ready.Close()

	cfg := testConfig([]config.Backend{
		{ID: "one", URL: unhealthy.URL, Enabled: true},
		{ID: "two", URL: ready.URL, Enabled: true},
	}, []string{"one", "two"})
	handler := New(cfg)
	handler.checker = fakeChecker{healthy: map[string]bool{"one": false, "two": true}}

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "http://app.goreecloud.com/", nil))
	if rw.Code != http.StatusOK || strings.TrimSpace(rw.Body.String()) != "ready" {
		t.Fatalf("status=%d body=%q", rw.Code, rw.Body.String())
	}
}

func TestRetryableRequestFailsOverOnServiceUnavailable(t *testing.T) {
	firstHits := 0
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits++
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "second")
	}))
	defer second.Close()

	cfg := testConfig([]config.Backend{
		{ID: "one", URL: first.URL, Enabled: true},
		{ID: "two", URL: second.URL, Enabled: true},
	}, []string{"one", "two"})
	handler := New(cfg)
	handler.checker = fakeChecker{healthy: map[string]bool{"one": true, "two": true}}

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "http://app.goreecloud.com/", nil))
	if rw.Code != http.StatusOK || strings.TrimSpace(rw.Body.String()) != "second" {
		t.Fatalf("status=%d body=%q", rw.Code, rw.Body.String())
	}
	if firstHits != 1 {
		t.Fatalf("first backend hits=%d", firstHits)
	}
}

func TestNonRetryableRequestDoesNotReplay(t *testing.T) {
	firstHits := 0
	secondHits := 0
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits++
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()

	cfg := testConfig([]config.Backend{
		{ID: "one", URL: first.URL, Enabled: true},
		{ID: "two", URL: second.URL, Enabled: true},
	}, []string{"one", "two"})
	handler := New(cfg)
	handler.checker = fakeChecker{healthy: map[string]bool{"one": true, "two": true}}

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "http://app.goreecloud.com/", strings.NewReader("payload")))
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rw.Code)
	}
	if firstHits != 1 || secondHits != 0 {
		t.Fatalf("first=%d second=%d", firstHits, secondHits)
	}
}

func TestNoHealthyBackendsFailsClosed(t *testing.T) {
	cfg := testConfig([]config.Backend{{ID: "one", URL: "http://127.0.0.1:1", Enabled: true}}, []string{"one"})
	handler := New(cfg)
	handler.checker = fakeChecker{healthy: map[string]bool{"one": false}}

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "http://app.goreecloud.com/", nil))
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rw.Code)
	}
}

func TestReloadKeepsServingNewValidatedConfig(t *testing.T) {
	one := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "one") }))
	defer one.Close()
	two := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "two") }))
	defer two.Close()

	handler := New(testConfig([]config.Backend{{ID: "b", URL: one.URL, Enabled: true}}, []string{"b"}))
	handler.checker = fakeChecker{healthy: map[string]bool{"b": true}}
	handler.Reload(testConfig([]config.Backend{{ID: "b", URL: two.URL, Enabled: true}}, []string{"b"}))

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "http://app.goreecloud.com/", nil))
	if strings.TrimSpace(rw.Body.String()) != "two" {
		t.Fatalf("body=%q", rw.Body.String())
	}
}

func testConfig(backends []config.Backend, backendIDs []string) *config.Config {
	return &config.Config{
		Schema:   "goreecloud-gateway-config/v1",
		Services: []config.Service{{ID: "svc", BackendIDs: backendIDs}},
		Backends: backends,
		Routes:   []config.Route{{ID: "r", ServiceID: "svc", Hostname: "app.goreecloud.com", PathPrefix: "/", Enabled: true}},
	}
}
