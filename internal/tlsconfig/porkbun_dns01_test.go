package tlsconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestPorkbunDNS01PresentAndCleanupUseBoundedExactRecordOperations(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()

		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if r.Header.Get("X-API-Key") != "pk-test" || r.Header.Get("X-Secret-API-Key") != "sk-test" {
			t.Fatal("Porkbun credentials were not sent in headers")
		}
		if !strings.HasPrefix(r.Header.Get("Idempotency-Key"), "goreecloud-gateway-dns01-") {
			t.Fatal("missing bounded idempotency key")
		}

		switch r.URL.Path {
		case "/dns/create/goreecloud.com":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["name"] != "_acme-challenge.search" || body["type"] != "TXT" || body["content"] != "challenge-value" || body["ttl"] != "600" {
				t.Fatalf("unexpected create body: %#v", body)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"SUCCESS","id":252962595}`))
		case "/dns/delete/goreecloud.com/252962595":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 0 {
				t.Fatalf("cleanup body was not empty: %#v", body)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"SUCCESS"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider, err := newPorkbunDNS01Provider("goreecloud.com", "pk-test", "sk-test", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	record, err := provider.Present(context.Background(), "search.goreecloud.com", "challenge-value")
	if err != nil {
		t.Fatal(err)
	}
	if record.Provider != DNS01ProviderPorkbun || record.Zone != "goreecloud.com" || record.Name != "_acme-challenge.search" || record.ID != "252962595" {
		t.Fatalf("unexpected challenge record: %+v", record)
	}
	if err := provider.Cleanup(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 {
		t.Fatalf("requests=%v", paths)
	}
}

func TestPorkbunDNS01WildcardUsesBaseName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["name"] != "_acme-challenge" {
			t.Fatalf("challenge record name=%v", body["name"])
		}
		_, _ = w.Write([]byte(`{"status":"SUCCESS","id":"44"}`))
	}))
	defer server.Close()

	provider, err := newPorkbunDNS01Provider("goreecloud.com", "pk-test", "sk-test", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Present(context.Background(), "*.goreecloud.com", "challenge-value"); err != nil {
		t.Fatal(err)
	}
}

func TestPorkbunDNS01RejectsNamesOutsideConfiguredZoneWithoutNetwork(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()

	provider, err := newPorkbunDNS01Provider("goreecloud.com", "pk-test", "sk-test", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Present(context.Background(), "example.net", "challenge-value"); err == nil {
		t.Fatal("out-of-zone challenge unexpectedly accepted")
	}
	if calls != 0 {
		t.Fatalf("network calls=%d", calls)
	}
}

func TestPorkbunDNS01CleanupRejectsNonChallengeRecord(t *testing.T) {
	provider, err := newPorkbunDNS01Provider("goreecloud.com", "pk-test", "sk-test", "https://example.invalid/api/json/v3", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = provider.Cleanup(context.Background(), PorkbunDNS01Record{
		Domain: "goreecloud.com",
		Name:   "www",
		ID:     "123",
	})
	if err == nil {
		t.Fatal("non-challenge record cleanup unexpectedly accepted")
	}
}

func TestPorkbunDNS01RefusesRedirectsBeforeCredentialForwarding(t *testing.T) {
	redirected := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected++
		http.Error(w, "credential leak", http.StatusInternalServerError)
	}))
	defer target.Close()

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	provider, err := newPorkbunDNS01Provider("goreecloud.com", "pk-test", "sk-test", redirector.URL, redirector.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Present(context.Background(), "search.goreecloud.com", "challenge-value"); err == nil {
		t.Fatal("redirecting Porkbun endpoint unexpectedly accepted")
	}
	if redirected != 0 {
		t.Fatalf("credentials followed redirect %d time(s)", redirected)
	}
}

func TestPorkbunDNS01RejectsOversizedAndFailedResponsesWithoutEchoingBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		handler http.HandlerFunc
	}{
		{
			name: "oversized",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(strings.Repeat("x", porkbunMaxResponseBytes+1)))
			},
		},
		{
			name: "api-failure",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"status":"ERROR","code":"BAD_REQUEST","message":"do-not-echo-sensitive-details"}`))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(tc.handler)
			defer server.Close()
			provider, err := newPorkbunDNS01Provider("goreecloud.com", "pk-test", "sk-test", server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.Present(context.Background(), "search.goreecloud.com", "challenge-value")
			if err == nil {
				t.Fatal("failed response unexpectedly accepted")
			}
			if strings.Contains(err.Error(), "do-not-echo-sensitive-details") || strings.Contains(err.Error(), "challenge-value") {
				t.Fatalf("error leaked response or challenge content: %v", err)
			}
		})
	}
}
