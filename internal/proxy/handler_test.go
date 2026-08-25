package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

func TestProxyRoutesAndStreams(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "text/plain"); _, _ = io.WriteString(w, "proxied:"+r.URL.Path) }))
	defer upstream.Close()
	cfg := &config.Config{Schema:"goreecloud-gateway-config/v1", Services:[]config.Service{{ID:"svc", BackendIDs:[]string{"b"}}}, Backends:[]config.Backend{{ID:"b", URL:upstream.URL, Enabled:true}}, Routes:[]config.Route{{ID:"r", ServiceID:"svc", Hostname:"app.goreecloud.com", PathPrefix:"/", Enabled:true}}}
	h := New(cfg)
	req := httptest.NewRequest("GET", "http://app.goreecloud.com/stream", nil)
	rw := httptest.NewRecorder(); h.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK { t.Fatalf("status=%d", rw.Code) }
	if got := strings.TrimSpace(rw.Body.String()); got != "proxied:/stream" { t.Fatalf("body=%q", got) }
}

func TestReloadKeepsServingNewValidatedConfig(t *testing.T) {
	one := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "one") })); defer one.Close()
	two := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "two") })); defer two.Close()
	makeCfg := func(target string) *config.Config { return &config.Config{Schema:"goreecloud-gateway-config/v1", Services:[]config.Service{{ID:"svc", BackendIDs:[]string{"b"}}}, Backends:[]config.Backend{{ID:"b", URL:target, Enabled:true}}, Routes:[]config.Route{{ID:"r", ServiceID:"svc", Hostname:"app.goreecloud.com", PathPrefix:"/", Enabled:true}}} }
	h := New(makeCfg(one.URL)); h.Reload(makeCfg(two.URL))
	rw := httptest.NewRecorder(); h.ServeHTTP(rw, httptest.NewRequest("GET", "http://app.goreecloud.com/", nil))
	if strings.TrimSpace(rw.Body.String()) != "two" { t.Fatalf("body=%q", rw.Body.String()) }
}
