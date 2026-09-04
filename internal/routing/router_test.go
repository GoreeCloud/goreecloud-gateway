package routing

import (
	"net/http/httptest"
	"testing"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

func TestResolvePrefersLongestPath(t *testing.T) {
	cfg := &config.Config{Schema:"goreecloud-gateway-config/v1", Services:[]config.Service{{ID:"svc", BackendIDs:[]string{"b"}}}, Backends:[]config.Backend{{ID:"b", URL:"http://127.0.0.1:9000", Enabled:true}}, Routes:[]config.Route{{ID:"root", ServiceID:"svc", Hostname:"app.goreecloud.com", PathPrefix:"/", Enabled:true},{ID:"api", ServiceID:"svc", Hostname:"app.goreecloud.com", PathPrefix:"/api", Methods:[]string{"GET"}, Enabled:true}}}
	r := httptest.NewRequest("GET", "http://app.goreecloud.com/api/health", nil)
	m, ok := Resolve(cfg, r); if !ok { t.Fatal("expected route") }; if m.Route.ID != "api" { t.Fatalf("got %s", m.Route.ID) }
}

func TestResolveRejectsWrongMethod(t *testing.T) {
	cfg := &config.Config{Schema:"goreecloud-gateway-config/v1", Services:[]config.Service{{ID:"svc", BackendIDs:[]string{"b"}}}, Backends:[]config.Backend{{ID:"b", URL:"http://127.0.0.1:9000", Enabled:true}}, Routes:[]config.Route{{ID:"api", ServiceID:"svc", Hostname:"app.goreecloud.com", PathPrefix:"/api", Methods:[]string{"GET"}, Enabled:true}}}
	r := httptest.NewRequest("POST", "http://app.goreecloud.com/api", nil)
	if _, ok := Resolve(cfg, r); ok { t.Fatal("unexpected route") }
}
