package routing

import (
	"net/http"
	"sort"
	"strings"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

type Match struct { Route config.Route; Service config.Service; Backend config.Backend }

func Resolve(cfg *config.Config, req *http.Request) (Match, bool) {
	host := req.Host
	if h, _, found := strings.Cut(host, ":"); found { host = h }
	var routes []config.Route
	for _, r := range cfg.Routes { if r.Enabled { routes = append(routes, r) } }
	sort.SliceStable(routes, func(i, j int) bool { return len(routes[i].PathPrefix) > len(routes[j].PathPrefix) })
	for _, r := range routes {
		if !strings.EqualFold(host, r.Hostname) || !strings.HasPrefix(req.URL.Path, normalizedPrefix(r.PathPrefix)) || !methodAllowed(r.Methods, req.Method) { continue }
		s, ok := cfg.Service(r.ServiceID); if !ok { continue }
		for _, id := range s.BackendIDs {
			b, ok := cfg.Backend(id); if ok && b.Enabled { return Match{Route:r, Service:s, Backend:b}, true }
		}
	}
	return Match{}, false
}

func normalizedPrefix(v string) string { if v == "" { return "/" }; return v }
func methodAllowed(methods []string, method string) bool { if len(methods)==0 { return true }; for _, m := range methods { if strings.EqualFold(m, method) { return true } }; return false }
