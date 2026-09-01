package publication

import (
	"sort"
	"slices"
)

const CaddyDataPlaneAuthority = "GoreeCloud/CaddyDataPlane"

// Plan is the validated, deterministic publication intent that a data-plane
// adapter can later translate into Caddy configuration.  Building a plan has
// no side effects and never contacts or mutates the active data plane.
type Plan struct {
	SchemaVersion      int            `json:"schema_version"`
	DataPlaneAuthority string         `json:"data_plane_authority"`
	Routes             []PlannedRoute `json:"routes"`
}

// PlannedRoute is a normalized route carried from publication policy into the
// future reconciler boundary.
type PlannedRoute struct {
	Hostname     string   `json:"hostname"`
	Upstream     string   `json:"upstream"`
	Exposure     string   `json:"exposure"`
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
}

// BuildPlan validates config and returns a deterministic, mutation-free plan.
// Route and CIDR ordering is canonicalized so later adapters can compare plans
// byte-for-byte before deciding whether a data-plane change is necessary.
func BuildPlan(config Config) (Plan, error) {
	if err := Validate(config); err != nil {
		return Plan{}, err
	}

	routes := make([]PlannedRoute, 0, len(config.Routes))
	for _, route := range config.Routes {
		allowedCIDRs := slices.Clone(route.AllowedCIDRs)
		sort.Strings(allowedCIDRs)
		routes = append(routes, PlannedRoute{
			Hostname:     route.Hostname,
			Upstream:     route.Upstream,
			Exposure:     route.Exposure,
			AllowedCIDRs: allowedCIDRs,
		})
	}
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Hostname < routes[j].Hostname
	})

	return Plan{
		SchemaVersion:      SchemaVersion,
		DataPlaneAuthority: CaddyDataPlaneAuthority,
		Routes:             routes,
	}, nil
}
