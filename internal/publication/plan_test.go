package publication

import (
	"reflect"
	"testing"
)

func TestBuildPlanCanonicalizesRouteAndCIDROrder(t *testing.T) {
	config := Config{
		SchemaVersion: SchemaVersion,
		Routes: []Route{
			{
				Hostname:     "manager.goreecloud.com",
				Upstream:     "http://goreecloud-manager:8000",
				Exposure:     ExposurePrivate,
				AllowedCIDRs: []string{"fd00:100::/48", "100.64.0.0/10"},
			},
			{
				Hostname: "api.goreecloud.com",
				Upstream: "http://goreecloud-api:8000",
				Exposure: ExposurePublic,
			},
		},
	}

	plan, err := BuildPlan(config)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if plan.DataPlaneAuthority != CaddyDataPlaneAuthority {
		t.Fatalf("unexpected data-plane authority %q", plan.DataPlaneAuthority)
	}
	if got, want := []string{plan.Routes[0].Hostname, plan.Routes[1].Hostname}, []string{"api.goreecloud.com", "manager.goreecloud.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("route order = %v, want %v", got, want)
	}
	if got, want := plan.Routes[1].AllowedCIDRs, []string{"100.64.0.0/10", "fd00:100::/48"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CIDR order = %v, want %v", got, want)
	}
}

func TestBuildPlanDoesNotAliasPolicySlices(t *testing.T) {
	config := Config{
		SchemaVersion: SchemaVersion,
		Routes: []Route{{
			Hostname:     "manager.goreecloud.com",
			Upstream:     "http://goreecloud-manager:8000",
			Exposure:     ExposurePrivate,
			AllowedCIDRs: []string{"100.64.0.0/10"},
		}},
	}

	plan, err := BuildPlan(config)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	config.Routes[0].AllowedCIDRs[0] = "10.0.0.0/8"
	if got := plan.Routes[0].AllowedCIDRs[0]; got != "100.64.0.0/10" {
		t.Fatalf("plan mutated through policy alias: %q", got)
	}
}

func TestBuildPlanFailsClosedOnInvalidPolicy(t *testing.T) {
	_, err := BuildPlan(Config{
		SchemaVersion: SchemaVersion,
		Routes: []Route{{
			Hostname: "api.goreecloud.com",
			Upstream: "http://user:secret@goreecloud-api:8000",
			Exposure: ExposurePublic,
		}},
	})
	if err == nil {
		t.Fatal("expected invalid policy to fail closed")
	}
}
