package publication

import (
	"strings"
	"testing"
)

func TestValidateAcceptsPublicAndPrivateRoutes(t *testing.T) {
	config := Config{
		SchemaVersion: SchemaVersion,
		Routes: []Route{
			{
				Hostname: "api.goreecloud.com",
				Upstream: "http://goreecloud-api:8000",
				Exposure: ExposurePublic,
			},
			{
				Hostname:     "manager.goreecloud.com",
				Upstream:     "http://goreecloud-manager:8000",
				Exposure:     ExposurePrivate,
				AllowedCIDRs: []string{"100.64.0.0/10"},
			},
		},
	}
	if err := Validate(config); err != nil {
		t.Fatalf("expected valid publication policy: %v", err)
	}
}

func TestValidateRejectsDuplicateHostname(t *testing.T) {
	config := Config{
		SchemaVersion: SchemaVersion,
		Routes: []Route{
			{Hostname: "api.goreecloud.com", Upstream: "http://api:8000", Exposure: ExposurePublic},
			{Hostname: "api.goreecloud.com", Upstream: "http://api-v2:8000", Exposure: ExposurePublic},
		},
	}
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "duplicate hostname") {
		t.Fatalf("expected duplicate hostname rejection, got %v", err)
	}
}

func TestValidateRejectsCredentialBearingUpstream(t *testing.T) {
	config := Config{
		SchemaVersion: SchemaVersion,
		Routes: []Route{{
			Hostname: "api.goreecloud.com",
			Upstream: "http://user:secret@api:8000",
			Exposure: ExposurePublic,
		}},
	}
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "must not contain credentials") {
		t.Fatalf("expected credential rejection, got %v", err)
	}
}

func TestValidateRequiresPrivateAllowlist(t *testing.T) {
	config := Config{
		SchemaVersion: SchemaVersion,
		Routes: []Route{{
			Hostname: "manager.goreecloud.com",
			Upstream: "http://manager:8000",
			Exposure: ExposurePrivate,
		}},
	}
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "requires at least one allowed CIDR") {
		t.Fatalf("expected private allowlist rejection, got %v", err)
	}
}

func TestValidateRejectsPublicAllowlist(t *testing.T) {
	config := Config{
		SchemaVersion: SchemaVersion,
		Routes: []Route{{
			Hostname:     "www.goreecloud.com",
			Upstream:     "http://website:8080",
			Exposure:     ExposurePublic,
			AllowedCIDRs: []string{"100.64.0.0/10"},
		}},
	}
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "public route must not define allowed CIDRs") {
		t.Fatalf("expected public allowlist rejection, got %v", err)
	}
}

func TestValidateRejectsNonCanonicalCIDR(t *testing.T) {
	config := Config{
		SchemaVersion: SchemaVersion,
		Routes: []Route{{
			Hostname:     "manager.goreecloud.com",
			Upstream:     "http://manager:8000",
			Exposure:     ExposurePrivate,
			AllowedCIDRs: []string{"100.64.1.1/10"},
		}},
	}
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "invalid canonical allowed CIDR") {
		t.Fatalf("expected canonical CIDR rejection, got %v", err)
	}
}

func TestValidateRejectsHostnameWithPortOrWildcard(t *testing.T) {
	for _, hostname := range []string{"manager.goreecloud.com:443", "*.goreecloud.com"} {
		config := Config{
			SchemaVersion: SchemaVersion,
			Routes: []Route{{Hostname: hostname, Upstream: "http://manager:8000", Exposure: ExposurePublic}},
		}
		if err := Validate(config); err == nil {
			t.Fatalf("expected hostname %q to be rejected", hostname)
		}
	}
}
