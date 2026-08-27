package config

import "testing"

func TestEnabledRouteRequiresExplicitTLSPolicy(t *testing.T) {
	cfg := validConfig()
	cfg.Routes[0].TLS = RouteTLS{}
	if err := cfg.Validate(); err == nil {
		t.Fatal("enabled route without TLS policy unexpectedly validated")
	}
}

func TestRequiredTLSRequiresCertificateProfile(t *testing.T) {
	cfg := validConfig()
	cfg.Routes[0].TLS = RouteTLS{Mode: "required"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("TLS-required route without certificate profile unexpectedly validated")
	}
}

func TestDisabledTLSRejectsCertificateProfile(t *testing.T) {
	cfg := validConfig()
	cfg.Routes[0].TLS = RouteTLS{Mode: "disabled", CertificateProfile: "should-not-be-used"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("TLS-disabled route with certificate profile unexpectedly validated")
	}
}

func TestExplicitTLSPoliciesValidate(t *testing.T) {
	for _, tls := range []RouteTLS{
		{Mode: "required", CertificateProfile: "default-private"},
		{Mode: "disabled"},
	} {
		cfg := validConfig()
		cfg.Routes[0].TLS = tls
		if err := cfg.Validate(); err != nil {
			t.Fatalf("TLS policy %+v rejected: %v", tls, err)
		}
	}
}

func validConfig() *Config {
	return &Config{
		Schema: "goreecloud-gateway-config/v1",
		Services: []Service{{
			ID:         "svc",
			Name:       "Service",
			BackendIDs: []string{"backend"},
		}},
		Routes: []Route{{
			ID:         "route",
			ServiceID:  "svc",
			Hostname:   "service.goreecloud.com",
			PathPrefix: "/",
			Exposure:   "private",
			Enabled:    true,
			TLS: RouteTLS{
				Mode:               "required",
				CertificateProfile: "default-private",
			},
		}},
		Backends: []Backend{{
			ID:      "backend",
			URL:     "http://127.0.0.1:8080",
			Enabled: true,
		}},
	}
}
