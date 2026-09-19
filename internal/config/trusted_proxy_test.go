package config

import "testing"

func TestTrustedProxyConfigurationValidatesExactAddressesAndCIDRs(t *testing.T) {
	cfg := validConfig()
	cfg.TrustedProxies = []string{"10.0.0.5", "192.0.2.0/24", "2001:db8:ffff::/48"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid trusted proxy configuration rejected: %v", err)
	}
}

func TestTrustedProxyConfigurationRejectsAmbiguousEntries(t *testing.T) {
	for _, entry := range []string{"", "not-an-ip", "0.0.0.0", "224.0.0.1", "::ffff:192.0.2.1"} {
		t.Run(entry, func(t *testing.T) {
			cfg := validConfig()
			cfg.TrustedProxies = []string{entry}
			if err := cfg.Validate(); err == nil {
				t.Fatalf("trusted proxy entry %q unexpectedly validated", entry)
			}
		})
	}
}
