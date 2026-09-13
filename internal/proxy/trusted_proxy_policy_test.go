package proxy

import (
	"net/netip"
	"testing"
)

func TestTrustedProxyPolicyReturnsDirectUntrustedPeer(t *testing.T) {
	policy := mustTrustedProxyPolicy(t, []string{"10.0.0.0/8", "2001:db8:ffff::/48"})

	got, err := policy.ResolveClientAddress("203.0.113.9:443", "198.51.100.7")
	if err != nil {
		t.Fatalf("ResolveClientAddress(): %v", err)
	}
	if want := netip.MustParseAddr("203.0.113.9"); got != want {
		t.Fatalf("client = %v, want %v", got, want)
	}
}

func TestTrustedProxyPolicyResolvesRightmostUntrustedClient(t *testing.T) {
	policy := mustTrustedProxyPolicy(t, []string{"10.0.0.0/8", "192.0.2.0/24"})

	got, err := policy.ResolveClientAddress("10.0.0.5:8443", "198.51.100.7, 192.0.2.44")
	if err != nil {
		t.Fatalf("ResolveClientAddress(): %v", err)
	}
	if want := netip.MustParseAddr("198.51.100.7"); got != want {
		t.Fatalf("client = %v, want %v", got, want)
	}
}

func TestTrustedProxyPolicySupportsIPv6(t *testing.T) {
	policy := mustTrustedProxyPolicy(t, []string{"2001:db8:ffff::/48"})

	got, err := policy.ResolveClientAddress("[2001:db8:ffff::12]:443", "2001:db8:1234::99")
	if err != nil {
		t.Fatalf("ResolveClientAddress(): %v", err)
	}
	if want := netip.MustParseAddr("2001:db8:1234::99"); got != want {
		t.Fatalf("client = %v, want %v", got, want)
	}
}

func TestTrustedProxyPolicyRejectsMissingForwardedForFromTrustedPeer(t *testing.T) {
	policy := mustTrustedProxyPolicy(t, []string{"10.0.0.0/8"})

	if _, err := policy.ResolveClientAddress("10.0.0.5:443", ""); err == nil {
		t.Fatal("expected missing forwarding chain to fail closed")
	}
}

func TestTrustedProxyPolicyRejectsMalformedForwardedForFromTrustedPeer(t *testing.T) {
	policy := mustTrustedProxyPolicy(t, []string{"10.0.0.0/8"})

	if _, err := policy.ResolveClientAddress("10.0.0.5:443", "198.51.100.7, unknown"); err == nil {
		t.Fatal("expected malformed forwarding chain to fail closed")
	}
}

func TestTrustedProxyPolicyRejectsEntirelyTrustedChain(t *testing.T) {
	policy := mustTrustedProxyPolicy(t, []string{"10.0.0.0/8", "192.0.2.0/24"})

	if _, err := policy.ResolveClientAddress("10.0.0.5:443", "192.0.2.10, 10.1.2.3"); err == nil {
		t.Fatal("expected all-trusted forwarding chain to fail closed")
	}
}

func TestTrustedProxyPolicyIgnoresSpoofedChainFromUntrustedPeer(t *testing.T) {
	policy := mustTrustedProxyPolicy(t, []string{"10.0.0.0/8"})

	got, err := policy.ResolveClientAddress("203.0.113.11:443", "1.1.1.1, 10.0.0.9")
	if err != nil {
		t.Fatalf("ResolveClientAddress(): %v", err)
	}
	if want := netip.MustParseAddr("203.0.113.11"); got != want {
		t.Fatalf("client = %v, want direct peer %v", got, want)
	}
}

func TestTrustedProxyPolicyRejectsAmbiguousTrustEntries(t *testing.T) {
	cases := []string{"", "not-an-ip", "0.0.0.0", "224.0.0.1", "::ffff:192.0.2.1"}
	for _, entry := range cases {
		t.Run(entry, func(t *testing.T) {
			if _, err := NewTrustedProxyPolicy([]string{entry}); err == nil {
				t.Fatalf("expected %q to be rejected", entry)
			}
		})
	}
}

func mustTrustedProxyPolicy(t *testing.T, entries []string) TrustedProxyPolicy {
	t.Helper()
	policy, err := NewTrustedProxyPolicy(entries)
	if err != nil {
		t.Fatalf("NewTrustedProxyPolicy(): %v", err)
	}
	return policy
}
