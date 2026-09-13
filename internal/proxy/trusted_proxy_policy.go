package proxy

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// TrustedProxyPolicy resolves the original client address only when the direct
// peer is explicitly trusted. It is intentionally independent from the active
// ingress path; callers must opt in with reviewed proxy CIDRs.
type TrustedProxyPolicy struct {
	prefixes []netip.Prefix
}

// NewTrustedProxyPolicy builds a fail-closed trusted-proxy policy. Entries may
// be CIDR prefixes or exact IP addresses. Empty, malformed, zoned, unspecified,
// multicast, and IPv4-mapped IPv6 entries are rejected to avoid ambiguous
// trust boundaries.
func NewTrustedProxyPolicy(entries []string) (TrustedProxyPolicy, error) {
	policy := TrustedProxyPolicy{prefixes: make([]netip.Prefix, 0, len(entries))}
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			return TrustedProxyPolicy{}, fmt.Errorf("trusted proxy entry is empty")
		}

		var prefix netip.Prefix
		var err error
		if strings.Contains(entry, "/") {
			prefix, err = netip.ParsePrefix(entry)
		} else {
			var addr netip.Addr
			addr, err = netip.ParseAddr(entry)
			if err == nil {
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
		}
		if err != nil || !prefix.IsValid() {
			return TrustedProxyPolicy{}, fmt.Errorf("invalid trusted proxy entry %q", entry)
		}
		addr := prefix.Addr()
		if addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() {
			return TrustedProxyPolicy{}, fmt.Errorf("unsupported trusted proxy entry %q", entry)
		}
		policy.prefixes = append(policy.prefixes, prefix.Masked())
	}
	return policy, nil
}

// ResolveClientAddress returns the peer address for an untrusted direct peer.
// For a trusted direct peer, it resolves X-Forwarded-For from right to left and
// returns the first address outside the trusted-proxy set. A trusted peer with
// missing, malformed, or entirely trusted forwarding data fails closed.
func (p TrustedProxyPolicy) ResolveClientAddress(remoteAddr, forwardedFor string) (netip.Addr, error) {
	peer, err := parsePeerAddress(remoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	if !p.contains(peer) {
		return peer, nil
	}

	chain, err := parseForwardedFor(forwardedFor)
	if err != nil {
		return netip.Addr{}, err
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if !p.contains(chain[i]) {
			return chain[i], nil
		}
	}
	return netip.Addr{}, fmt.Errorf("trusted proxy chain contains no untrusted client address")
}

func (p TrustedProxyPolicy) contains(addr netip.Addr) bool {
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parsePeerAddress(remoteAddr string) (netip.Addr, error) {
	value := strings.TrimSpace(remoteAddr)
	if value == "" {
		return netip.Addr{}, fmt.Errorf("remote address is empty")
	}

	host := value
	if splitHost, _, err := net.SplitHostPort(value); err == nil {
		host = splitHost
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsValid() {
		return netip.Addr{}, fmt.Errorf("invalid remote address %q", remoteAddr)
	}
	if addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("unsupported remote address %q", remoteAddr)
	}
	return addr.Unmap(), nil
}

func parseForwardedFor(value string) ([]netip.Addr, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("trusted proxy supplied no X-Forwarded-For chain")
	}

	parts := strings.Split(value, ",")
	chain := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		token := strings.TrimSpace(part)
		addr, err := netip.ParseAddr(token)
		if err != nil || !addr.IsValid() || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
			return nil, fmt.Errorf("invalid X-Forwarded-For address %q", token)
		}
		chain = append(chain, addr.Unmap())
	}
	return chain, nil
}
