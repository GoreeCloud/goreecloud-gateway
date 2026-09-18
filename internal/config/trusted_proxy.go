package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// ParseTrustedProxyPrefixes validates trusted ingress proxy addresses and
// returns normalized prefixes. Configuration owns this validation so invalid
// trust boundaries are rejected before the Gateway listener starts or reloads.
func ParseTrustedProxyPrefixes(entries []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			return nil, fmt.Errorf("trusted proxy entry is empty")
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
			return nil, fmt.Errorf("invalid trusted proxy entry %q", entry)
		}

		addr := prefix.Addr()
		if addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() {
			return nil, fmt.Errorf("unsupported trusted proxy entry %q", entry)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}
