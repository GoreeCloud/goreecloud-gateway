package tlsconfig

import (
	"fmt"
	"strings"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

// Inventory is a validated hostname-to-certificate-profile selection model for
// the future HTTPS listener. It contains file references only and does not load
// certificate or private-key bytes.
type Inventory struct {
	byHostname map[string]config.CertificateProfile
}

func NewInventory(cfg *config.Config) (*Inventory, error) {
	if cfg == nil {
		return nil, fmt.Errorf("gateway tls: configuration is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	profiles := make(map[string]config.CertificateProfile, len(cfg.CertificateProfiles))
	for _, profile := range cfg.CertificateProfiles {
		profiles[profile.ID] = profile
	}
	inventory := &Inventory{byHostname: make(map[string]config.CertificateProfile)}
	for _, route := range cfg.Routes {
		if !route.Enabled || route.TLS.Mode != "required" {
			continue
		}
		profile, ok := profiles[route.TLS.CertificateProfile]
		if !ok || !profile.Enabled {
			return nil, fmt.Errorf("gateway tls: route %q has unavailable certificate profile %q", route.ID, route.TLS.CertificateProfile)
		}
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(route.Hostname), "."))
		if existing, ok := inventory.byHostname[host]; ok && existing.ID != profile.ID {
			return nil, fmt.Errorf("gateway tls: hostname %q maps to conflicting certificate profiles", route.Hostname)
		}
		inventory.byHostname[host] = profile
	}
	return inventory, nil
}

func (i *Inventory) ProfileForServerName(serverName string) (config.CertificateProfile, bool) {
	if i == nil {
		return config.CertificateProfile{}, false
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(serverName), "."))
	profile, ok := i.byHostname[host]
	return profile, ok
}
