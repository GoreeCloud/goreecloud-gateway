package tlsconfig

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

// Runtime loads validated certificate profiles into an SNI-selectable TLS
// configuration. Private-key bytes live only in crypto/tls memory and are never
// copied into Gateway configuration, status, logs, or migration evidence.
type Runtime struct {
	config *tls.Config
}

func NewRuntime(cfg *config.Config) (*Runtime, error) {
	inventory, err := NewInventory(cfg)
	if err != nil {
		return nil, err
	}

	loaded := make(map[string]*tls.Certificate, len(cfg.CertificateProfiles))
	for _, profile := range cfg.CertificateProfiles {
		if !profile.Enabled {
			continue
		}
		certificate, loadErr := tls.LoadX509KeyPair(profile.CertificateFile, profile.PrivateKeyFile)
		if loadErr != nil {
			return nil, fmt.Errorf("gateway tls: load certificate profile %q: %w", profile.ID, loadErr)
		}
		loaded[profile.ID] = &certificate
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello == nil || strings.TrimSpace(hello.ServerName) == "" {
				return nil, fmt.Errorf("gateway tls: SNI server name is required")
			}
			profile, ok := inventory.ProfileForServerName(hello.ServerName)
			if !ok {
				return nil, fmt.Errorf("gateway tls: no certificate profile for SNI server name")
			}
			certificate, ok := loaded[profile.ID]
			if !ok {
				return nil, fmt.Errorf("gateway tls: certificate profile %q is unavailable", profile.ID)
			}
			return certificate, nil
		},
	}
	return &Runtime{config: tlsConfig}, nil
}

func (r *Runtime) TLSConfig() *tls.Config {
	if r == nil || r.config == nil {
		return nil
	}
	return r.config.Clone()
}
