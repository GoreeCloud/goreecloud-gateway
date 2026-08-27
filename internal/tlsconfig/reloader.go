package tlsconfig

import (
	"crypto/tls"
	"fmt"
	"sync"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

// Reloader owns the last-known-good TLS runtime used by an HTTPS listener.
// Reload constructs and validates the complete replacement before publishing it,
// so failed certificate changes cannot disturb established listener state.
type Reloader struct {
	mu      sync.RWMutex
	runtime *Runtime
}

func NewReloader(cfg *config.Config) (*Reloader, error) {
	runtime, err := NewRuntime(cfg)
	if err != nil {
		return nil, err
	}
	return &Reloader{runtime: runtime}, nil
}

func (r *Reloader) Reload(cfg *config.Config) error {
	next, err := NewRuntime(cfg)
	if err != nil {
		return fmt.Errorf("gateway tls: reload rejected: %w", err)
	}
	r.mu.Lock()
	r.runtime = next
	r.mu.Unlock()
	return nil
}

func (r *Reloader) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			r.mu.RLock()
			current := r.runtime
			r.mu.RUnlock()
			if current == nil || current.config == nil || current.config.GetCertificate == nil {
				return nil, fmt.Errorf("gateway tls: certificate runtime is unavailable")
			}
			return current.config.GetCertificate(hello)
		},
	}
}
