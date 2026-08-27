package tlsconfig

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

func TestReloaderRejectsInvalidReplacementAndRetainsRuntime(t *testing.T) {
	certPEM, keyPEM := testCertificate(t, []string{"gateway.example.test"})
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil { t.Fatal(err) }

	good := &config.Config{CertificateProfiles: []config.CertificateProfile{{ID: "primary", CertFile: certPath, KeyFile: keyPath, Hostnames: []string{"gateway.example.test"}}}}
	reloader, err := NewReloader(good)
	if err != nil { t.Fatal(err) }

	before, err := reloader.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "gateway.example.test"})
	if err != nil || before == nil { t.Fatalf("initial certificate lookup failed: %v", err) }

	bad := &config.Config{CertificateProfiles: []config.CertificateProfile{{ID: "primary", CertFile: certPath, KeyFile: filepath.Join(dir, "missing-key.pem"), Hostnames: []string{"gateway.example.test"}}}}
	if err := reloader.Reload(bad); err == nil { t.Fatal("invalid replacement unexpectedly accepted") }

	after, err := reloader.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "gateway.example.test"})
	if err != nil || after == nil { t.Fatalf("last-known-good certificate was not retained: %v", err) }
	if before != after { t.Fatal("failed reload replaced the last-known-good certificate runtime") }
}

func TestReloaderPublishesValidatedReplacement(t *testing.T) {
	dir := t.TempDir()
	cert1, key1 := testCertificate(t, []string{"gateway.example.test"})
	cert2, key2 := testCertificate(t, []string{"gateway.example.test"})
	cert1Path, key1Path := filepath.Join(dir, "cert1.pem"), filepath.Join(dir, "key1.pem")
	cert2Path, key2Path := filepath.Join(dir, "cert2.pem"), filepath.Join(dir, "key2.pem")
	for path, data := range map[string][]byte{cert1Path: cert1, key1Path: key1, cert2Path: cert2, key2Path: key2} {
		if err := os.WriteFile(path, data, 0o600); err != nil { t.Fatal(err) }
	}

	first := &config.Config{CertificateProfiles: []config.CertificateProfile{{ID: "primary", CertFile: cert1Path, KeyFile: key1Path, Hostnames: []string{"gateway.example.test"}}}}
	second := &config.Config{CertificateProfiles: []config.CertificateProfile{{ID: "primary", CertFile: cert2Path, KeyFile: key2Path, Hostnames: []string{"gateway.example.test"}}}}
	reloader, err := NewReloader(first)
	if err != nil { t.Fatal(err) }
	before, err := reloader.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "gateway.example.test"})
	if err != nil { t.Fatal(err) }
	if err := reloader.Reload(second); err != nil { t.Fatal(err) }
	after, err := reloader.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "gateway.example.test"})
	if err != nil { t.Fatal(err) }
	if before == after { t.Fatal("validated replacement was not published") }
}
