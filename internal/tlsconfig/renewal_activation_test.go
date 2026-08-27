package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"
)

func certificateSerialForTest(t *testing.T, certPath, keyPath string) string {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.SerialNumber.String()
}

func TestActivateRenewalPublicationReloadsExactPublishedPair(t *testing.T) {
	dir := t.TempDir()
	oldCert, oldKey := writeTestCertificate(t, dir, "old")
	newCert, newKey := writeTestCertificate(t, dir, "new")
	oldSerial := certificateSerialForTest(t, oldCert, oldKey)
	newSerial := certificateSerialForTest(t, newCert, newKey)

	reloader, err := NewReloader(reloadConfig(oldCert, oldKey))
	if err != nil {
		t.Fatal(err)
	}
	publication := RenewalPublicationReceipt{
		Schema:                      RenewalPublicationReceiptSchemaV1,
		ProfileID:                   "primary",
		PublishedAt:                 time.Now().UTC().Format(time.RFC3339Nano),
		PreviousSerial:              oldSerial,
		CandidateSerial:             newSerial,
		LiveCertificateFile:         newCert,
		LivePrivateKeyFile:          newKey,
		BackupDirectory:             filepath.Join(dir, "backup"),
		RuntimeReloadRequired:       true,
		ProductionCutoverAuthorized: false,
	}

	receipt, err := ActivateRenewalPublication(reloader, reloadConfig(newCert, newKey), publication, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != RenewalRuntimeActivationReceiptSchemaV1 || !receipt.RuntimeReloaded || !receipt.BackupRetained || receipt.ProductionCutoverAuthorized {
		t.Fatalf("unsafe or incomplete runtime activation receipt: %+v", receipt)
	}
	if receipt.PreviousSerial != oldSerial || receipt.CandidateSerial != newSerial {
		t.Fatalf("runtime activation receipt serials do not match publication: %+v", receipt)
	}
}

func TestActivateRenewalPublicationRejectsConfigPathDrift(t *testing.T) {
	dir := t.TempDir()
	oldCert, oldKey := writeTestCertificate(t, dir, "old")
	newCert, newKey := writeTestCertificate(t, dir, "new")
	otherCert, otherKey := writeTestCertificate(t, dir, "other")
	reloader, err := NewReloader(reloadConfig(oldCert, oldKey))
	if err != nil {
		t.Fatal(err)
	}
	publication := RenewalPublicationReceipt{
		Schema:                      RenewalPublicationReceiptSchemaV1,
		ProfileID:                   "primary",
		PublishedAt:                 time.Now().UTC().Format(time.RFC3339Nano),
		PreviousSerial:              certificateSerialForTest(t, oldCert, oldKey),
		CandidateSerial:             certificateSerialForTest(t, newCert, newKey),
		LiveCertificateFile:         newCert,
		LivePrivateKeyFile:          newKey,
		BackupDirectory:             filepath.Join(dir, "backup"),
		RuntimeReloadRequired:       true,
		ProductionCutoverAuthorized: false,
	}
	if _, err := ActivateRenewalPublication(reloader, reloadConfig(otherCert, otherKey), publication, time.Now()); err == nil {
		t.Fatal("activation unexpectedly accepted config path drift")
	}
}
