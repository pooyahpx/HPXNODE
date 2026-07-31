package ikev2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCert drops a self-signed certificate for domain, valid until
// notAfter, into dir using the layout loadStoredCert expects.
func writeTestCert(t *testing.T, dir, domain string, notAfter time.Time) (certFile, keyFile, chainFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	chainFile = filepath.Join(dir, "chain.pem")
	write := func(path string, blk *pem.Block) {
		if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	write(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	write(chainFile, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certFile, keyFile, chainFile
}

func TestLoadStoredCert(t *testing.T) {
	const domain = "node1.example.com"

	t.Run("fresh certificate is usable", func(t *testing.T) {
		dir := t.TempDir()
		c, k, ch := writeTestCert(t, dir, domain, time.Now().Add(80*24*time.Hour))
		certPEM, keyPEM, chainPEM, ok := loadStoredCert(c, k, ch, domain)
		if !ok {
			t.Fatal("expected a freshly issued certificate to be usable")
		}
		if certPEM == "" || keyPEM == "" || chainPEM == "" {
			t.Fatal("expected all three PEM blobs to be returned")
		}
	})

	t.Run("near expiry is not usable but is still returned", func(t *testing.T) {
		dir := t.TempDir()
		c, k, ch := writeTestCert(t, dir, domain, time.Now().Add(5*24*time.Hour))
		certPEM, _, _, ok := loadStoredCert(c, k, ch, domain)
		if ok {
			t.Fatal("a certificate inside the renewal window must not be reported usable")
		}
		if certPEM == "" {
			t.Fatal("the existing certificate should still be returned so it can be served if renewal fails")
		}
	})

	t.Run("wrong hostname is rejected", func(t *testing.T) {
		dir := t.TempDir()
		c, k, ch := writeTestCert(t, dir, "other.example.com", time.Now().Add(80*24*time.Hour))
		if _, _, _, ok := loadStoredCert(c, k, ch, domain); ok {
			t.Fatal("a certificate for a different hostname must not be accepted")
		}
	})

	t.Run("missing files are not usable", func(t *testing.T) {
		dir := t.TempDir()
		if _, _, _, ok := loadStoredCert(
			filepath.Join(dir, "cert.pem"),
			filepath.Join(dir, "key.pem"),
			filepath.Join(dir, "chain.pem"),
			domain,
		); ok {
			t.Fatal("expected a missing certificate to be unusable")
		}
	})
}

func TestAutoCertDomainOffByDefault(t *testing.T) {
	t.Setenv(envAutoCertDomain, "")
	if autoCertDomain() != "" {
		t.Fatal("per-node certificates must stay off unless the domain env var is set")
	}
	t.Setenv(envAutoCertDomain, "  node1.example.com  ")
	if got := autoCertDomain(); got != "node1.example.com" {
		t.Fatalf("expected the domain to be trimmed, got %q", got)
	}
}

func TestApplyAutoCertNoopWhenDisabled(t *testing.T) {
	t.Setenv(envAutoCertDomain, "")
	o := &IKEv2{config: &Config{
		Identity:   "panel-supplied",
		ServerCert: "cert", ServerKey: "key", CACert: "ca",
	}}
	if err := o.applyAutoCert(); err != nil {
		t.Fatalf("applyAutoCert should be a no-op when disabled, got %v", err)
	}
	if o.config.Identity != "panel-supplied" || o.config.ServerCert != "cert" {
		t.Fatal("the panel-supplied certificate material must be left untouched when disabled")
	}
}

func TestAutoCertHTTPPortDefault(t *testing.T) {
	t.Setenv(envAutoCertHTTPPort, "")
	if got := autoCertHTTPPort(); got != "80" {
		t.Fatalf("expected the challenge to default to port 80, got %q", got)
	}
	t.Setenv(envAutoCertHTTPPort, "8080")
	if got := autoCertHTTPPort(); got != "8080" {
		t.Fatalf("expected the port override to be honoured, got %q", got)
	}
}
