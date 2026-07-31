package ikev2

// Per-node Let's Encrypt certificates for IKEv2.
//
// The panel ships one shared IKEv2 core config to every node, but each node
// answers on its own hostname, and native VPN clients (notably Android's
// built-in IKEv2/IPsec client) insist on a server certificate whose SAN is
// exactly the hostname the user typed — a wildcard SAN is rejected. They also
// want RSA rather than ECDSA.
//
// So when HPX_NODE_IKEV2_DOMAIN is set, the node ignores the certificate
// material from the shared core config and instead obtains (and renews) its
// own RSA certificate for that hostname over the ACME HTTP-01 challenge, and
// uses the hostname as the IKE identity. That keeps a single core config
// usable across every node: adding a node needs a DNS record and a panel host
// entry, nothing else.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	// envAutoCertDomain is the node's own public hostname. Setting it turns on
	// per-node certificate management.
	envAutoCertDomain = "HPX_NODE_IKEV2_DOMAIN"
	// envAutoCertHTTPPort overrides the port the HTTP-01 challenge listens on.
	// Let's Encrypt always connects to port 80, so only change this when
	// something in front forwards 80 here.
	envAutoCertHTTPPort = "HPX_NODE_IKEV2_HTTP_PORT"
	// envAutoCertDirectory overrides the ACME directory (for staging tests).
	envAutoCertDirectory = "HPX_NODE_IKEV2_ACME_DIRECTORY"

	autoCertDir = "/var/lib/hpx-node/certs/ikev2"
	// Renew once the certificate has less than this left, matching the usual
	// Let's Encrypt guidance of renewing at ~1/3 of a 90-day lifetime.
	autoCertRenewBefore = 30 * 24 * time.Hour
	// How often the background loop re-checks expiry.
	autoCertCheckEvery = 12 * time.Hour
)

// autoCertDomain returns the configured per-node hostname, or "" when the
// feature is off.
func autoCertDomain() string {
	return strings.TrimSpace(os.Getenv(envAutoCertDomain))
}

func autoCertHTTPPort() string {
	if p := strings.TrimSpace(os.Getenv(envAutoCertHTTPPort)); p != "" {
		return p
	}
	return "80"
}

func autoCertPaths(domain string) (certFile, keyFile, chainFile string) {
	dir := filepath.Join(autoCertDir, domain)
	return filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "chain.pem")
}

// applyAutoCert swaps the shared core config's certificate material for this
// node's own certificate. It is a no-op when the feature is off.
func (o *IKEv2) applyAutoCert() error {
	domain := autoCertDomain()
	if domain == "" {
		return nil
	}

	certPEM, keyPEM, chainPEM, err := o.ensureAutoCert(domain)
	if err != nil {
		return err
	}

	o.config.Identity = domain
	o.config.ServerAddr = domain
	o.config.ServerCert = certPEM
	o.config.ServerKey = keyPEM
	o.config.CACert = chainPEM
	return nil
}

// ensureAutoCert returns a currently valid certificate for domain, issuing a
// new one when none exists or the stored one is close to expiry.
func (o *IKEv2) ensureAutoCert(domain string) (certPEM, keyPEM, chainPEM string, err error) {
	certFile, keyFile, chainFile := autoCertPaths(domain)

	if c, k, ch, ok := loadStoredCert(certFile, keyFile, chainFile, domain); ok {
		return c, k, ch, nil
	}

	o.emitLogf("Info", "ikev2: requesting a Let's Encrypt certificate for %s (HTTP-01 on port %s)", domain, autoCertHTTPPort())
	if err := o.issueAutoCert(domain); err != nil {
		// A stored certificate that is merely near expiry still beats failing
		// the whole backend: keep serving it and retry on the next check.
		if c, k, ch, ok := loadStoredCert(certFile, keyFile, chainFile, domain); ok || c != "" {
			o.emitLogf("Warning", "ikev2: certificate renewal for %s failed (%v) — continuing with the existing certificate", domain, err)
			return c, k, ch, nil
		}
		return "", "", "", fmt.Errorf("obtain certificate for %s: %w", domain, err)
	}
	o.emitLogf("Info", "ikev2: certificate for %s installed", domain)

	c, k, ch, ok := loadStoredCert(certFile, keyFile, chainFile, domain)
	if !ok {
		return "", "", "", fmt.Errorf("certificate for %s was issued but does not verify", domain)
	}
	return c, k, ch, nil
}

// loadStoredCert reads a previously issued certificate. ok reports whether it
// is usable (right hostname and not near expiry); the PEM values are returned
// even when ok is false so a soon-to-expire certificate can still be served if
// renewal fails.
func loadStoredCert(certFile, keyFile, chainFile, domain string) (certPEM, keyPEM, chainPEM string, ok bool) {
	certRaw, err := os.ReadFile(certFile)
	if err != nil {
		return "", "", "", false
	}
	keyRaw, err := os.ReadFile(keyFile)
	if err != nil {
		return "", "", "", false
	}
	chainRaw, err := os.ReadFile(chainFile)
	if err != nil {
		return "", "", "", false
	}
	certPEM, keyPEM, chainPEM = string(certRaw), string(keyRaw), string(chainRaw)

	block, _ := pem.Decode(certRaw)
	if block == nil {
		return certPEM, keyPEM, chainPEM, false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certPEM, keyPEM, chainPEM, false
	}
	if leaf.VerifyHostname(domain) != nil {
		return certPEM, keyPEM, chainPEM, false
	}
	if time.Until(leaf.NotAfter) < autoCertRenewBefore {
		return certPEM, keyPEM, chainPEM, false
	}
	return certPEM, keyPEM, chainPEM, true
}

// issueAutoCert runs a full ACME order for domain and writes the results.
func (o *IKEv2) issueAutoCert(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	certFile, keyFile, chainFile := autoCertPaths(domain)
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return err
	}

	accountKey, err := loadOrCreateAccountKey()
	if err != nil {
		return fmt.Errorf("acme account key: %w", err)
	}

	client := &acme.Client{Key: accountKey, DirectoryURL: acmeDirectoryURL()}
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil &&
		err != acme.ErrAccountAlreadyExists {
		// A pre-existing account registered with the same key is fine; other
		// errors are fatal.
		if !strings.Contains(strings.ToLower(err.Error()), "already") {
			return fmt.Errorf("register acme account: %w", err)
		}
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return fmt.Errorf("authorize order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("get authorization: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return fmt.Errorf("no http-01 challenge offered for %s", domain)
		}

		stop, err := o.serveHTTPChallenge(client, chal)
		if err != nil {
			return err
		}
		_, acceptErr := client.Accept(ctx, chal)
		if acceptErr == nil {
			_, acceptErr = client.WaitAuthorization(ctx, authz.URI)
		}
		stop()
		if acceptErr != nil {
			return fmt.Errorf("http-01 challenge failed: %w", acceptErr)
		}
	}

	// RSA on purpose: Android's built-in IKEv2 client rejects ECDSA server
	// certificates.
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		return err
	}

	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalize order: %w", err)
	}
	if len(der) == 0 {
		return fmt.Errorf("acme returned an empty certificate chain")
	}

	var leafPEM, chainPEM strings.Builder
	for i, b := range der {
		blk := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		if i == 0 {
			leafPEM.Write(blk)
		} else {
			chainPEM.Write(blk)
		}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})

	if err := os.WriteFile(certFile, []byte(leafPEM.String()), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(chainFile, []byte(chainPEM.String()), 0o600)
}

// serveHTTPChallenge brings up a short-lived HTTP listener that answers the
// ACME key-authorization request, and returns a func that shuts it down.
func (o *IKEv2) serveHTTPChallenge(client *acme.Client, chal *acme.Challenge) (func(), error) {
	response, err := client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return nil, err
	}
	path := client.HTTP01ChallengePath(chal.Token)

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(response))
	})

	ln, err := net.Listen("tcp", ":"+autoCertHTTPPort())
	if err != nil {
		return nil, fmt.Errorf("listen on port %s for the http-01 challenge (is something else using it?): %w", autoCertHTTPPort(), err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}, nil
}

func acmeDirectoryURL() string {
	if d := strings.TrimSpace(os.Getenv(envAutoCertDirectory)); d != "" {
		return d
	}
	return "https://acme-v02.api.letsencrypt.org/directory"
}

// loadOrCreateAccountKey keeps one ACME account key per node so repeat orders
// reuse the same registration.
func loadOrCreateAccountKey() (*rsa.PrivateKey, error) {
	path := filepath.Join(autoCertDir, "account.key")
	if raw, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(raw); block != nil {
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
	}
	if err := os.MkdirAll(autoCertDir, 0o700); err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// watchAutoCert periodically renews the node certificate and restarts charon
// once a new one is in place. It returns immediately when the feature is off.
func (o *IKEv2) watchAutoCert(ctx context.Context) {
	domain := autoCertDomain()
	if domain == "" {
		return
	}
	ticker := time.NewTicker(autoCertCheckEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			certFile, keyFile, chainFile := autoCertPaths(domain)
			if _, _, _, ok := loadStoredCert(certFile, keyFile, chainFile, domain); ok {
				continue
			}
			o.emitLogf("Info", "ikev2: certificate for %s is due for renewal", domain)
			if err := o.issueAutoCert(domain); err != nil {
				o.emitLogf("Warning", "ikev2: certificate renewal for %s failed: %v", domain, err)
				continue
			}
			o.emitLogf("Info", "ikev2: certificate for %s renewed — reloading", domain)
			if err := o.Restart(); err != nil {
				o.emitLogf("Warning", "ikev2: reload after certificate renewal failed: %v", err)
			}
			return // Restart() spawns a fresh watcher.
		}
	}
}
