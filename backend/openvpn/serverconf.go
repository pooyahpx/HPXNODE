package openvpn

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// parseCIDR returns the network address and dotted-decimal mask for an IPv4 CIDR.
func parseCIDR(cidr string) (string, string, error) {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return "", "", fmt.Errorf("invalid server_subnet %q: %w", cidr, err)
	}
	mask := ipNet.Mask
	if len(mask) != net.IPv4len {
		return "", "", fmt.Errorf("server_subnet %q must be IPv4", cidr)
	}
	dotted := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	return ipNet.IP.String(), dotted, nil
}

// writeFiles materializes the CA/cert/key/tls-crypt and the rendered server.conf
// into the backend work directory, returning the server.conf path.
func (c *Config) writeFiles() (string, error) {
	if err := os.MkdirAll(c.workDir, 0o700); err != nil {
		return "", fmt.Errorf("create work dir: %w", err)
	}

	files := map[string]string{
		"ca.crt":     c.CACert,
		"server.crt": c.ServerCert,
		"server.key": c.ServerKey,
	}
	if strings.TrimSpace(c.TLSCryptKey) != "" {
		files["tc.key"] = c.TLSCryptKey
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(c.workDir, name), []byte(content), 0o600); err != nil {
			return "", fmt.Errorf("write %s: %w", name, err)
		}
	}

	conf, err := c.renderServerConf()
	if err != nil {
		return "", err
	}
	confPath := filepath.Join(c.workDir, "server.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		return "", fmt.Errorf("write server.conf: %w", err)
	}
	return confPath, nil
}

func (c *Config) renderServerConf() (string, error) {
	netAddr, mask, err := parseCIDR(c.ServerSubnet)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "port %d\n", c.Port)
	fmt.Fprintf(&b, "proto %s\n", c.Proto)
	fmt.Fprintf(&b, "dev %s\n", c.Device)
	b.WriteString("topology subnet\n")
	fmt.Fprintf(&b, "server %s %s\n", netAddr, mask)
	b.WriteString("ca ca.crt\n")
	b.WriteString("cert server.crt\n")
	b.WriteString("key server.key\n")
	b.WriteString("dh none\n")
	b.WriteString("ecdh-curve prime256v1\n")
	if strings.TrimSpace(c.TLSCryptKey) != "" {
		b.WriteString("tls-crypt tc.key\n")
	}
	fmt.Fprintf(&b, "cipher %s\n", c.Cipher)
	if len(c.DataCiphers) > 0 {
		fmt.Fprintf(&b, "data-ciphers %s\n", strings.Join(c.DataCiphers, ":"))
	}
	fmt.Fprintf(&b, "auth %s\n", c.Auth)
	fmt.Fprintf(&b, "keepalive %s\n", c.Keepalive)
	fmt.Fprintf(&b, "max-clients %d\n", c.MaxClients)
	if c.DuplicateCN {
		b.WriteString("duplicate-cn\n")
	}
	for _, dns := range c.DNS {
		fmt.Fprintf(&b, "push \"dhcp-option DNS %s\"\n", dns)
	}
	for _, line := range c.Push {
		fmt.Fprintf(&b, "push %q\n", line)
	}
	// Operator-supplied raw directives (mssfix, sndbuf, compress, …). Appended
	// before the management/status block so those critical lines always win.
	for _, line := range c.ExtraServerDirectives {
		if line = strings.TrimSpace(line); line != "" {
			b.WriteString(line + "\n")
		}
	}
	// Authorize connecting clients over the management interface (no external scripts).
	// auth-user-pass-optional lets cert-only clients through: management-client-auth
	// otherwise demands a username/password, which our certificate-based clients
	// don't send. Authorization is then decided by CN+serial in the mgmt handler.
	fmt.Fprintf(&b, "management %s unix\n", c.mgmtSocketPath())
	b.WriteString("management-client-auth\n")
	b.WriteString("auth-user-pass-optional\n")
	b.WriteString("verify-client-cert require\n")
	b.WriteString("status-version 3\n")
	fmt.Fprintf(&b, "status %s 5\n", filepath.Join(c.workDir, "status.log"))
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString("verb 3\n")

	return b.String(), nil
}
