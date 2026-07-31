package ikev2

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// swanctlDir is the strongSwan config directory swanctl reads (compiled-in;
// no runtime override). One charon per host means a single ikev2 backend owns it.
const swanctlDir = "/etc/swanctl"

func (o *IKEv2) certFileName() string { return "pg-" + o.config.InboundTag + ".pem" }
func (o *IKEv2) confFileName() string { return "pg-" + o.config.InboundTag + ".conf" }

// writeConfig lays out the swanctl certificate material and connection config.
func (o *IKEv2) writeConfig() error {
	for _, sub := range []string{"conf.d", "x509", "x509ca", "private"} {
		if err := os.MkdirAll(filepath.Join(swanctlDir, sub), 0o700); err != nil {
			return err
		}
	}
	// Clear previous CA files for this tag so a shorter chain never leaves stale
	// certs behind.
	oldCAs, _ := filepath.Glob(filepath.Join(swanctlDir, "x509ca", "pg-"+o.config.InboundTag+"-ca*.pem"))
	for _, f := range oldCAs {
		_ = os.Remove(f)
	}

	files := map[string]string{
		filepath.Join(swanctlDir, "x509", o.certFileName()):                    o.config.ServerCert,
		filepath.Join(swanctlDir, "private", "pg-"+o.config.InboundTag+".key"): o.config.ServerKey,
	}
	// swanctl loads only the FIRST certificate per file, so write each CA/chain
	// certificate to its own file — a public CA chain (e.g. Let's Encrypt) can
	// have several intermediates that must all be sent to the client.
	for i, cert := range splitPEMCerts(o.config.CACert) {
		files[filepath.Join(swanctlDir, "x509ca", fmt.Sprintf("pg-%s-ca-%d.pem", o.config.InboundTag, i))] = cert
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return o.writeSwanctl()
}

// splitPEMCerts splits a PEM bundle into individual certificate blocks.
func splitPEMCerts(pemData string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(pemData, "\n") {
		if strings.TrimSpace(line) == "" && cur.Len() == 0 {
			continue
		}
		cur.WriteString(line)
		cur.WriteString("\n")
		if strings.Contains(line, "END CERTIFICATE") {
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		}
	}
	return out
}

// writeSwanctl (re)writes the connection/pool/secrets config from current users.
func (o *IKEv2) writeSwanctl() error {
	tag := o.config.InboundTag
	ike := strings.Join(o.config.IKEProposals, ",")
	esp := strings.Join(o.config.ESPProposals, ",")
	dns := strings.Join(o.config.DNS, ",")

	var b strings.Builder
	fmt.Fprintf(&b, "connections {\n")
	fmt.Fprintf(&b, "    %s {\n", tag)
	fmt.Fprintf(&b, "        version = 2\n")
	fmt.Fprintf(&b, "        proposals = %s\n", ike)
	fmt.Fprintf(&b, "        rekey_time = 4h\n")
	fmt.Fprintf(&b, "        encap = yes\n")
	fmt.Fprintf(&b, "        dpd_delay = 30s\n")
	fmt.Fprintf(&b, "        fragmentation = yes\n")
	fmt.Fprintf(&b, "        pools = %s-pool\n", tag)
	fmt.Fprintf(&b, "        send_cert = always\n")
	fmt.Fprintf(&b, "        local {\n")
	fmt.Fprintf(&b, "            auth = pubkey\n")
	fmt.Fprintf(&b, "            certs = %s\n", o.certFileName())
	fmt.Fprintf(&b, "            id = %s\n", o.config.Identity)
	fmt.Fprintf(&b, "        }\n")
	fmt.Fprintf(&b, "        remote {\n")
	fmt.Fprintf(&b, "            auth = eap-mschapv2\n")
	fmt.Fprintf(&b, "            eap_id = %%any\n")
	fmt.Fprintf(&b, "        }\n")
	fmt.Fprintf(&b, "        children {\n")
	fmt.Fprintf(&b, "            %s {\n", tag)
	fmt.Fprintf(&b, "                esp_proposals = %s\n", esp)
	fmt.Fprintf(&b, "                local_ts = 0.0.0.0/0,::/0\n")
	fmt.Fprintf(&b, "                rekey_time = 1h\n")
	fmt.Fprintf(&b, "                dpd_action = clear\n")
	fmt.Fprintf(&b, "            }\n")
	fmt.Fprintf(&b, "        }\n")
	fmt.Fprintf(&b, "    }\n")
	fmt.Fprintf(&b, "}\n\n")

	fmt.Fprintf(&b, "pools {\n")
	fmt.Fprintf(&b, "    %s-pool {\n", tag)
	fmt.Fprintf(&b, "        addrs = %s\n", o.config.Pool)
	if dns != "" {
		fmt.Fprintf(&b, "        dns = %s\n", dns)
	}
	fmt.Fprintf(&b, "    }\n")
	fmt.Fprintf(&b, "}\n\n")

	fmt.Fprintf(&b, "secrets {\n")
	for username, entry := range o.users.snapshot() {
		fmt.Fprintf(&b, "    eap-%s {\n", username)
		fmt.Fprintf(&b, "        id = %s\n", username)
		fmt.Fprintf(&b, "        secret = %q\n", entry.password)
		fmt.Fprintf(&b, "    }\n")
	}
	fmt.Fprintf(&b, "}\n")

	return os.WriteFile(filepath.Join(swanctlDir, "conf.d", o.confFileName()), []byte(b.String()), 0o600)
}
