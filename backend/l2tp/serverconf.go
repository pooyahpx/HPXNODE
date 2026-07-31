package l2tp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pooyahpx/HPXNODE/backend/ipsec"
)

var xl2tpdVersionRe = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)`)

// DetectVersion returns the installed xl2tpd version.
func DetectVersion() string {
	out, err := exec.Command(xl2tpdBinary, "-v").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	if m := xl2tpdVersionRe.FindStringSubmatch(string(out)); len(m) == 2 {
		return m[1]
	}
	return "unknown"
}

func (o *L2TP) confFileName() string    { return "pg-l2tp-" + o.config.InboundTag + ".conf" }
func (o *L2TP) xl2tpdConfPath() string  { return filepath.Join(o.config.workDir, "xl2tpd.conf") }
func (o *L2TP) pppOptionsPath() string  { return filepath.Join(o.config.workDir, "ppp-options") }
func (o *L2TP) controlSocketPath() string { return filepath.Join(o.config.workDir, "l2tp-control") }
func (o *L2TP) pidPath() string         { return filepath.Join(o.config.workDir, "xl2tpd.pid") }

// writeConfig lays out every file the IPsec + L2TP stack needs.
func (o *L2TP) writeConfig() error {
	if err := os.MkdirAll(o.config.workDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(ipsec.SwanctlDir, "conf.d"), 0o700); err != nil {
		return err
	}
	if err := o.writeSwanctl(); err != nil {
		return err
	}
	if err := o.writeXl2tpdConf(); err != nil {
		return err
	}
	if err := o.writePPPOptions(); err != nil {
		return err
	}
	if err := writeIPScripts(); err != nil {
		return err
	}
	return o.writeChapSecrets()
}

// writeIPScripts installs the pppd ip-up/ip-down hooks that record one file per
// live PPP session (interface -> username + tunnel IP + pid). pppd runs every
// executable in these directories when a session comes up or goes down, so the
// Go poll loop can attribute per-interface traffic to a user and enforce limits.
func writeIPScripts() error {
	up := "#!/bin/sh\n" +
		"# HPXPANEL L2TP session accounting hook (managed; do not edit).\n" +
		"IF=\"${IFNAME:-$PPP_IFACE}\"\n" +
		"REMOTE=\"${IPREMOTE:-$PPP_REMOTE}\"\n" +
		"[ -n \"$PEERNAME\" ] || exit 0\n" +
		"[ -n \"$IF\" ] || exit 0\n" +
		"d=" + sessionStateDir + "\n" +
		"mkdir -p \"$d\"; umask 077\n" +
		"{\n" +
		"  echo \"user=$PEERNAME\"\n" +
		"  echo \"tunnel_ip=$REMOTE\"\n" +
		"  echo \"pid=${PPPD_PID:-0}\"\n" +
		"  echo \"started=$(date +%s)\"\n" +
		"} > \"$d/$IF\"\n"

	down := "#!/bin/sh\n" +
		"# HPXPANEL L2TP session accounting hook (managed; do not edit).\n" +
		"IF=\"${IFNAME:-$PPP_IFACE}\"\n" +
		"[ -n \"$IF\" ] && rm -f " + sessionStateDir + "/\"$IF\"\n" +
		"exit 0\n"

	scripts := map[string]string{
		"/etc/ppp/ip-up.d/pg-l2tp":   up,
		"/etc/ppp/ip-down.d/pg-l2tp": down,
	}
	for path, content := range scripts {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			return err
		}
	}
	return os.MkdirAll(sessionStateDir, 0o700)
}

// writeSwanctl writes the IKEv1 transport-mode PSK connection that terminates
// the IPsec layer for L2TP. local_ts is pinned to UDP/1701 (the L2TP port) in
// transport mode, so only L2TP traffic rides this SA.
func (o *L2TP) writeSwanctl() error {
	tag := o.config.InboundTag
	ike := strings.Join(o.config.IKEProposals, ",")
	esp := strings.Join(o.config.ESPProposals, ",")

	var b strings.Builder
	fmt.Fprintf(&b, "connections {\n")
	fmt.Fprintf(&b, "    %s-l2tp {\n", tag)
	fmt.Fprintf(&b, "        version = 1\n")
	fmt.Fprintf(&b, "        proposals = %s\n", ike)
	fmt.Fprintf(&b, "        encap = yes\n")
	fmt.Fprintf(&b, "        rekey_time = 0\n")
	fmt.Fprintf(&b, "        fragmentation = yes\n")
	fmt.Fprintf(&b, "        local {\n")
	fmt.Fprintf(&b, "            auth = psk\n")
	fmt.Fprintf(&b, "        }\n")
	fmt.Fprintf(&b, "        remote {\n")
	fmt.Fprintf(&b, "            auth = psk\n")
	fmt.Fprintf(&b, "        }\n")
	fmt.Fprintf(&b, "        children {\n")
	fmt.Fprintf(&b, "            %s-l2tp {\n", tag)
	fmt.Fprintf(&b, "                esp_proposals = %s\n", esp)
	fmt.Fprintf(&b, "                local_ts = dynamic[udp/l2tp]\n")
	// remote_ts must accept ANY client UDP port: clients behind NAT have their
	// L2TP source port (1701) rewritten by the NAT, so pinning it to udp/1701
	// makes charon reject QUICK_MODE ("no matching CHILD_SA config found").
	fmt.Fprintf(&b, "                remote_ts = dynamic[udp]\n")
	fmt.Fprintf(&b, "                mode = transport\n")
	fmt.Fprintf(&b, "                rekey_time = 0\n")
	fmt.Fprintf(&b, "                dpd_action = clear\n")
	fmt.Fprintf(&b, "            }\n")
	fmt.Fprintf(&b, "        }\n")
	fmt.Fprintf(&b, "    }\n")
	fmt.Fprintf(&b, "}\n\n")

	fmt.Fprintf(&b, "secrets {\n")
	fmt.Fprintf(&b, "    ike-%s-l2tp {\n", tag)
	fmt.Fprintf(&b, "        secret = %q\n", o.config.PSK)
	fmt.Fprintf(&b, "    }\n")
	fmt.Fprintf(&b, "}\n")

	return os.WriteFile(filepath.Join(ipsec.SwanctlDir, "conf.d", o.confFileName()), []byte(b.String()), 0o600)
}

// writeXl2tpdConf writes the xl2tpd LNS config: listen on 1701 and hand clients
// PPP sessions from the pool.
func (o *L2TP) writeXl2tpdConf() error {
	start, end := poolRange(o.config.Pool, o.config.LocalIP)
	var b strings.Builder
	fmt.Fprintf(&b, "[global]\n")
	fmt.Fprintf(&b, "port = 1701\n")
	fmt.Fprintf(&b, "access control = no\n\n")
	fmt.Fprintf(&b, "[lns default]\n")
	fmt.Fprintf(&b, "ip range = %s-%s\n", start, end)
	fmt.Fprintf(&b, "local ip = %s\n", o.config.LocalIP)
	fmt.Fprintf(&b, "require chap = yes\n")
	fmt.Fprintf(&b, "refuse pap = yes\n")
	fmt.Fprintf(&b, "require authentication = yes\n")
	fmt.Fprintf(&b, "name = %s\n", o.config.InboundTag)
	fmt.Fprintf(&b, "pppoptfile = %s\n", o.pppOptionsPath())
	fmt.Fprintf(&b, "length bit = yes\n")
	return os.WriteFile(o.xl2tpdConfPath(), []byte(b.String()), 0o600)
}

// writePPPOptions writes the pppd option file used for every L2TP session.
func (o *L2TP) writePPPOptions() error {
	var b strings.Builder
	fmt.Fprintf(&b, "require-mschap-v2\n")
	for _, d := range o.config.DNS {
		fmt.Fprintf(&b, "ms-dns %s\n", d)
	}
	fmt.Fprintf(&b, "asyncmap 0\n")
	fmt.Fprintf(&b, "auth\n")
	fmt.Fprintf(&b, "hide-password\n")
	fmt.Fprintf(&b, "name %s\n", o.config.InboundTag)
	fmt.Fprintf(&b, "proxyarp\n")
	fmt.Fprintf(&b, "lcp-echo-interval 30\n")
	fmt.Fprintf(&b, "lcp-echo-failure 4\n")
	fmt.Fprintf(&b, "nodefaultroute\n")
	fmt.Fprintf(&b, "mtu 1400\n")
	fmt.Fprintf(&b, "mru 1400\n")
	fmt.Fprintf(&b, "noccp\n")
	// Disable IPv6CP and Van Jacobson compression: some clients (notably iOS
	// behind carrier NAT) never complete IPCP otherwise ("No network protocols
	// running"), because the extra control protocols stall the negotiation.
	fmt.Fprintf(&b, "noipv6\n")
	fmt.Fprintf(&b, "novj\n")
	fmt.Fprintf(&b, "novjccomp\n")
	fmt.Fprintf(&b, "connect-delay 5000\n")
	return os.WriteFile(o.pppOptionsPath(), []byte(b.String()), 0o600)
}

// writeChapSecrets merges this core's users into the shared chap-secrets file,
// keyed by the server field (= inbound tag) so multiple L2TP cores and other
// protocols keep their own entries.
func (o *L2TP) writeChapSecrets() error {
	kept, err := o.chapSecretsWithoutTag()
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, line := range kept {
		b.WriteString(line)
		b.WriteString("\n")
	}
	for username, entry := range o.users.snapshot() {
		// client  server  secret  IP
		fmt.Fprintf(&b, "%q %s %q *\n", username, o.config.InboundTag, entry.password)
	}
	return os.WriteFile(chapSecretsPath, []byte(b.String()), 0o600)
}

func (o *L2TP) removeChapSecrets() {
	kept, err := o.chapSecretsWithoutTag()
	if err != nil {
		return
	}
	_ = os.WriteFile(chapSecretsPath, []byte(strings.Join(kept, "\n")+"\n"), 0o600)
}

// chapSecretsWithoutTag returns the existing chap-secrets lines that do NOT
// belong to this core (server field != inbound tag), so a rewrite never drops
// other backends' credentials.
func (o *L2TP) chapSecretsWithoutTag() ([]string, error) {
	f, err := os.Open(chapSecretsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var kept []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		trimmed := strings.TrimSpace(line)
		// Keep comments/blank lines and any entry whose server field isn't ours.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || len(fields) < 2 || fields[1] != o.config.InboundTag {
			kept = append(kept, line)
		}
	}
	return kept, sc.Err()
}

// poolRange derives the DHCP-style "start-end" xl2tpd range from a CIDR,
// excluding the network, broadcast and the server's own local IP.
func poolRange(pool, localIP string) (string, string) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(pool))
	if err != nil {
		return localIP, localIP
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return localIP, localIP
	}
	mask := ipnet.Mask
	network := ip4.Mask(mask)
	// Broadcast = network | ^mask.
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = network[i] | ^mask[i]
	}
	start := dup4(network)
	inc(start) // network + 1
	inc(start) // network + 2 (skip the server local IP at +1)
	end := dup4(bcast)
	dec(end) // broadcast - 1
	if bytesCompare(start, end) > 0 {
		return localIP, localIP
	}
	return start.String(), end.String()
}

func dup4(ip net.IP) net.IP { out := make(net.IP, 4); copy(out, ip.To4()); return out }
func inc(ip net.IP) {
	for i := 3; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
func dec(ip net.IP) {
	for i := 3; i >= 0; i-- {
		if ip[i] != 0 {
			ip[i]--
			break
		}
		ip[i] = 255
	}
}
func bytesCompare(a, b net.IP) int {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
