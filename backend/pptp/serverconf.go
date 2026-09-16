package pptp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var pptpdVersionRe = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)`)

func DetectVersion() string {
	out, err := exec.Command(pptpdBinary, "--version").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	if m := pptpdVersionRe.FindStringSubmatch(string(out)); len(m) == 2 {
		return m[1]
	}
	return "unknown"
}

func (o *PPTP) pptpdConfPath() string   { return filepath.Join(o.config.workDir, "pptpd.conf") }
func (o *PPTP) pppOptionsPath() string  { return filepath.Join(o.config.workDir, "options.pptpd") }
func (o *PPTP) pidPath() string         { return filepath.Join(o.config.workDir, "pptpd.pid") }

func (o *PPTP) writeConfig() error {
	if err := os.MkdirAll(o.config.workDir, 0o700); err != nil {
		return err
	}
	if err := o.writePptpdConf(); err != nil {
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

func writeIPScripts() error {
	up := "#!/bin/sh\n" +
		"# HPXPANEL PPTP session accounting hook (managed; do not edit).\n" +
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
		"# HPXPANEL PPTP session accounting hook (managed; do not edit).\n" +
		"IF=\"${IFNAME:-$PPP_IFACE}\"\n" +
		"[ -n \"$IF\" ] && rm -f " + sessionStateDir + "/\"$IF\"\n" +
		"exit 0\n"

	scripts := map[string]string{
		"/etc/ppp/ip-up.d/pg-pptp":   up,
		"/etc/ppp/ip-down.d/pg-pptp": down,
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

func (o *PPTP) writePptpdConf() error {
	start, end := poolRange(o.config.Pool, o.config.LocalIP)
	var b strings.Builder
	fmt.Fprintf(&b, "option %s\n", o.pppOptionsPath())
	fmt.Fprintf(&b, "localip %s\n", o.config.LocalIP)
	fmt.Fprintf(&b, "remoteip %s-%s\n", start, end)
	fmt.Fprintf(&b, "listen %s\n", listenAddr(o.config.ServerAddr))
	fmt.Fprintf(&b, "port %d\n", o.config.Port)
	fmt.Fprintf(&b, "pidfile %s\n", o.pidPath())
	return os.WriteFile(o.pptpdConfPath(), []byte(b.String()), 0o600)
}

func listenAddr(serverAddr string) string {
	s := strings.TrimSpace(serverAddr)
	if s == "" {
		return "0.0.0.0"
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

func (o *PPTP) writePPPOptions() error {
	var b strings.Builder
	fmt.Fprintf(&b, "name %s\n", o.config.InboundTag)
	fmt.Fprintf(&b, "refuse-pap\n")
	fmt.Fprintf(&b, "refuse-chap\n")
	fmt.Fprintf(&b, "refuse-mschap\n")
	fmt.Fprintf(&b, "require-mschap-v2\n")
	fmt.Fprintf(&b, "require-mppe-128\n")
	for _, d := range o.config.DNS {
		fmt.Fprintf(&b, "ms-dns %s\n", d)
	}
	fmt.Fprintf(&b, "proxyarp\n")
	fmt.Fprintf(&b, "nodefaultroute\n")
	fmt.Fprintf(&b, "lock\n")
	fmt.Fprintf(&b, "nobsdcomp\n")
	fmt.Fprintf(&b, "novj\n")
	fmt.Fprintf(&b, "novjccomp\n")
	fmt.Fprintf(&b, "nologfd\n")
	return os.WriteFile(o.pppOptionsPath(), []byte(b.String()), 0o600)
}

func (o *PPTP) writeChapSecrets() error {
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
		fmt.Fprintf(&b, "%q %s %q *\n", username, o.config.InboundTag, entry.password)
	}
	return os.WriteFile(chapSecretsPath, []byte(b.String()), 0o600)
}

func (o *PPTP) removeChapSecrets() {
	kept, err := o.chapSecretsWithoutTag()
	if err != nil {
		return
	}
	_ = os.WriteFile(chapSecretsPath, []byte(strings.Join(kept, "\n")+"\n"), 0o600)
}

func (o *PPTP) chapSecretsWithoutTag() ([]string, error) {
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
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || len(fields) < 2 || fields[1] != o.config.InboundTag {
			kept = append(kept, line)
		}
	}
	return kept, sc.Err()
}

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
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = network[i] | ^mask[i]
	}
	start := dup4(network)
	inc(start)
	inc(start)
	end := dup4(bcast)
	dec(end)
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
