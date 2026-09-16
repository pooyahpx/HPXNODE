package pptp

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const sessionStateDir = "/run/pg-pptp/sessions"

type pptpSession struct {
	user     string
	ifname   string
	tunnelIP string
	clientIP string
	pid      int
	started  int64
}

func readSessions() []pptpSession {
	entries, err := os.ReadDir(sessionStateDir)
	if err != nil {
		return nil
	}
	var out []pptpSession
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		s := parseSessionFile(filepath.Join(sessionStateDir, e.Name()), e.Name())
		if s.user != "" && s.ifname != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseSessionFile(path, ifname string) pptpSession {
	s := pptpSession{ifname: ifname}
	f, err := os.Open(path)
	if err != nil {
		return s
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "user":
			s.user = v
		case "tunnel_ip":
			s.tunnelIP = v
		case "client":
			s.clientIP = v
		case "pid":
			s.pid, _ = strconv.Atoi(v)
		case "started":
			s.started, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return s
}

func ifaceBytes(ifname string) (rx int64, tx int64) {
	base := filepath.Join("/sys/class/net", ifname, "statistics")
	rx = readCounter(filepath.Join(base, "rx_bytes"))
	tx = readCounter(filepath.Join(base, "tx_bytes"))
	return
}

func readCounter(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}
