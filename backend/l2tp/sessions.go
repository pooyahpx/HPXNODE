package l2tp

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// sessionStateDir is where the pppd ip-up/ip-down hooks record one file per live
// PPP session, keyed by interface name. The hooks are the only writers; the Go
// poll loop is the only reader.
const sessionStateDir = "/run/pg-l2tp/sessions"

// l2tpSession is one live PPP session (one connected device).
type l2tpSession struct {
	user     string
	ifname   string
	tunnelIP string
	clientIP string
	pid      int
	started  int64
}

// readSessions returns every session the ip-up hook has recorded. A missing
// directory (no one connected yet) is not an error.
func readSessions() []l2tpSession {
	entries, err := os.ReadDir(sessionStateDir)
	if err != nil {
		return nil
	}
	var out []l2tpSession
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

func parseSessionFile(path, ifname string) l2tpSession {
	s := l2tpSession{ifname: ifname}
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

// ifaceBytes reads an interface's cumulative counters. rx = bytes the server
// received from the client (the client's upload); tx = bytes sent to the client
// (its download).
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
