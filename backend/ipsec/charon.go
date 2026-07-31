// Package ipsec owns the single strongSwan charon daemon that every IPsec-based
// backend on a node shares — IKEv2 and L2TP/IPsec both need it, and only one
// charon can run per host (it binds UDP 500/4500 and the /var/run/charon.vici
// control socket). The daemon is therefore reference-counted: the first backend
// to Acquire starts it, the last to Release stops it. Each backend still writes
// its own swanctl connection fragment under /etc/swanctl/conf.d and applies it
// with LoadAll, so their connections coexist on the one daemon.
package ipsec

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// ViciSocketPath is charon's VICI control socket (compiled-in default).
	ViciSocketPath = "/var/run/charon.vici"
	// SwanctlDir is the config directory swanctl reads; fragments live in conf.d.
	SwanctlDir = "/etc/swanctl"

	charonBinary  = "/usr/lib/ipsec/charon"
	swanctlBinary = "/usr/sbin/swanctl"
)

// Logf is a severity+message logger, matching the backends' emitLog signature so
// charon's output flows into whichever backend first started it.
type Logf func(severity, message string)

// manager is the process-wide shared charon supervisor.
type manager struct {
	mu       sync.Mutex
	refs     int
	process  *exec.Cmd
	waitDone chan struct{}
	logf     Logf

	// loadMu serialises swanctl --load-all so two backends reloading at once
	// don't spawn racing swanctl processes against the same daemon.
	loadMu sync.Mutex
}

var shared = &manager{}

// CheckDeps reports whether strongSwan (charon + swanctl) is installed, so the
// panel gets a clear "not installed" error instead of a cryptic charon failure.
func CheckDeps() error {
	for _, p := range []string{charonBinary, swanctlBinary} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("strongSwan is not installed on this node (missing %s)", p)
		}
	}
	return nil
}

// Acquire ensures the shared charon daemon is running and bumps the reference
// count. The first caller spawns charon and waits for its VICI socket; later
// callers return immediately. logf is adopted only by the caller that actually
// starts the daemon.
func Acquire(logf Logf) error { return shared.acquire(logf) }

// Release drops one reference; when the last is dropped the daemon is stopped.
func Release() { shared.release() }

// Running reports whether the shared daemon is currently up.
func Running() bool {
	shared.mu.Lock()
	defer shared.mu.Unlock()
	return shared.refs > 0 && shared.process != nil
}

// LoadAll applies every swanctl fragment under conf.d to the running daemon.
// Safe to call from any backend: swanctl merges all fragments, so a reload
// triggered by one backend keeps the others' connections intact.
func LoadAll() error { return shared.loadAll() }

func (m *manager) acquire(logf Logf) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refs > 0 {
		m.refs++
		return nil
	}
	if err := CheckDeps(); err != nil {
		return err
	}
	m.logf = logf
	if err := m.startLocked(); err != nil {
		return err
	}
	m.refs = 1
	return nil
}

func (m *manager) startLocked() error {
	cmd := exec.Command(charonBinary)
	cmd.Env = append(os.Environ(), "STRONGSWAN_CONF=/etc/strongswan.conf")
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start charon: %w", err)
	}
	m.process = cmd
	m.waitDone = make(chan struct{})
	waitDone := m.waitDone
	go m.pump(stdout)
	go m.pump(stderr)
	go func() { _ = cmd.Wait(); close(waitDone) }()

	if err := m.waitForSocket(waitDone, 15*time.Second); err != nil {
		_ = cmd.Process.Kill()
		m.process = nil
		return err
	}
	m.log("Info", "charon: shared daemon started")
	return nil
}

func (m *manager) waitForSocket(waitDone chan struct{}, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ViciSocketPath); err == nil {
			if conn, e := net.DialTimeout("unix", ViciSocketPath, time.Second); e == nil {
				_ = conn.Close()
				return nil
			}
		}
		select {
		case <-waitDone:
			return errors.New("charon exited before the VICI socket was ready")
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.New("timed out waiting for the charon VICI socket")
}

func (m *manager) release() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refs == 0 {
		return
	}
	m.refs--
	if m.refs > 0 {
		return
	}
	if m.process != nil && m.process.Process != nil {
		_ = m.process.Process.Kill()
	}
	if m.waitDone != nil {
		select {
		case <-m.waitDone:
		case <-time.After(5 * time.Second):
		}
	}
	m.process = nil
	m.log("Info", "charon: shared daemon stopped")
}

func (m *manager) loadAll() error {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	cmd := exec.Command(swanctlBinary, "--load-all", "--noprompt")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("swanctl --load-all: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *manager) pump(r io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			for _, line := range strings.Split(strings.TrimRight(string(buf[:n]), "\n"), "\n") {
				m.log("Info", "charon: "+line)
			}
		}
		if err != nil {
			return
		}
	}
}

func (m *manager) log(severity, message string) {
	if m.logf != nil {
		m.logf(severity, message)
	}
}
