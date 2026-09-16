package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pooyahpx/HPXNODE/common"
)

const (
	defaultBinary = "/usr/local/bin/sing-box"
	AnyTLS        = "anytls"
	Tuic          = "tuic"
	Naive         = "naive"
)

// Inbound is a protocol inbound extracted from an xray-style config for sing-box.
type Inbound struct {
	Tag      string
	Protocol string
	Listen   string
	Port     int
	Settings map[string]any
	Users    []*common.User
}

// Sidecar runs a sing-box process for anytls/tuic/naive inbounds.
type Sidecar struct {
	bin      string
	workDir  string
	inbounds []*Inbound
	process  *exec.Cmd
	waitDone chan struct{}
	cancel   context.CancelFunc
	logChan  chan string
	mu       sync.Mutex
	running  bool
}

func FindBinary() string {
	if p := strings.TrimSpace(os.Getenv("SINGBOX_EXECUTABLE_PATH")); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if _, err := os.Stat(defaultBinary); err == nil {
		return defaultBinary
	}
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p
	}
	return ""
}

func CheckDeps() error {
	if FindBinary() == "" {
		return fmt.Errorf("sing-box is not installed on this node")
	}
	return nil
}

func IsSidecarProtocol(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case AnyTLS, Tuic, Naive:
		return true
	default:
		return false
	}
}

func New(workDir string, inbounds []*Inbound, logBuf int) (*Sidecar, error) {
	bin := FindBinary()
	if bin == "" {
		return nil, fmt.Errorf("sing-box binary not found (set SINGBOX_EXECUTABLE_PATH)")
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, err
	}
	s := &Sidecar{
		bin: bin, workDir: workDir, inbounds: inbounds,
		waitDone: make(chan struct{}), logChan: make(chan string, logBuf),
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	if err := s.start(ctx); err != nil {
		cancel()
		return nil, err
	}
	return s, nil
}

func (s *Sidecar) configPath() string { return filepath.Join(s.workDir, "config.json") }

func (s *Sidecar) buildConfig() (map[string]any, error) {
	inbounds := make([]map[string]any, 0, len(s.inbounds))
	for _, in := range s.inbounds {
		listen := in.Listen
		if listen == "" {
			listen = "0.0.0.0"
		}
		port := in.Port
		if port <= 0 {
			port = 443
		}
		entry := map[string]any{
			"type":   strings.ToLower(in.Protocol),
			"tag":    in.Tag,
			"listen": listen,
			"listen_port": port,
		}
		users := make([]map[string]any, 0)
		for _, u := range in.Users {
			if u == nil || !contains(u.GetInbounds(), in.Tag) {
				continue
			}
			switch strings.ToLower(in.Protocol) {
			case AnyTLS:
				if p := u.GetProxies().GetAnytls(); p != nil && p.GetPassword() != "" {
					users = append(users, map[string]any{"name": u.GetEmail(), "password": p.GetPassword()})
				}
			case Tuic:
				if p := u.GetProxies().GetTuic(); p != nil {
					users = append(users, map[string]any{"name": u.GetEmail(), "uuid": p.GetId(), "password": p.GetPassword()})
				}
			case Naive:
				if p := u.GetProxies().GetNaive(); p != nil {
					users = append(users, map[string]any{"username": p.GetUsername(), "password": p.GetPassword()})
				}
			}
		}
		entry["users"] = users
		inbounds = append(inbounds, entry)
	}
	return map[string]any{
		"log":      map[string]any{"level": "info"},
		"inbounds": inbounds,
		"outbounds": []map[string]any{
			{"type": "direct", "tag": "direct"},
		},
	}, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Sidecar) writeConfig() error {
	cfg, err := s.buildConfig()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.configPath(), b, 0o600)
}

func (s *Sidecar) start(ctx context.Context) error {
	if err := s.writeConfig(); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, s.bin, "run", "-c", s.configPath())
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sing-box: %w", err)
	}
	s.process = cmd
	s.running = true
	go pump(s, stderr)
	go pump(s, stdout)
	go func() { _ = cmd.Wait(); close(s.waitDone); s.mu.Lock(); s.running = false; s.mu.Unlock() }()
	return nil
}

func pump(s *Sidecar, r interface{ Read([]byte) (int, error) }) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			select {
			case s.logChan <- string(buf[:n]):
			default:
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *Sidecar) SyncUsers(users []*common.User) error {
	s.mu.Lock()
	for _, in := range s.inbounds {
		in.Users = users
	}
	s.mu.Unlock()
	return s.Restart()
}

func (s *Sidecar) Restart() error {
	s.Shutdown()
	s.waitDone = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	return s.start(ctx)
}

func (s *Sidecar) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.process != nil && s.process.Process != nil {
		_ = s.process.Process.Kill()
	}
	select {
	case <-s.waitDone:
	case <-time.After(5 * time.Second):
	}
	s.running = false
}

func (s *Sidecar) Logs() <-chan string { return s.logChan }

func (s *Sidecar) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// PortFromSettings extracts a listen port from inbound settings/port fields.
func PortFromAny(port any) int {
	switch v := port.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	case string:
		var n int
		fmt.Sscanf(v, "%d", &n)
		return n
	default:
		return 0
	}
}
