package sshvpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pooyahpx/HPXNODE/common"
	"github.com/pooyahpx/HPXNODE/config"
	"github.com/pooyahpx/HPXNODE/pkg/stats"
)

var errNotStarted = errors.New("ssh not started")

const sshGroup = "hpx-ssh"

type Config struct {
	InboundTag string `json:"inbound_tag"`
	Port       int    `json:"port"`
	Pool       string `json:"pool"`
	workDir    string
}

func NewConfig(configStr string) (*Config, error) {
	cfg := &Config{}
	if strings.TrimSpace(configStr) == "" {
		return nil, fmt.Errorf("ssh config string must not be empty")
	}
	if err := json.Unmarshal([]byte(configStr), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse ssh config: %w", err)
	}
	if cfg.InboundTag == "" {
		return nil, fmt.Errorf("inbound_tag is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 2222
	}
	return cfg, nil
}

func findSSHD() string {
	for _, p := range []string{"/usr/sbin/sshd", "/sbin/sshd"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("sshd"); err == nil {
		return p
	}
	return ""
}

func CheckDeps() error {
	if findSSHD() == "" {
		return fmt.Errorf("sshd is not installed on this node")
	}
	return nil
}

func DetectVersion() string {
	bin := findSSHD()
	if bin == "" {
		return "unknown"
	}
	out, _ := exec.Command(bin, "-V").CombinedOutput()
	// sshd -V writes to stderr
	line := strings.TrimSpace(string(out))
	if line == "" {
		return "unknown"
	}
	return strings.Fields(line)[0]
}

type userStore struct {
	tag   string
	mu    sync.RWMutex
	users map[string]string
}

func newUserStore(tag string) *userStore {
	return &userStore{tag: tag, users: map[string]string{}}
}

func (s *userStore) replaceAll(users []*common.User) {
	next := map[string]string{}
	for _, u := range users {
		c := u.GetProxies().GetSsh()
		if c == nil || c.GetUsername() == "" || !slices.Contains(u.GetInbounds(), s.tag) {
			continue
		}
		next[c.GetUsername()] = c.GetPassword()
	}
	s.mu.Lock()
	s.users = next
	s.mu.Unlock()
}

func (s *userStore) apply(u *common.User) {
	c := u.GetProxies().GetSsh()
	s.mu.Lock()
	defer s.mu.Unlock()
	if c == nil || c.GetUsername() == "" || !slices.Contains(u.GetInbounds(), s.tag) {
		if u.GetEmail() != "" {
			delete(s.users, u.GetEmail())
		}
		return
	}
	s.users[c.GetUsername()] = c.GetPassword()
}

func (s *userStore) snapshot() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.users))
	for k, v := range s.users {
		out[k] = v
	}
	return out
}

type SSHVPN struct {
	config       *Config
	cfg          *config.Config
	users        *userStore
	statsTracker *stats.Tracker
	process      *exec.Cmd
	waitDone     chan struct{}
	logChan      chan string
	cancel       context.CancelFunc
	startTime    time.Time
	mu           sync.RWMutex
	state        int
	shutdownOnce sync.Once
}

func New(cfg *config.Config, sConfig *Config, users []*common.User) (*SSHVPN, error) {
	if sConfig == nil {
		return nil, errors.New("ssh config must not be nil")
	}
	sConfig.workDir = filepath.Join(cfg.GeneratedConfigPath, "ssh", sConfig.InboundTag)
	ctx, cancel := context.WithCancel(context.Background())
	o := &SSHVPN{
		config: sConfig, cfg: cfg, users: newUserStore(sConfig.InboundTag),
		statsTracker: stats.New(), waitDone: make(chan struct{}),
		logChan: make(chan string, cfg.LogBufferSize), cancel: cancel, startTime: time.Now(),
	}
	o.users.replaceAll(users)
	if err := o.start(ctx); err != nil {
		cancel()
		return nil, err
	}
	return o, nil
}

func (o *SSHVPN) sshdConfigPath() string { return filepath.Join(o.config.workDir, "sshd_config") }
func (o *SSHVPN) hostKeyPath() string    { return filepath.Join(o.config.workDir, "ssh_host_ed25519_key") }
func (o *SSHVPN) passwdPath() string     { return filepath.Join(o.config.workDir, "passwd") }
func (o *SSHVPN) usersFile() string      { return filepath.Join(o.config.workDir, "users.txt") }

func (o *SSHVPN) writeUsers() error {
	if err := os.MkdirAll(o.config.workDir, 0o700); err != nil {
		return err
	}
	var b strings.Builder
	for u, p := range o.users.snapshot() {
		fmt.Fprintf(&b, "%s:%s\n", u, p)
	}
	return os.WriteFile(o.usersFile(), []byte(b.String()), 0o600)
}

func (o *SSHVPN) ensureHostKey() error {
	if _, err := os.Stat(o.hostKeyPath()); err == nil {
		return nil
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		keygen = "ssh-keygen"
	}
	return exec.Command(keygen, "-t", "ed25519", "-f", o.hostKeyPath(), "-N", "", "-q").Run()
}

func (o *SSHVPN) writeSSHDConfig() error {
	var b strings.Builder
	fmt.Fprintf(&b, "Port %d\n", o.config.Port)
	fmt.Fprintf(&b, "ListenAddress 0.0.0.0\n")
	fmt.Fprintf(&b, "HostKey %s\n", o.hostKeyPath())
	fmt.Fprintf(&b, "PermitRootLogin no\n")
	fmt.Fprintf(&b, "PasswordAuthentication yes\n")
	fmt.Fprintf(&b, "PubkeyAuthentication no\n")
	fmt.Fprintf(&b, "ChallengeResponseAuthentication no\n")
	fmt.Fprintf(&b, "UsePAM no\n")
	fmt.Fprintf(&b, "AllowTcpForwarding yes\n")
	fmt.Fprintf(&b, "PermitTunnel yes\n")
	fmt.Fprintf(&b, "AllowGroups %s\n", sshGroup)
	fmt.Fprintf(&b, "PidFile %s\n", filepath.Join(o.config.workDir, "sshd.pid"))
	fmt.Fprintf(&b, "ForceCommand /bin/true\n")
	return os.WriteFile(o.sshdConfigPath(), []byte(b.String()), 0o600)
}

func (o *SSHVPN) syncSystemUsers() {
	// Best-effort: ensure group exists and sync passwords via chpasswd when available.
	_ = exec.Command("groupadd", "-f", sshGroup).Run()
	for user, pass := range o.users.snapshot() {
		_ = exec.Command("useradd", "-M", "-s", "/usr/sbin/nologin", "-G", sshGroup, user).Run()
		cmd := exec.Command("chpasswd")
		cmd.Stdin = strings.NewReader(user + ":" + pass + "\n")
		_ = cmd.Run()
	}
}

func (o *SSHVPN) start(ctx context.Context) error {
	if err := o.writeUsers(); err != nil {
		return err
	}
	if err := o.ensureHostKey(); err != nil {
		return fmt.Errorf("ssh host key: %w", err)
	}
	if err := o.writeSSHDConfig(); err != nil {
		return err
	}
	o.syncSystemUsers()
	bin := findSSHD()
	if bin == "" {
		return fmt.Errorf("sshd not found")
	}
	cmd := exec.CommandContext(ctx, bin, "-D", "-e", "-f", o.sshdConfigPath())
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sshd: %w", err)
	}
	o.process = cmd
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				o.log("Info", string(buf[:n]))
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				o.log("Info", string(buf[:n]))
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { _ = cmd.Wait(); close(o.waitDone) }()
	o.mu.Lock()
	o.state = 1
	o.mu.Unlock()
	o.log("Info", fmt.Sprintf("ssh: started (%s) on port %d", o.config.InboundTag, o.config.Port))
	return nil
}

func (o *SSHVPN) log(sev, msg string) {
	select {
	case o.logChan <- fmt.Sprintf("%s [%s] %s", time.Now().UTC().Format("2006/01/02 15:04:05"), sev, msg):
	default:
	}
}

func (o *SSHVPN) Started() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.state == 1
}
func (o *SSHVPN) Version() string     { return DetectVersion() }
func (o *SSHVPN) Logs() <-chan string { return o.logChan }
func (o *SSHVPN) Restart() error {
	o.Shutdown()
	ctx, cancel := context.WithCancel(context.Background())
	o.cancel = cancel
	o.waitDone = make(chan struct{})
	o.shutdownOnce = sync.Once{}
	return o.start(ctx)
}
func (o *SSHVPN) Shutdown() {
	o.shutdownOnce.Do(func() {
		o.mu.Lock()
		o.state = 0
		o.mu.Unlock()
		if o.cancel != nil {
			o.cancel()
		}
		if o.process != nil && o.process.Process != nil {
			_ = o.process.Process.Kill()
		}
		select {
		case <-o.waitDone:
		case <-time.After(5 * time.Second):
		}
	})
}
func (o *SSHVPN) SyncUser(_ context.Context, u *common.User) error {
	o.users.apply(u)
	if err := o.writeUsers(); err != nil {
		return err
	}
	o.syncSystemUsers()
	return nil
}
func (o *SSHVPN) SyncUsers(_ context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	if err := o.writeUsers(); err != nil {
		return err
	}
	o.syncSystemUsers()
	return nil
}
func (o *SSHVPN) UpdateUsers(ctx context.Context, users []*common.User) error {
	return o.SyncUsers(ctx, users)
}
func (o *SSHVPN) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.Restart()
}
func (o *SSHVPN) GetOutboundsLatency(_ context.Context, _ *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
}
func (o *SSHVPN) GetStats(_ context.Context, _ *common.StatRequest) (*common.StatResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	return &common.StatResponse{}, nil
}
func (o *SSHVPN) GetUserOnlineStats(_ context.Context, email string) (*common.OnlineStatResponse, error) {
	return &common.OnlineStatResponse{Name: email}, nil
}
func (o *SSHVPN) GetUserOnlineIpListStats(_ context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	return &common.StatsOnlineIpListResponse{Name: email, Ips: map[string]int64{}}, nil
}
func (o *SSHVPN) GetSysStats(_ context.Context) (*common.BackendStatsResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &common.BackendStatsResponse{Alloc: m.Alloc, Uptime: uint32(time.Since(o.startTime).Seconds())}, nil
}
