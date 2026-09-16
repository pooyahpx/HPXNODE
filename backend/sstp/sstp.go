package sstp

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

var errNotStarted = errors.New("sstp not started")

type Config struct {
	InboundTag string   `json:"inbound_tag"`
	Port       int      `json:"port"`
	Pool       string   `json:"pool"`
	DNS        []string `json:"dns"`
	workDir    string
}

func NewConfig(configStr string) (*Config, error) {
	cfg := &Config{}
	if strings.TrimSpace(configStr) == "" {
		return nil, fmt.Errorf("sstp config string must not be empty")
	}
	if err := json.Unmarshal([]byte(configStr), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse sstp config: %w", err)
	}
	if cfg.InboundTag == "" {
		return nil, fmt.Errorf("inbound_tag is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 443
	}
	if len(cfg.DNS) == 0 {
		cfg.DNS = []string{"1.1.1.1", "8.8.8.8"}
	}
	return cfg, nil
}

func findBinary() string {
	for _, p := range []string{"/usr/sbin/accel-pppd", "/usr/bin/accel-pppd", "/usr/local/bin/accel-pppd"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("accel-pppd"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/bin/vpnserver", "/usr/local/bin/vpnserver"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func CheckDeps() error {
	if findBinary() == "" {
		return fmt.Errorf("sstp is not installed on this node (need accel-pppd)")
	}
	return nil
}

func DetectVersion() string {
	bin := findBinary()
	if bin == "" {
		return "unknown"
	}
	out, _ := exec.Command(bin, "-V").CombinedOutput()
	fields := strings.Fields(string(out))
	if len(fields) > 0 {
		return fields[len(fields)-1]
	}
	return "unknown"
}

type userStore struct {
	tag   string
	mu    sync.RWMutex
	users map[string]string // username -> password
}

func newUserStore(tag string) *userStore {
	return &userStore{tag: tag, users: map[string]string{}}
}

func (s *userStore) replaceAll(users []*common.User) {
	next := map[string]string{}
	for _, u := range users {
		c := u.GetProxies().GetSstp()
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
	c := u.GetProxies().GetSstp()
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

type SSTP struct {
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

func New(cfg *config.Config, sConfig *Config, users []*common.User) (*SSTP, error) {
	if sConfig == nil {
		return nil, errors.New("sstp config must not be nil")
	}
	sConfig.workDir = filepath.Join(cfg.GeneratedConfigPath, "sstp", sConfig.InboundTag)
	ctx, cancel := context.WithCancel(context.Background())
	o := &SSTP{
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

func (o *SSTP) usersPath() string { return filepath.Join(o.config.workDir, "chap-secrets") }
func (o *SSTP) confPath() string  { return filepath.Join(o.config.workDir, "accel-pppd.conf") }

func (o *SSTP) writeUsers() error {
	if err := os.MkdirAll(o.config.workDir, 0o700); err != nil {
		return err
	}
	var b strings.Builder
	for u, p := range o.users.snapshot() {
		fmt.Fprintf(&b, "%s * %s *\n", u, p)
	}
	return os.WriteFile(o.usersPath(), []byte(b.String()), 0o600)
}

func (o *SSTP) writeConf() error {
	pool := o.config.Pool
	if pool == "" {
		pool = "10.34.0.0/24"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[modules]\nlog_file\nchap-secrets\nippool\npppd_compat\nsstp\n\n")
	fmt.Fprintf(&b, "[core]\nlog-error=/dev/stderr\n\n")
	fmt.Fprintf(&b, "[sstp]\nbind=0.0.0.0:%d\n\n", o.config.Port)
	fmt.Fprintf(&b, "[ip-pool]\ngw-ip-address=%s\n\n", firstHost(pool))
	fmt.Fprintf(&b, "[chap-secrets]\nchap-secrets=%s\n", o.usersPath())
	return os.WriteFile(o.confPath(), []byte(b.String()), 0o600)
}

func firstHost(pool string) string {
	cidr := strings.TrimSpace(pool)
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		cidr = cidr[:i]
	}
	parts := strings.Split(cidr, ".")
	if len(parts) == 4 {
		parts[3] = "1"
		return strings.Join(parts, ".")
	}
	return cidr
}

func (o *SSTP) start(ctx context.Context) error {
	if err := o.writeUsers(); err != nil {
		return err
	}
	if err := o.writeConf(); err != nil {
		return err
	}
	bin := findBinary()
	if bin == "" {
		return fmt.Errorf("sstp binary not found")
	}
	cmd := exec.CommandContext(ctx, bin, "-c", o.confPath())
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sstp: %w", err)
	}
	o.process = cmd
	go pump(o, stdout)
	go pump(o, stderr)
	go func() { _ = cmd.Wait(); close(o.waitDone) }()
	o.mu.Lock()
	o.state = 1
	o.mu.Unlock()
	o.log("Info", fmt.Sprintf("sstp: started (%s)", o.config.InboundTag))
	return nil
}

func pump(o *SSTP, r interface{ Read([]byte) (int, error) }) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			o.log("Info", string(buf[:n]))
		}
		if err != nil {
			return
		}
	}
}

func (o *SSTP) log(sev, msg string) {
	select {
	case o.logChan <- fmt.Sprintf("%s [%s] %s", time.Now().UTC().Format("2006/01/02 15:04:05"), sev, msg):
	default:
	}
}

func (o *SSTP) Started() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.state == 1
}
func (o *SSTP) Version() string     { return DetectVersion() }
func (o *SSTP) Logs() <-chan string { return o.logChan }
func (o *SSTP) Restart() error {
	o.Shutdown()
	ctx, cancel := context.WithCancel(context.Background())
	o.cancel = cancel
	o.waitDone = make(chan struct{})
	o.shutdownOnce = sync.Once{}
	return o.start(ctx)
}
func (o *SSTP) Shutdown() {
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
func (o *SSTP) SyncUser(_ context.Context, u *common.User) error {
	o.users.apply(u)
	return o.writeUsers()
}
func (o *SSTP) SyncUsers(_ context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.writeUsers()
}
func (o *SSTP) UpdateUsers(ctx context.Context, users []*common.User) error {
	return o.SyncUsers(ctx, users)
}
func (o *SSTP) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.Restart()
}
func (o *SSTP) GetOutboundsLatency(_ context.Context, _ *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
}
func (o *SSTP) GetStats(_ context.Context, req *common.StatRequest) (*common.StatResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	if req.GetType() == common.StatType_UsersStat {
		return o.statsTracker.GetUsersStats(context.Background(), req.GetReset_()), nil
	}
	return &common.StatResponse{}, nil
}
func (o *SSTP) GetUserOnlineStats(_ context.Context, email string) (*common.OnlineStatResponse, error) {
	return &common.OnlineStatResponse{Name: email}, nil
}
func (o *SSTP) GetUserOnlineIpListStats(_ context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	return &common.StatsOnlineIpListResponse{Name: email, Ips: map[string]int64{}}, nil
}
func (o *SSTP) GetSysStats(_ context.Context) (*common.BackendStatsResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &common.BackendStatsResponse{Alloc: m.Alloc, Uptime: uint32(time.Since(o.startTime).Seconds())}, nil
}
