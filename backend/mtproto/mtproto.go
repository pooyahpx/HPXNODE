package mtproto

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

var errNotStarted = errors.New("mtproto not started")

type Config struct {
	InboundTag string `json:"inbound_tag"`
	Port       int    `json:"port"`
	Secret     string `json:"secret"`
	workDir    string
}

func NewConfig(configStr string) (*Config, error) {
	cfg := &Config{}
	if strings.TrimSpace(configStr) == "" {
		return nil, fmt.Errorf("mtproto config string must not be empty")
	}
	if err := json.Unmarshal([]byte(configStr), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse mtproto config: %w", err)
	}
	if cfg.InboundTag == "" {
		return nil, fmt.Errorf("inbound_tag is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 443
	}
	return cfg, nil
}

func findMTG() string {
	if p := strings.TrimSpace(os.Getenv("MTG_EXECUTABLE_PATH")); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	for _, p := range []string{"/usr/local/bin/mtg", "/usr/bin/mtg"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("mtg"); err == nil {
		return p
	}
	return ""
}

func CheckDeps() error {
	if findMTG() == "" {
		return fmt.Errorf("mtg binary is not installed on this node")
	}
	return nil
}

func DetectVersion() string {
	bin := findMTG()
	if bin == "" {
		return "unknown"
	}
	out, _ := exec.Command(bin, "--version").CombinedOutput()
	fields := strings.Fields(string(out))
	if len(fields) > 0 {
		return fields[len(fields)-1]
	}
	return "unknown"
}

type MTProto struct {
	config       *Config
	cfg          *config.Config
	secret       string
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

func New(cfg *config.Config, mConfig *Config, users []*common.User) (*MTProto, error) {
	if mConfig == nil {
		return nil, errors.New("mtproto config must not be nil")
	}
	mConfig.workDir = filepath.Join(cfg.GeneratedConfigPath, "mtproto", mConfig.InboundTag)
	ctx, cancel := context.WithCancel(context.Background())
	o := &MTProto{
		config: mConfig, cfg: cfg, statsTracker: stats.New(),
		waitDone: make(chan struct{}), logChan: make(chan string, cfg.LogBufferSize),
		cancel: cancel, startTime: time.Now(),
	}
	o.secret = pickSecret(mConfig, users)
	if err := o.start(ctx); err != nil {
		cancel()
		return nil, err
	}
	return o, nil
}

func pickSecret(cfg *Config, users []*common.User) string {
	if strings.TrimSpace(cfg.Secret) != "" {
		return strings.TrimSpace(cfg.Secret)
	}
	for _, u := range users {
		m := u.GetProxies().GetMtproto()
		if m == nil || m.GetSecret() == "" || !slices.Contains(u.GetInbounds(), cfg.InboundTag) {
			continue
		}
		return m.GetSecret()
	}
	return ""
}

func (o *MTProto) start(ctx context.Context) error {
	_ = os.MkdirAll(o.config.workDir, 0o700)
	bin := findMTG()
	if bin == "" {
		return fmt.Errorf("mtg binary not found")
	}
	if o.secret == "" {
		return fmt.Errorf("mtproto secret is required")
	}
	bind := fmt.Sprintf("0.0.0.0:%d", o.config.Port)
	cmd := exec.CommandContext(ctx, bin, "run", o.secret, "-b", bind)
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start mtg: %w", err)
	}
	o.process = cmd
	go pump(o, stderr)
	go pump(o, stdout)
	go func() { _ = cmd.Wait(); close(o.waitDone) }()
	o.mu.Lock()
	o.state = 1
	o.mu.Unlock()
	o.log("Info", fmt.Sprintf("mtproto: started (%s) on %s", o.config.InboundTag, bind))
	return nil
}

func pump(o *MTProto, r interface{ Read([]byte) (int, error) }) {
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

func (o *MTProto) log(sev, msg string) {
	select {
	case o.logChan <- fmt.Sprintf("%s [%s] %s", time.Now().UTC().Format("2006/01/02 15:04:05"), sev, msg):
	default:
	}
}

func (o *MTProto) Started() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.state == 1
}
func (o *MTProto) Version() string     { return DetectVersion() }
func (o *MTProto) Logs() <-chan string { return o.logChan }
func (o *MTProto) Restart() error {
	o.Shutdown()
	ctx, cancel := context.WithCancel(context.Background())
	o.cancel = cancel
	o.waitDone = make(chan struct{})
	o.shutdownOnce = sync.Once{}
	return o.start(ctx)
}
func (o *MTProto) Shutdown() {
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
func (o *MTProto) SyncUser(_ context.Context, u *common.User) error {
	m := u.GetProxies().GetMtproto()
	if m != nil && m.GetSecret() != "" && slices.Contains(u.GetInbounds(), o.config.InboundTag) {
		if o.secret != m.GetSecret() {
			o.secret = m.GetSecret()
			return o.Restart()
		}
	}
	return nil
}
func (o *MTProto) SyncUsers(_ context.Context, users []*common.User) error {
	sec := pickSecret(o.config, users)
	if sec != "" && sec != o.secret {
		o.secret = sec
		return o.Restart()
	}
	return nil
}
func (o *MTProto) UpdateUsers(ctx context.Context, users []*common.User) error {
	return o.SyncUsers(ctx, users)
}
func (o *MTProto) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	o.secret = pickSecret(o.config, users)
	return o.Restart()
}
func (o *MTProto) GetOutboundsLatency(_ context.Context, _ *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
}
func (o *MTProto) GetStats(_ context.Context, _ *common.StatRequest) (*common.StatResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	return &common.StatResponse{}, nil
}
func (o *MTProto) GetUserOnlineStats(_ context.Context, email string) (*common.OnlineStatResponse, error) {
	return &common.OnlineStatResponse{Name: email}, nil
}
func (o *MTProto) GetUserOnlineIpListStats(_ context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	return &common.StatsOnlineIpListResponse{Name: email, Ips: map[string]int64{}}, nil
}
func (o *MTProto) GetSysStats(_ context.Context) (*common.BackendStatsResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &common.BackendStatsResponse{Alloc: m.Alloc, Uptime: uint32(time.Since(o.startTime).Seconds())}, nil
}
