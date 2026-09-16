package gre

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

var errNotStarted = errors.New("gre not started")

type Config struct {
	InboundTag string `json:"inbound_tag"`
	Local      string `json:"local"`
	Peer       string `json:"peer"`
	Remote     string `json:"remote"`
	Fou        bool   `json:"fou"`
	IPsec      bool   `json:"ipsec"`
	workDir    string
}

func NewConfig(configStr string) (*Config, error) {
	cfg := &Config{}
	if strings.TrimSpace(configStr) == "" {
		return nil, fmt.Errorf("gre config string must not be empty")
	}
	if err := json.Unmarshal([]byte(configStr), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse gre config: %w", err)
	}
	if cfg.InboundTag == "" {
		return nil, fmt.Errorf("inbound_tag is required")
	}
	if cfg.Peer == "" {
		cfg.Peer = cfg.Remote
	}
	if cfg.Local == "" || cfg.Peer == "" {
		return nil, fmt.Errorf("local and peer (or remote) are required")
	}
	return cfg, nil
}

func CheckDeps() error {
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("ip command is not installed on this node")
	}
	return nil
}

func DetectVersion() string { return "iproute2" }

type GRE struct {
	config       *Config
	cfg          *config.Config
	users        map[string]string // email -> peer_ip
	usersMu      sync.RWMutex
	statsTracker *stats.Tracker
	logChan      chan string
	cancel       context.CancelFunc
	startTime    time.Time
	mu           sync.RWMutex
	state        int
	shutdownOnce sync.Once
	iface        string
}

func New(cfg *config.Config, gConfig *Config, users []*common.User) (*GRE, error) {
	if gConfig == nil {
		return nil, errors.New("gre config must not be nil")
	}
	gConfig.workDir = filepath.Join(cfg.GeneratedConfigPath, "gre", gConfig.InboundTag)
	_, cancel := context.WithCancel(context.Background())
	o := &GRE{
		config: gConfig, cfg: cfg, users: map[string]string{},
		statsTracker: stats.New(), logChan: make(chan string, cfg.LogBufferSize),
		cancel: cancel, startTime: time.Now(),
		iface: "gre-" + sanitize(gConfig.InboundTag),
	}
	o.replaceUsers(users)
	if err := o.start(); err != nil {
		cancel()
		return nil, err
	}
	return o, nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) > 12 {
		out = out[:12]
	}
	if out == "" {
		out = "tun"
	}
	return out
}

func (o *GRE) replaceUsers(users []*common.User) {
	next := map[string]string{}
	for _, u := range users {
		g := u.GetProxies().GetGre()
		if g == nil || !slices.Contains(u.GetInbounds(), o.config.InboundTag) {
			continue
		}
		next[u.GetEmail()] = g.GetPeerIp()
	}
	o.usersMu.Lock()
	o.users = next
	o.usersMu.Unlock()
}

func (o *GRE) start() error {
	_ = os.MkdirAll(o.config.workDir, 0o700)
	_ = exec.Command("ip", "link", "del", o.iface).Run()
	args := []string{"tunnel", "add", o.iface, "mode", "gre", "remote", o.config.Peer, "local", o.config.Local}
	if err := exec.Command("ip", args...).Run(); err != nil {
		return fmt.Errorf("ip tunnel add: %w", err)
	}
	if err := exec.Command("ip", "link", "set", o.iface, "up").Run(); err != nil {
		return fmt.Errorf("ip link set up: %w", err)
	}
	o.mu.Lock()
	o.state = 1
	o.mu.Unlock()
	o.log("Info", fmt.Sprintf("gre: started %s (%s -> %s)", o.iface, o.config.Local, o.config.Peer))
	return nil
}

func (o *GRE) log(sev, msg string) {
	select {
	case o.logChan <- fmt.Sprintf("%s [%s] %s", time.Now().UTC().Format("2006/01/02 15:04:05"), sev, msg):
	default:
	}
}

func (o *GRE) Started() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.state == 1
}
func (o *GRE) Version() string     { return DetectVersion() }
func (o *GRE) Logs() <-chan string { return o.logChan }
func (o *GRE) Restart() error {
	o.Shutdown()
	o.shutdownOnce = sync.Once{}
	_, cancel := context.WithCancel(context.Background())
	o.cancel = cancel
	return o.start()
}
func (o *GRE) Shutdown() {
	o.shutdownOnce.Do(func() {
		o.mu.Lock()
		o.state = 0
		o.mu.Unlock()
		if o.cancel != nil {
			o.cancel()
		}
		_ = exec.Command("ip", "link", "del", o.iface).Run()
	})
}
func (o *GRE) SyncUser(_ context.Context, u *common.User) error {
	o.usersMu.Lock()
	defer o.usersMu.Unlock()
	g := u.GetProxies().GetGre()
	if g == nil || !slices.Contains(u.GetInbounds(), o.config.InboundTag) {
		delete(o.users, u.GetEmail())
		return nil
	}
	o.users[u.GetEmail()] = g.GetPeerIp()
	return nil
}
func (o *GRE) SyncUsers(_ context.Context, users []*common.User) error {
	o.replaceUsers(users)
	return nil
}
func (o *GRE) UpdateUsers(ctx context.Context, users []*common.User) error {
	return o.SyncUsers(ctx, users)
}
func (o *GRE) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	o.replaceUsers(users)
	return o.Restart()
}
func (o *GRE) GetOutboundsLatency(_ context.Context, _ *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
}
func (o *GRE) GetStats(_ context.Context, _ *common.StatRequest) (*common.StatResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	return &common.StatResponse{}, nil
}
func (o *GRE) GetUserOnlineStats(_ context.Context, email string) (*common.OnlineStatResponse, error) {
	return &common.OnlineStatResponse{Name: email}, nil
}
func (o *GRE) GetUserOnlineIpListStats(_ context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	return &common.StatsOnlineIpListResponse{Name: email, Ips: map[string]int64{}}, nil
}
func (o *GRE) GetSysStats(_ context.Context) (*common.BackendStatsResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &common.BackendStatsResponse{Alloc: m.Alloc, Uptime: uint32(time.Since(o.startTime).Seconds())}, nil
}
