package openconnect

import (
	"context"
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

var errNotStarted = errors.New("openconnect not started")

const (
	ocservBinary = "/usr/sbin/ocserv"
)

type lifecycleState uint8

const (
	lifecycleStopped lifecycleState = iota
	lifecycleRunning
)

func CheckDeps() error {
	if _, err := os.Stat(ocservBinary); err != nil {
		if _, lookErr := exec.LookPath("ocserv"); lookErr != nil {
			return fmt.Errorf("ocserv is not installed on this node")
		}
	}
	return nil
}

func DetectVersion() string {
	path := ocservBinary
	if _, err := os.Stat(path); err != nil {
		if p, err := exec.LookPath("ocserv"); err == nil {
			path = p
		} else {
			return "unknown"
		}
	}
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	fields := strings.Fields(string(out))
	if len(fields) >= 2 {
		return fields[len(fields)-1]
	}
	return "unknown"
}

type userEntry struct {
	password string
}

type userStore struct {
	inboundTag string
	mu         sync.RWMutex
	users      map[string]userEntry
}

func newUserStore(tag string) *userStore {
	return &userStore{inboundTag: tag, users: make(map[string]userEntry)}
}

func credsFor(u *common.User) (string, string, bool) {
	c := u.GetProxies().GetOpenconnect()
	if c == nil || c.GetUsername() == "" || c.GetPassword() == "" {
		return "", "", false
	}
	return c.GetUsername(), c.GetPassword(), true
}

func (s *userStore) wants(u *common.User) bool {
	if _, _, ok := credsFor(u); !ok {
		return false
	}
	return slices.Contains(u.GetInbounds(), s.inboundTag)
}

func (s *userStore) replaceAll(users []*common.User) {
	next := make(map[string]userEntry)
	for _, u := range users {
		if !s.wants(u) {
			continue
		}
		user, pass, _ := credsFor(u)
		next[user] = userEntry{password: pass}
	}
	s.mu.Lock()
	s.users = next
	s.mu.Unlock()
}

func (s *userStore) applyUser(u *common.User) {
	if !s.wants(u) {
		user := u.GetEmail()
		s.mu.Lock()
		delete(s.users, user)
		s.mu.Unlock()
		return
	}
	user, pass, _ := credsFor(u)
	s.mu.Lock()
	s.users[user] = userEntry{password: pass}
	s.mu.Unlock()
}

func (s *userStore) snapshot() map[string]userEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]userEntry, len(s.users))
	for k, v := range s.users {
		out[k] = v
	}
	return out
}

type OpenConnect struct {
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
	state        lifecycleState
	shutdownOnce sync.Once
}

func New(cfg *config.Config, ocConfig *Config, users []*common.User) (*OpenConnect, error) {
	if ocConfig == nil {
		return nil, errors.New("openconnect config must not be nil")
	}
	ocConfig.workDir = filepath.Join(cfg.GeneratedConfigPath, "openconnect", ocConfig.InboundTag)
	ctx, cancel := context.WithCancel(context.Background())
	o := &OpenConnect{
		config:       ocConfig,
		cfg:          cfg,
		users:        newUserStore(ocConfig.InboundTag),
		statsTracker: stats.New(),
		waitDone:     make(chan struct{}),
		logChan:      make(chan string, cfg.LogBufferSize),
		cancel:       cancel,
		startTime:    time.Now(),
	}
	o.users.replaceAll(users)
	if err := o.start(ctx); err != nil {
		cancel()
		return nil, err
	}
	return o, nil
}

func (o *OpenConnect) confPath() string     { return filepath.Join(o.config.workDir, "ocserv.conf") }
func (o *OpenConnect) passwdPath() string   { return filepath.Join(o.config.workDir, "ocpasswd") }
func (o *OpenConnect) binary() string {
	if _, err := os.Stat(ocservBinary); err == nil {
		return ocservBinary
	}
	if p, err := exec.LookPath("ocserv"); err == nil {
		return p
	}
	return ocservBinary
}

func (o *OpenConnect) writeConfig() error {
	if err := os.MkdirAll(o.config.workDir, 0o700); err != nil {
		return err
	}
	if err := o.writePasswd(); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "auth = \"plain[%s]\"\n", o.passwdPath())
	fmt.Fprintf(&b, "tcp-port = %d\n", o.config.Port)
	fmt.Fprintf(&b, "udp-port = %d\n", o.config.Port)
	fmt.Fprintf(&b, "run-as-user = nobody\n")
	fmt.Fprintf(&b, "run-as-group = daemon\n")
	fmt.Fprintf(&b, "socket-file = %s\n", filepath.Join(o.config.workDir, "ocserv.sock"))
	fmt.Fprintf(&b, "server-cert = /etc/ssl/certs/ssl-cert-snakeoil.pem\n")
	fmt.Fprintf(&b, "server-key = /etc/ssl/private/ssl-cert-snakeoil.key\n")
	fmt.Fprintf(&b, "ipv4-network = %s\n", o.config.Pool)
	fmt.Fprintf(&b, "tunnel-all-dns = true\n")
	for _, d := range o.config.DNS {
		fmt.Fprintf(&b, "dns = %s\n", d)
	}
	fmt.Fprintf(&b, "device = vpns\n")
	fmt.Fprintf(&b, "ping-leases = true\n")
	return os.WriteFile(o.confPath(), []byte(b.String()), 0o600)
}

func (o *OpenConnect) writePasswd() error {
	// ocpasswd format: username:group:hashed-or-plain depending on auth module.
	// plain[] auth expects: username:password (one per line).
	var b strings.Builder
	for user, e := range o.users.snapshot() {
		fmt.Fprintf(&b, "%s:%s\n", user, e.password)
	}
	return os.WriteFile(o.passwdPath(), []byte(b.String()), 0o600)
}

func (o *OpenConnect) start(ctx context.Context) error {
	if err := o.writeConfig(); err != nil {
		return fmt.Errorf("write openconnect config: %w", err)
	}
	cmd := exec.CommandContext(ctx, o.binary(), "-f", "-c", o.confPath())
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start ocserv: %w", err)
	}
	o.process = cmd
	go o.pump(stdout)
	go o.pump(stderr)
	go func() { _ = cmd.Wait(); close(o.waitDone) }()
	o.mu.Lock()
	o.state = lifecycleRunning
	o.mu.Unlock()
	o.emitLogf("Info", "openconnect: started (%s)", o.config.InboundTag)
	return nil
}

func (o *OpenConnect) pump(r interface{ Read([]byte) (int, error) }) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			o.emitLog("Info", string(buf[:n]))
		}
		if err != nil {
			return
		}
	}
}

func (o *OpenConnect) emitLogf(sev, format string, args ...any) {
	o.emitLog(sev, fmt.Sprintf(format, args...))
}

func (o *OpenConnect) emitLog(sev, msg string) {
	o.mu.RLock()
	ch := o.logChan
	o.mu.RUnlock()
	if ch == nil {
		return
	}
	line := fmt.Sprintf("%s [%s] %s", time.Now().UTC().Format("2006/01/02 15:04:05"), sev, msg)
	select {
	case ch <- line:
	default:
	}
}

func (o *OpenConnect) Started() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.state == lifecycleRunning
}
func (o *OpenConnect) Version() string       { return DetectVersion() }
func (o *OpenConnect) Logs() <-chan string   { return o.logChan }

func (o *OpenConnect) Restart() error {
	o.Shutdown()
	ctx, cancel := context.WithCancel(context.Background())
	o.cancel = cancel
	o.waitDone = make(chan struct{})
	o.shutdownOnce = sync.Once{}
	return o.start(ctx)
}

func (o *OpenConnect) Shutdown() {
	o.shutdownOnce.Do(func() {
		o.mu.Lock()
		o.state = lifecycleStopped
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
		o.emitLog("Info", "openconnect: shutdown complete")
	})
}

func (o *OpenConnect) SyncUser(_ context.Context, user *common.User) error {
	o.users.applyUser(user)
	return o.writePasswd()
}
func (o *OpenConnect) SyncUsers(_ context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.writePasswd()
}
func (o *OpenConnect) UpdateUsers(ctx context.Context, users []*common.User) error {
	return o.SyncUsers(ctx, users)
}
func (o *OpenConnect) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.Restart()
}

func (o *OpenConnect) GetOutboundsLatency(_ context.Context, _ *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
}
func (o *OpenConnect) GetStats(_ context.Context, req *common.StatRequest) (*common.StatResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	switch req.GetType() {
	case common.StatType_UserStat:
		return o.statsTracker.GetStats(context.Background(), []string{req.GetName()}, req.GetReset_()), nil
	case common.StatType_UsersStat:
		return o.statsTracker.GetUsersStats(context.Background(), req.GetReset_()), nil
	default:
		return &common.StatResponse{}, nil
	}
}
func (o *OpenConnect) GetUserOnlineStats(_ context.Context, email string) (*common.OnlineStatResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	return &common.OnlineStatResponse{Name: email, Value: 0}, nil
}
func (o *OpenConnect) GetUserOnlineIpListStats(_ context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	return &common.StatsOnlineIpListResponse{Name: email, Ips: map[string]int64{}}, nil
}
func (o *OpenConnect) GetSysStats(_ context.Context) (*common.BackendStatsResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &common.BackendStatsResponse{
		NumGoroutine: uint32(runtime.NumGoroutine()),
		Alloc:        m.Alloc,
		Uptime:       uint32(time.Since(o.startTime).Seconds()),
	}, nil
}
