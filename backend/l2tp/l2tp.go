package l2tp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/pooyahpx/HPXNODE/backend/ipsec"
	"github.com/pooyahpx/HPXNODE/common"
	"github.com/pooyahpx/HPXNODE/config"
	"github.com/pooyahpx/HPXNODE/pkg/stats"
)

var errNotStarted = errors.New("l2tp not started")

const (
	onlineActivityThreshold = 60 * time.Second
	xl2tpdBinary            = "/usr/sbin/xl2tpd"
	pppdBinary              = "/usr/sbin/pppd"
	chapSecretsPath         = "/etc/ppp/chap-secrets"
)

type lifecycleState uint8

const (
	lifecycleStopped lifecycleState = iota
	lifecycleRunning
)

// CheckDeps reports whether strongSwan, xl2tpd and pppd are all installed, so
// the panel gets a clear "not installed" error instead of a cryptic failure.
func CheckDeps() error {
	if err := ipsec.CheckDeps(); err != nil {
		return err
	}
	for _, p := range []string{xl2tpdBinary, pppdBinary} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("xl2tpd/ppp is not installed on this node (missing %s)", p)
		}
	}
	return nil
}

// L2TP implements backend.Backend as an L2TP/IPsec server: the shared charon
// daemon terminates the IPsec (transport-mode, PSK) layer, and a supervised
// xl2tpd + pppd run the L2TP tunnel with per-user CHAP credentials inside it.
type L2TP struct {
	config *Config
	cfg    *config.Config

	users          *userStore
	statsTracker   *stats.Tracker
	interfaceStats *stats.InterfaceCountersTracker
	totalRx        int64
	totalTx        int64
	// per-PPP-interface last-seen byte counters, to accumulate deltas across
	// session churn (a ppp<N> interface goes away when its device disconnects).
	ifSeen map[string][2]int64
	// per-user cumulative byte counters fed to the stats tracker.
	cumRx map[string]int64
	cumTx map[string]int64
	// onlineIPs is the last poll's snapshot of distinct client IPs per user.
	onlineIPs map[string]map[string]int64

	process   *exec.Cmd
	waitDone  chan struct{}
	logChan   chan string
	cancel    context.CancelFunc
	startTime time.Time

	mu             sync.RWMutex
	state          lifecycleState
	shutdownOnce   sync.Once
	hostRouting    func()
	updateInterval time.Duration
}

// New creates and starts an L2TP/IPsec backend.
func New(cfg *config.Config, l2Config *Config, users []*common.User) (*L2TP, error) {
	if l2Config == nil {
		return nil, errors.New("l2tp config must not be nil")
	}
	l2Config.workDir = filepath.Join(cfg.GeneratedConfigPath, "l2tp", l2Config.InboundTag)

	ctx, cancel := context.WithCancel(context.Background())
	interval := time.Duration(cfg.StatsUpdateIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}

	o := &L2TP{
		config:         l2Config,
		cfg:            cfg,
		users:          newUserStore(l2Config.InboundTag),
		statsTracker:   stats.New(),
		interfaceStats: stats.NewInterfaceCountersTracker(),
		ifSeen:         make(map[string][2]int64),
		cumRx:          make(map[string]int64),
		cumTx:          make(map[string]int64),
		onlineIPs:      make(map[string]map[string]int64),
		waitDone:       make(chan struct{}),
		logChan:        make(chan string, cfg.LogBufferSize),
		cancel:         cancel,
		startTime:      time.Now(),
		updateInterval: interval,
		state:          lifecycleStopped,
	}
	o.users.replaceAll(users)

	if err := o.start(ctx); err != nil {
		cancel()
		return nil, err
	}
	return o, nil
}

func (o *L2TP) start(ctx context.Context) error {
	if err := o.writeConfig(); err != nil {
		return fmt.Errorf("write l2tp config: %w", err)
	}
	if err := o.setupNAT(); err != nil {
		o.emitLogf("Warning", "l2tp: nat setup failed: %v", err)
	}

	// Bring up the IPsec (transport-mode PSK) layer on the shared charon daemon.
	if err := ipsec.Acquire(o.emitLog); err != nil {
		return fmt.Errorf("start charon: %w", err)
	}
	if err := ipsec.LoadAll(); err != nil {
		ipsec.Release()
		return fmt.Errorf("swanctl load: %w", err)
	}

	// Supervise xl2tpd in the foreground; it spawns pppd per client connection.
	cmd := exec.CommandContext(ctx, xl2tpdBinary, "-D",
		"-c", o.xl2tpdConfPath(),
		"-C", o.controlSocketPath(),
		"-p", o.pidPath(),
	)
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		ipsec.Release()
		return fmt.Errorf("start xl2tpd: %w", err)
	}
	o.process = cmd
	go o.pump(stdout)
	go o.pump(stderr)
	go func() { _ = cmd.Wait(); close(o.waitDone) }()

	o.mu.Lock()
	o.state = lifecycleRunning
	o.mu.Unlock()

	go o.pollLoop(ctx)
	o.emitLogf("Info", "l2tp: started (%s)", o.config.InboundTag)
	return nil
}

func (o *L2TP) pump(r interface{ Read([]byte) (int, error) }) {
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

// --- Backend interface ---

func (o *L2TP) Started() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.state == lifecycleRunning
}

func (o *L2TP) Version() string { return DetectVersion() }

func (o *L2TP) Logs() <-chan string { return o.logChan }

func (o *L2TP) Restart() error {
	o.Shutdown()
	ctx, cancel := context.WithCancel(context.Background())
	o.cancel = cancel
	o.waitDone = make(chan struct{})
	o.shutdownOnce = sync.Once{}
	return o.start(ctx)
}

func (o *L2TP) Shutdown() {
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
		// Drop this core's IPsec connection fragment and reload, then release the
		// shared charon (stops it only if no other IPsec backend still needs it).
		_ = os.Remove(filepath.Join(ipsec.SwanctlDir, "conf.d", o.confFileName()))
		o.removeChapSecrets()
		if ipsec.Running() {
			_ = ipsec.LoadAll()
		}
		ipsec.Release()
		if o.hostRouting != nil {
			o.hostRouting()
		}
		o.emitLog("Info", "l2tp: shutdown complete")
	})
}

func (o *L2TP) SyncUser(ctx context.Context, user *common.User) error {
	return o.applyUsers([]*common.User{user})
}

func (o *L2TP) SyncUsers(ctx context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.reloadUsers()
}

func (o *L2TP) UpdateUsers(ctx context.Context, users []*common.User) error {
	return o.applyUsers(users)
}

func (o *L2TP) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.Restart()
}

func (o *L2TP) applyUsers(users []*common.User) error {
	for _, u := range users {
		o.users.applyUser(u)
	}
	return o.reloadUsers()
}

// reloadUsers rewrites chap-secrets from the current user set. pppd reads it per
// authentication, so new sessions immediately see the change; existing sessions
// keep running until they reconnect (best-effort, matching xl2tpd's model).
func (o *L2TP) reloadUsers() error { return o.writeChapSecrets() }

func (o *L2TP) GetOutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
}
