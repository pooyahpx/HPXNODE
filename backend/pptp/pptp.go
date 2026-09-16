package pptp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/pooyahpx/HPXNODE/common"
	"github.com/pooyahpx/HPXNODE/config"
	"github.com/pooyahpx/HPXNODE/pkg/stats"
)

var errNotStarted = errors.New("pptp not started")

const (
	onlineActivityThreshold = 60 * time.Second
	pptpdBinary             = "/usr/sbin/pptpd"
	pppdBinary              = "/usr/sbin/pppd"
	chapSecretsPath         = "/etc/ppp/chap-secrets"
)

type lifecycleState uint8

const (
	lifecycleStopped lifecycleState = iota
	lifecycleRunning
)

// CheckDeps reports whether pptpd and pppd are installed.
func CheckDeps() error {
	for _, p := range []string{pptpdBinary, pppdBinary} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("pptp is not installed on this node (missing %s)", p)
		}
	}
	return nil
}

// PPTP implements backend.Backend as a PPTP server (pptpd + pppd, no IPsec).
type PPTP struct {
	config *Config
	cfg    *config.Config

	users          *userStore
	statsTracker   *stats.Tracker
	interfaceStats *stats.InterfaceCountersTracker
	totalRx        int64
	totalTx        int64
	ifSeen         map[string][2]int64
	cumRx          map[string]int64
	cumTx          map[string]int64
	onlineIPs      map[string]map[string]int64

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

func New(cfg *config.Config, pptpConfig *Config, users []*common.User) (*PPTP, error) {
	if pptpConfig == nil {
		return nil, errors.New("pptp config must not be nil")
	}
	pptpConfig.workDir = filepath.Join(cfg.GeneratedConfigPath, "pptp", pptpConfig.InboundTag)

	ctx, cancel := context.WithCancel(context.Background())
	interval := time.Duration(cfg.StatsUpdateIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}

	o := &PPTP{
		config:         pptpConfig,
		cfg:            cfg,
		users:          newUserStore(pptpConfig.InboundTag),
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

func (o *PPTP) start(ctx context.Context) error {
	if err := o.writeConfig(); err != nil {
		return fmt.Errorf("write pptp config: %w", err)
	}
	if err := o.setupNAT(); err != nil {
		o.emitLogf("Warning", "pptp: nat setup failed: %v", err)
	}

	cmd := exec.CommandContext(ctx, pptpdBinary, "-f", "-c", o.pptpdConfPath(), "-p", o.pidPath())
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start pptpd: %w", err)
	}
	o.process = cmd
	go o.pump(stdout)
	go o.pump(stderr)
	go func() { _ = cmd.Wait(); close(o.waitDone) }()

	o.mu.Lock()
	o.state = lifecycleRunning
	o.mu.Unlock()

	go o.pollLoop(ctx)
	o.emitLogf("Info", "pptp: started (%s)", o.config.InboundTag)
	return nil
}

func (o *PPTP) pump(r interface{ Read([]byte) (int, error) }) {
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

func (o *PPTP) Started() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.state == lifecycleRunning
}

func (o *PPTP) Version() string { return DetectVersion() }

func (o *PPTP) Logs() <-chan string { return o.logChan }

func (o *PPTP) Restart() error {
	o.Shutdown()
	ctx, cancel := context.WithCancel(context.Background())
	o.cancel = cancel
	o.waitDone = make(chan struct{})
	o.shutdownOnce = sync.Once{}
	return o.start(ctx)
}

func (o *PPTP) Shutdown() {
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
		o.removeChapSecrets()
		if o.hostRouting != nil {
			o.hostRouting()
		}
		o.emitLog("Info", "pptp: shutdown complete")
	})
}

func (o *PPTP) SyncUser(ctx context.Context, user *common.User) error {
	return o.applyUsers([]*common.User{user})
}

func (o *PPTP) SyncUsers(ctx context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.reloadUsers()
}

func (o *PPTP) UpdateUsers(ctx context.Context, users []*common.User) error {
	return o.applyUsers(users)
}

func (o *PPTP) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.Restart()
}

func (o *PPTP) applyUsers(users []*common.User) error {
	for _, u := range users {
		o.users.applyUser(u)
	}
	return o.reloadUsers()
}

func (o *PPTP) reloadUsers() error { return o.writeChapSecrets() }

func (o *PPTP) GetOutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
}
