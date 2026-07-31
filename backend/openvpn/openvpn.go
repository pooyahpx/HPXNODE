package openvpn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/pooyahpx/HPXNODE/common"
	"github.com/pooyahpx/HPXNODE/config"
	"github.com/pooyahpx/HPXNODE/pkg/stats"
)

var (
	errNotStarted    = errors.New("openvpn not started")
	openvpnVersionRe = regexp.MustCompile(`OpenVPN\s+(\d+\.\d+\.\d+)`)
)

type lifecycleState uint8

const (
	lifecycleStopped lifecycleState = iota
	lifecycleRunning
)

const onlineActivityThreshold = 60 * time.Second

// OpenVPN implements backend.Backend by supervising an openvpn server process
// and authorizing users over its management interface.
type OpenVPN struct {
	config *Config
	cfg    *config.Config

	users        *userStore
	mgmt         *mgmtClient
	statsTracker *stats.Tracker
	// Node-level (outbound) counters, kept separate from the per-user tracker so
	// the panel's node-usage poll (Outbounds) does not drain per-user deltas.
	interfaceStats *stats.InterfaceCountersTracker
	totalRx        int64
	totalTx        int64

	// per-session cumulative byte counters keyed by ClientID, for delta feeding.
	sessionSeen map[string]clientStatus
	// per-CN cumulative byte counters fed to the stats tracker.
	cnCumulative map[string]*clientStatus

	process   *exec.Cmd
	waitDone  chan struct{}
	logChan   chan string
	cancel    context.CancelFunc
	startTime time.Time
	version   string

	mu           sync.RWMutex
	state        lifecycleState
	shutdownOnce sync.Once
	hostRouting  func()

	updateInterval time.Duration
}

// New creates and starts an OpenVPN backend.
func New(cfg *config.Config, ovConfig *Config, users []*common.User) (*OpenVPN, error) {
	if ovConfig == nil {
		return nil, errors.New("openvpn config must not be nil")
	}

	// derive() (multi-listener) already picked a per-listener directory; only
	// fill in the default when it hasn't.
	if ovConfig.workDir == "" {
		ovConfig.workDir = filepath.Join(cfg.GeneratedConfigPath, "openvpn", ovConfig.InboundTag)
	}

	ctx, cancel := context.WithCancel(context.Background())
	interval := time.Duration(cfg.StatsUpdateIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}

	o := &OpenVPN{
		config:         ovConfig,
		cfg:            cfg,
		users:          newUserStore(ovConfig.InboundTag),
		statsTracker:   stats.New(),
		interfaceStats: stats.NewInterfaceCountersTracker(),
		sessionSeen:    make(map[string]clientStatus),
		waitDone:       make(chan struct{}),
		logChan:        make(chan string, cfg.LogBufferSize),
		cancel:         cancel,
		startTime:      time.Now(),
		updateInterval: interval,
		state:          lifecycleStopped,
	}

	// Seed the authorization allowlist before the process accepts clients.
	o.users.replaceAll(users)

	confPath, err := ovConfig.writeFiles()
	if err != nil {
		cancel()
		return nil, err
	}

	if err := o.startProcess(confPath); err != nil {
		cancel()
		return nil, err
	}

	o.mgmt = newMgmtClient(ovConfig.mgmtSocketPath(), o.users, o.emitLogf2)
	if err := o.mgmt.connect(); err != nil {
		o.stopProcess()
		cancel()
		return nil, err
	}
	go o.mgmt.run()

	o.hostRouting = applyHostRouting(ovConfig.ServerSubnet, ovConfig.EgressInterface)

	o.mu.Lock()
	o.state = lifecycleRunning
	o.mu.Unlock()

	go o.statsLoop(ctx)

	o.emitLog("Info", fmt.Sprintf("openvpn backend started for inbound %s", ovConfig.InboundTag))
	return o, nil
}

// emitLogf2 adapts emitLogf to the mgmt client's logf signature.
func (o *OpenVPN) emitLogf2(format string, args ...any) {
	o.emitLogf("Info", format, args...)
}

func (o *OpenVPN) startProcess(confPath string) error {
	o.version = detectVersion()

	cmd := exec.Command("openvpn", "--config", confPath)
	cmd.Dir = o.config.workDir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("openvpn stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start openvpn: %w", err)
	}
	o.process = cmd

	go o.pipeLogs(stdout)
	go func() {
		_ = cmd.Wait()
		close(o.waitDone)
	}()

	return nil
}

func (o *OpenVPN) pipeLogs(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		o.emitLog("Info", scanner.Text())
	}
}

func (o *OpenVPN) stopProcess() {
	o.mu.RLock()
	proc := o.process
	waitDone := o.waitDone
	o.mu.RUnlock()
	if proc == nil || proc.Process == nil {
		return
	}
	_ = proc.Process.Signal(terminateSignal())
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		_ = proc.Process.Kill()
	}
}

// CheckDeps reports whether the openvpn binary this backend needs is installed,
// so the panel gets a clear "not installed" error instead of a crash.
func CheckDeps() error {
	if _, err := exec.LookPath("openvpn"); err != nil {
		return errors.New("openvpn is not installed on this node")
	}
	return nil
}

// DetectVersion returns the installed openvpn version (independent of running).
func DetectVersion() string { return detectVersion() }

func detectVersion() string {
	out, err := exec.Command("openvpn", "--version").Output()
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	if m := openvpnVersionRe.FindStringSubmatch(string(out)); len(m) == 2 {
		return m[1]
	}
	return "unknown"
}

// ---- backend.Backend interface ----

func (o *OpenVPN) Started() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.state == lifecycleRunning
}

func (o *OpenVPN) Version() string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.version
}

func (o *OpenVPN) Logs() <-chan string {
	return o.logChan
}

func (o *OpenVPN) Restart() error {
	o.mu.RLock()
	confPath := filepath.Join(o.config.workDir, "server.conf")
	o.mu.RUnlock()

	o.stopProcess()
	o.mu.Lock()
	o.waitDone = make(chan struct{})
	o.mu.Unlock()

	if err := o.startProcess(confPath); err != nil {
		return err
	}
	// Reconnect management after restart.
	o.mgmt.close()
	o.mgmt = newMgmtClient(o.config.mgmtSocketPath(), o.users, o.emitLogf2)
	if err := o.mgmt.connect(); err != nil {
		return err
	}
	go o.mgmt.run()
	return nil
}

func (o *OpenVPN) Shutdown() {
	o.shutdownOnce.Do(func() {
		if o.cancel != nil {
			o.cancel()
		}
		if o.mgmt != nil {
			o.mgmt.close()
		}
		o.stopProcess()

		o.mu.Lock()
		if o.hostRouting != nil {
			o.hostRouting()
			o.hostRouting = nil
		}
		o.state = lifecycleStopped
		o.version = ""
		if o.logChan != nil {
			close(o.logChan)
			o.logChan = nil
		}
		o.mu.Unlock()
		log.Println("openvpn shutdown complete")
	})
}

func (o *OpenVPN) SyncUser(ctx context.Context, user *common.User) error {
	return o.applyUsers([]*common.User{user})
}

func (o *OpenVPN) SyncUsers(ctx context.Context, users []*common.User) error {
	removed := o.users.replaceAll(users)
	for _, cn := range removed {
		o.mgmt.kill(cn)
		o.emitLogf("Info", "openvpn: removed user %s", cn)
	}
	for _, u := range users {
		o.enforceDeviceLimit(u.GetEmail())
	}
	return nil
}

// enforceDeviceLimit drops any sessions that exceed the user's current device
// limit, so lowering the limit disconnects the extra devices immediately (not
// only on their next connect).
func (o *OpenVPN) enforceDeviceLimit(cn string) {
	for _, cid := range o.users.excessSessions(cn) {
		o.mgmt.killClient(cid)
		o.emitLogf("Info", "openvpn: user %s over device limit, killing session %s", cn, cid)
	}
}

func (o *OpenVPN) UpdateUsers(ctx context.Context, users []*common.User) error {
	return o.applyUsers(users)
}

func (o *OpenVPN) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.Restart()
}

func (o *OpenVPN) applyUsers(users []*common.User) error {
	for _, u := range users {
		cn, changedSerial, removed := o.users.applyUser(u)
		if cn == "" {
			continue
		}
		if removed {
			o.mgmt.kill(cn)
			o.emitLogf("Info", "openvpn: removed user %s", cn)
		} else if changedSerial {
			// New certificate serial: force reconnect so the old cert is denied.
			o.mgmt.kill(cn)
			o.emitLogf("Info", "openvpn: reissued user %s, killing old session", cn)
		} else {
			// Same user, possibly a lowered device limit: drop extra sessions.
			o.enforceDeviceLimit(cn)
		}
	}
	return nil
}
