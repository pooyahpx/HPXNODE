package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/pooyahpx/HPXNODE/backend"
	"github.com/pooyahpx/HPXNODE/backend/ikev2"
	"github.com/pooyahpx/HPXNODE/backend/l2tp"
	"github.com/pooyahpx/HPXNODE/backend/openvpn"
	"github.com/pooyahpx/HPXNODE/backend/ratelimit"
	"github.com/pooyahpx/HPXNODE/backend/wireguard"
	"github.com/pooyahpx/HPXNODE/backend/xray"
	"github.com/pooyahpx/HPXNODE/common"
	"github.com/pooyahpx/HPXNODE/config"
	"github.com/pooyahpx/HPXNODE/pkg/netutil"
	"github.com/pooyahpx/HPXNODE/pkg/sysstats"
)

const NodeVersion = "0.5.2"

type Service interface {
	Disconnect()
}

// backendKey identifies one running core. Keying by type alone would let a
// node run only a single instance per protocol, but some setups need more than
// one — e.g. OpenVPN listening on both UDP and TCP, which OpenVPN itself can
// only do as two separate servers. The instance part comes from the core config
// (see backendInstanceID), so the panel can assign several cores of the same
// type to one node and each gets its own process.
type backendKey struct {
	typ      common.BackendType
	instance string
}

type Controller struct {
	// backends holds every core running on this node, keyed by type+instance,
	// so one node can serve e.g. openvpn + ikev2 at the same time — and several
	// openvpn cores side by side.
	backends    map[backendKey]backend.Backend
	cfg         *config.Config
	apiPort     int
	metricPort  int
	clientIP    string
	lastRequest time.Time
	stats       *common.SystemStatsResponse
	cancelFunc  context.CancelFunc
	mu          sync.RWMutex

	// shaper applies per-user speed limits with tc; nil until a limited client
	// appears, so nodes that never use limits install nothing.
	shaper *ratelimit.Manager

	// Installed-backend capabilities are detected once (they don't change while
	// the node runs) and reused, since version probes exec external commands.
	capsOnce     sync.Once
	capsAvail    []common.BackendType
	capsVersions map[string]string
}

func New(cfg *config.Config) *Controller {
	_, cancel := context.WithCancel(context.Background())
	return &Controller{
		cfg:        cfg,
		backends:   make(map[backendKey]backend.Backend),
		apiPort:    netutil.FindFreePort(),
		metricPort: netutil.FindFreePort(),
		cancelFunc: cancel,
	}
}

func (c *Controller) ApiKey() uuid.UUID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.ApiKey
}

func (c *Controller) Connect(ip string, keepAlive uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRequest = time.Now()
	c.clientIP = ip

	ctx, cancel := context.WithCancel(context.Background())
	c.cancelFunc = cancel
	go c.recordSystemStats(ctx)
	go c.enforceGlobalLimits(ctx)
	if keepAlive > 0 {
		go c.keepAliveTracker(ctx, time.Duration(keepAlive)*time.Second)
	}
}

func (c *Controller) Disconnect() {
	c.cancelFunc()

	c.mu.Lock()
	backends := make([]backend.Backend, 0, len(c.backends))
	for _, b := range c.backends {
		backends = append(backends, b)
	}
	c.mu.Unlock()

	// Shutdown backends outside of lock to avoid deadlock.
	// Shutdown() will wait for process termination to complete.
	for _, b := range backends {
		b.Shutdown()
	}

	c.closeShaping()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.backends = make(map[backendKey]backend.Backend)
	c.apiPort = netutil.FindFreePort()
	c.metricPort = netutil.FindFreePort()
	c.clientIP = ""
}

func (c *Controller) Ip() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientIP
}

func (c *Controller) NewRequest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRequest = time.Now()
}

// backendDisabled reports whether an operator has turned a backend off on this
// node via HPX_NODE_DISABLE_<TYPE>=1 (regardless of what the panel assigns). Lets
// a container run a fixed subset of backends like the interactive installer does.
func backendDisabled(t common.BackendType) bool {
	names := map[common.BackendType][]string{
		common.BackendType_XRAY:      {"HPX_NODE_DISABLE_XRAY"},
		common.BackendType_OPENVPN:   {"HPX_NODE_DISABLE_OPENVPN"},
		common.BackendType_WIREGUARD: {"HPX_NODE_DISABLE_WIREGUARD", "HPX_NODE_DISABLE_WG"},
		common.BackendType_IKEV2:     {"HPX_NODE_DISABLE_IKEV2"},
		common.BackendType_L2TP:      {"HPX_NODE_DISABLE_L2TP"},
	}
	for _, n := range names[t] {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(n))) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

// StartBackend brings a core up and adds it to the node's backend set. Cores
// are tracked per type+instance (see backendKey), so a node can run several
// cores side by side — different protocols, and also several cores of the same
// protocol such as OpenVPN on UDP and on TCP. Calling it again for the same
// instance shuts the old process down and swaps the new one in.
func (c *Controller) StartBackend(ctx context.Context, backendCfg *common.Backend) error {
	if backendDisabled(backendCfg.GetType()) {
		return fmt.Errorf("backend %q is disabled on this node (HPX_NODE_DISABLE_*)", backendTypeKey(backendCfg.GetType()))
	}

	key := backendKey{
		typ:      backendCfg.GetType(),
		instance: backendInstanceID(backendCfg.GetType(), backendCfg.GetConfig()),
	}

	// Retire a previous instance of this exact core *before* launching the new
	// one. The replacement reuses the same listen port and the same on-disk
	// state, so letting the two overlap makes the new process fail to bind and
	// exit — and the old one is torn down straight after, leaving nothing
	// running. Cores under a different key are untouched and keep serving.
	c.mu.Lock()
	old := c.backends[key]
	delete(c.backends, key)
	c.mu.Unlock()
	if old != nil {
		old.Shutdown()
	}

	var newBackend backend.Backend

	switch backendCfg.GetType() {
	case common.BackendType_XRAY:
		config, err := xray.NewConfig(backendCfg.GetConfig(), backendCfg.GetExcludeInbounds())
		if err != nil {
			return err
		}

		newBackend, err = xray.New(
			ctx,
			config,
			backendCfg.GetUsers(),
			c.apiPort,
			c.metricPort,
			c.cfg,
		)
		if err != nil {
			return err
		}

	case common.BackendType_WIREGUARD:
		if err := wireguard.CheckDeps(); err != nil {
			return err
		}
		config, err := wireguard.NewConfig(backendCfg.GetConfig())
		if err != nil {
			return err
		}
		newBackend, err = wireguard.New(c.cfg, config, backendCfg.GetUsers())
		if err != nil {
			return err
		}

	case common.BackendType_OPENVPN:
		if err := openvpn.CheckDeps(); err != nil {
			return err
		}
		config, err := openvpn.NewConfig(backendCfg.GetConfig())
		if err != nil {
			return err
		}
		// NewBackend starts one server per listener, so a single core can offer
		// both UDP and TCP.
		newBackend, err = openvpn.NewBackend(c.cfg, config, backendCfg.GetUsers())
		if err != nil {
			return err
		}

	case common.BackendType_IKEV2:
		if err := ikev2.CheckDeps(); err != nil {
			return err
		}
		config, err := ikev2.NewConfig(backendCfg.GetConfig())
		if err != nil {
			return err
		}
		newBackend, err = ikev2.New(c.cfg, config, backendCfg.GetUsers())
		if err != nil {
			return err
		}

	case common.BackendType_L2TP:
		if err := l2tp.CheckDeps(); err != nil {
			return err
		}
		config, err := l2tp.NewConfig(backendCfg.GetConfig())
		if err != nil {
			return err
		}
		newBackend, err = l2tp.New(c.cfg, config, backendCfg.GetUsers())
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid backend type")
	}

	c.mu.Lock()
	c.backends[key] = newBackend
	c.mu.Unlock()

	return nil
}

// Backend returns a composite view over every core running on this node, so the
// rpc/rest handlers can keep operating on a single backend.Backend.
func (c *Controller) Backend() backend.Backend {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.backends) == 0 {
		return nil
	}
	list := make([]backend.Backend, 0, len(c.backends))
	for _, b := range c.backends {
		list = append(list, b)
	}
	composite := backend.NewComposite(list)
	if composite == nil {
		return nil
	}
	return composite
}

// enforceGlobalLimits periodically applies each user's ip_limit across every
// protocol on the node. Per-backend enforcement only counts a user's devices
// within one protocol, so a user at ip_limit 1 could still be online via ikev2
// and l2tp at once; this pass sheds that cross-protocol excess by priority.
func (c *Controller) enforceGlobalLimits(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			limiters := make([]backend.DeviceLimiter, 0, len(c.backends))
			for _, b := range c.backends {
				if dl, ok := b.(backend.DeviceLimiter); ok {
					limiters = append(limiters, dl)
				}
			}
			c.mu.RUnlock()
			backend.EnforceGlobalDeviceLimits(limiters)
		}
	}
}

func (c *Controller) keepAliveTracker(ctx context.Context, keepAlive time.Duration) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			lastRequest := c.lastRequest
			c.mu.RUnlock()
			if time.Since(lastRequest) >= keepAlive {
				log.Println("disconnect automatically due to keep alive timeout")
				c.Disconnect()
			}
		}
	}
}

func (c *Controller) recordSystemStats(ctx context.Context) {
	interval := 1500 * time.Millisecond

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	collect := func() {
		stats, err := sysstats.GetSystemStats()
		if err != nil {
			log.Printf("Failed to get system stats: %v", err)
			return
		}

		c.mu.Lock()
		c.stats = stats
		c.mu.Unlock()
	}

	collect()
	c.refreshShaping()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collect()
			c.refreshShaping()
		}
	}
}

func (c *Controller) SystemStats(ctx context.Context) *common.SystemStatsResponse {
	c.mu.RLock()
	statsSnapshot := c.stats
	c.mu.RUnlock()

	backendSnapshot := c.Backend()

	response := &common.SystemStatsResponse{}
	if statsSnapshot != nil {
		response = &common.SystemStatsResponse{
			MemTotal:               statsSnapshot.GetMemTotal(),
			MemUsed:                statsSnapshot.GetMemUsed(),
			CpuCores:               statsSnapshot.GetCpuCores(),
			CpuUsage:               statsSnapshot.GetCpuUsage(),
			IncomingBandwidthSpeed: statsSnapshot.GetIncomingBandwidthSpeed(),
			OutgoingBandwidthSpeed: statsSnapshot.GetOutgoingBandwidthSpeed(),
			Uptime:                 statsSnapshot.GetUptime(),
		}
	}

	if backendSnapshot == nil {
		return response
	}

	// Backend uptime is owned by each backend implementation; controller only forwards it here.
	backendStats, err := backendSnapshot.GetSysStats(ctx)
	if err != nil {
		log.Printf("Failed to get backend uptime for system stats: %v", err)
		return response
	}

	response.Uptime = uint64(backendStats.GetUptime())
	return response
}

// backendTypeKey maps a backend type to the short name the panel keys on
// (matches the capabilities/versions naming: wireguard -> "wg").
// backendInstanceID pulls the identifier that distinguishes two cores of the
// same type out of the core config the panel sent. OpenVPN and IKEv2 are
// identified by their inbound tag and WireGuard by its interface name — all
// three already scope their on-disk state by that value, so instances never
// collide. Xray is deliberately left unkeyed: one xray process serves every
// inbound, so a second xray core should still replace the first.
//
// An unparseable or tag-less config falls back to "", which restores the old
// replace-by-type behaviour rather than silently starting a duplicate.
func backendInstanceID(t common.BackendType, configStr string) string {
	var field string
	switch t {
	case common.BackendType_OPENVPN, common.BackendType_IKEV2, common.BackendType_L2TP:
		field = "inbound_tag"
	case common.BackendType_WIREGUARD:
		field = "interface_name"
	default:
		return ""
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(configStr), &parsed); err != nil {
		return ""
	}
	if v, ok := parsed[field].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func backendTypeKey(t common.BackendType) string {
	switch t {
	case common.BackendType_XRAY:
		return "xray"
	case common.BackendType_OPENVPN:
		return "openvpn"
	case common.BackendType_WIREGUARD:
		return "wg"
	case common.BackendType_IKEV2:
		return "ikev2"
	case common.BackendType_L2TP:
		return "l2tp"
	default:
		return t.String()
	}
}

// UserOnlineIpList merges every backend's online IPs for a user and tags each IP
// with the backend it is connected through. It makes the same backend calls the
// composite already makes, but keeps the protocol attribution the composite
// flattens away.
func (c *Controller) UserOnlineIpList(ctx context.Context, email string) *common.StatsOnlineIpListResponse {
	c.mu.RLock()
	typed := make(map[backendKey]backend.Backend, len(c.backends))
	for k, b := range c.backends {
		typed[k] = b
	}
	c.mu.RUnlock()

	resp := &common.StatsOnlineIpListResponse{
		Name:       email,
		Ips:        map[string]int64{},
		IpProtocol: map[string]string{},
	}
	for k, b := range typed {
		s, err := b.GetUserOnlineIpListStats(ctx, email)
		if err != nil || s == nil {
			continue
		}
		proto := backendTypeKey(k.typ)
		for ip, ts := range s.GetIps() {
			if ts >= resp.Ips[ip] {
				resp.Ips[ip] = ts
				resp.IpProtocol[ip] = proto
			}
		}
	}
	return resp
}

func (c *Controller) BaseInfoResponse() *common.BaseInfoResponse {
	back := c.Backend()
	avail, versions := c.capabilities()

	response := &common.BaseInfoResponse{
		Started:           false,
		CoreVersion:       "",
		NodeVersion:       NodeVersion,
		AvailableBackends: avail,
		BackendVersions:   versions,
	}

	if back != nil {
		response.Started = back.Started()
		response.CoreVersion = back.Version()
	}

	return response
}

// capabilities reports which backend types this node can run (their OS-level
// dependencies are installed) and each one's installed version. xray needs no
// external dep; the others are probed via each backend's CheckDeps. Results are
// cached because version detection execs external commands. The panel uses this
// to grey out cores a node cannot serve and to show installed versions.
func (c *Controller) capabilities() ([]common.BackendType, map[string]string) {
	c.capsOnce.Do(func() {
		var avail []common.BackendType
		versions := map[string]string{}
		// A backend counts as available only if it isn't disabled by env AND its
		// OS deps are present; the panel greys out the rest.
		if !backendDisabled(common.BackendType_XRAY) {
			avail = append(avail, common.BackendType_XRAY)
			versions["xray"] = xray.DetectVersion(c.cfg.XrayExecutablePath)
		}
		if !backendDisabled(common.BackendType_OPENVPN) && openvpn.CheckDeps() == nil {
			avail = append(avail, common.BackendType_OPENVPN)
			versions["openvpn"] = openvpn.DetectVersion()
		}
		if !backendDisabled(common.BackendType_WIREGUARD) && wireguard.CheckDeps() == nil {
			avail = append(avail, common.BackendType_WIREGUARD)
			versions["wg"] = wireguard.DetectVersion()
		}
		if !backendDisabled(common.BackendType_IKEV2) && ikev2.CheckDeps() == nil {
			avail = append(avail, common.BackendType_IKEV2)
			versions["ikev2"] = ikev2.DetectVersion()
		}
		if !backendDisabled(common.BackendType_L2TP) && l2tp.CheckDeps() == nil {
			avail = append(avail, common.BackendType_L2TP)
			versions["l2tp"] = l2tp.DetectVersion()
		}
		c.capsAvail = avail
		c.capsVersions = versions
	})
	return c.capsAvail, c.capsVersions
}

func (c *Controller) OutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	backendSnapshot := c.Backend()

	if backendSnapshot == nil {
		return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
	}

	return backendSnapshot.GetOutboundsLatency(ctx, request)
}
