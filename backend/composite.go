package backend

import (
	"context"
	"strings"
	"sync"

	"github.com/pooyahpx/HPXNODE/backend/ratelimit"
	"github.com/pooyahpx/HPXNODE/common"
)

// Composite fans a single Backend-shaped call out across several real backends
// (e.g. openvpn + ikev2 running on one node). It lets the controller and the
// rpc/rest handlers keep treating the node as if it owned one backend, while
// each underlying backend independently decides which users/stats belong to it.
type Composite struct {
	backends []Backend
}

// NewComposite builds a composite over the given backends. It returns nil when
// there are no backends so callers can keep the "no backend" contract.
func NewComposite(backends []Backend) *Composite {
	if len(backends) == 0 {
		return nil
	}
	return &Composite{backends: backends}
}

// speedShaped is the optional interface a backend implements to report clients
// that carry a speed limit. It mirrors the controller's shapedBackend so the
// composite can forward the call.
type speedShaped interface {
	ShapedClients() []ratelimit.Client
}

// ShapedClients merges the shaped clients of every member that supports it, so a
// composite backend (e.g. OpenVPN split across a UDP and a TCP listener) still
// gets its clients shaped. Without this, the controller's type assertion would
// see only the composite — which lacks the method — and silently skip shaping
// every OpenVPN client on a multi-listener node.
func (c *Composite) ShapedClients() []ratelimit.Client {
	var out []ratelimit.Client
	for _, b := range c.backends {
		if sb, ok := b.(speedShaped); ok {
			out = append(out, sb.ShapedClients()...)
		}
	}
	return out
}

// Started reports true when at least one underlying backend is up. The node is
// usable as long as any of its cores serves traffic.
func (c *Composite) Started() bool {
	for _, b := range c.backends {
		if b.Started() {
			return true
		}
	}
	return false
}

// Version joins the per-backend versions so the panel's core_version field
// reflects everything running on the node.
func (c *Composite) Version() string {
	parts := make([]string, 0, len(c.backends))
	for _, b := range c.backends {
		if v := b.Version(); v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, ", ")
}

// Logs merges every backend's log stream into one channel.
func (c *Composite) Logs() <-chan string {
	out := make(chan string, 256)
	var wg sync.WaitGroup
	for _, b := range c.backends {
		src := b.Logs()
		if src == nil {
			continue
		}
		wg.Add(1)
		go func(ch <-chan string) {
			defer wg.Done()
			for line := range ch {
				select {
				case out <- line:
				default:
				}
			}
		}(src)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// Restart restarts all backends, returning the first error.
func (c *Composite) Restart() error {
	var firstErr error
	for _, b := range c.backends {
		if err := b.Restart(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Shutdown tears down every backend.
func (c *Composite) Shutdown() {
	for _, b := range c.backends {
		b.Shutdown()
	}
}

// SyncUser pushes a user to every backend; each backend keeps only the users it
// actually serves (a vless user is a no-op for the openvpn backend, etc.).
func (c *Composite) SyncUser(ctx context.Context, user *common.User) error {
	var firstErr error
	for _, b := range c.backends {
		if err := b.SyncUser(ctx, user); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *Composite) SyncUsers(ctx context.Context, users []*common.User) error {
	var firstErr error
	for _, b := range c.backends {
		if err := b.SyncUsers(ctx, users); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *Composite) UpdateUsers(ctx context.Context, users []*common.User) error {
	var firstErr error
	for _, b := range c.backends {
		if err := b.UpdateUsers(ctx, users); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *Composite) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	var firstErr error
	for _, b := range c.backends {
		if err := b.UpdateUsersAndRestart(ctx, users); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// GetSysStats returns the freshest backend runtime stats, preferring the one
// with the greatest uptime so the reported node uptime stays monotonic.
func (c *Composite) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	var best *common.BackendStatsResponse
	var firstErr error
	for _, b := range c.backends {
		s, err := b.GetSysStats(ctx)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if best == nil || s.GetUptime() > best.GetUptime() {
			best = s
		}
	}
	if best == nil {
		return &common.BackendStatsResponse{}, firstErr
	}
	return best, nil
}

// GetStats concatenates the per-backend stat lists.
func (c *Composite) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	merged := &common.StatResponse{}
	var firstErr error
	for _, b := range c.backends {
		s, err := b.GetStats(ctx, request)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if s != nil {
			merged.Stats = append(merged.Stats, s.GetStats()...)
		}
	}
	if len(merged.Stats) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return merged, nil
}

// GetOutboundsLatency is only meaningful for xray; sum across backends that
// implement it (the rest return empty).
func (c *Composite) GetOutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	merged := &common.LatencyResponse{}
	var firstErr error
	for _, b := range c.backends {
		l, err := b.GetOutboundsLatency(ctx, request)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if l != nil {
			merged.Latencies = append(merged.Latencies, l.GetLatencies()...)
		}
	}
	if len(merged.Latencies) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return merged, nil
}

// GetUserOnlineStats sums the online device/session count for a user across all
// backends, so a user connected via openvpn and ikev2 counts on both.
func (c *Composite) GetUserOnlineStats(ctx context.Context, name string) (*common.OnlineStatResponse, error) {
	var total int64
	var found bool
	var firstErr error
	for _, b := range c.backends {
		s, err := b.GetUserOnlineStats(ctx, name)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if s != nil {
			total += s.GetValue()
			found = true
		}
	}
	if !found && firstErr != nil {
		return nil, firstErr
	}
	return &common.OnlineStatResponse{Name: name, Value: total}, nil
}

// GetUserOnlineIpListStats merges the per-backend IP->count maps for a user.
func (c *Composite) GetUserOnlineIpListStats(ctx context.Context, name string) (*common.StatsOnlineIpListResponse, error) {
	merged := map[string]int64{}
	var found bool
	var firstErr error
	for _, b := range c.backends {
		s, err := b.GetUserOnlineIpListStats(ctx, name)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if s != nil {
			for ip, v := range s.GetIps() {
				merged[ip] += v
			}
			found = true
		}
	}
	if !found && firstErr != nil {
		return nil, firstErr
	}
	return &common.StatsOnlineIpListResponse{Name: name, Ips: merged}, nil
}
