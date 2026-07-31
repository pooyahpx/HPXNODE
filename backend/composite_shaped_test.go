package backend

import (
	"context"
	"testing"

	"github.com/pooyahpx/HPXNODE/backend/ratelimit"
	"github.com/pooyahpx/HPXNODE/common"
)

// shapedStub is a Backend that also reports shaped clients.
type shapedStub struct {
	nopBackend
	clients []ratelimit.Client
}

func (s shapedStub) ShapedClients() []ratelimit.Client { return s.clients }

// plainStub is a Backend with no ShapedClients (e.g. xray).
type plainStub struct{ nopBackend }

// A composite over a multi-listener OpenVPN (two shaped members) plus an
// unshaped one must return every shaped client. This is the regression: without
// forwarding, the controller sees only the composite and shapes nobody.
func TestCompositeShapedClientsMergesMembers(t *testing.T) {
	c := NewComposite([]Backend{
		shapedStub{clients: []ratelimit.Client{{User: "1", Address: "10.29.0.5", LimitKbps: 3000}}},
		shapedStub{clients: []ratelimit.Client{{User: "1", Address: "10.31.0.5", LimitKbps: 3000}}},
		plainStub{},
	})

	got := c.ShapedClients()
	if len(got) != 2 {
		t.Fatalf("expected both listeners' clients, got %d: %+v", len(got), got)
	}
	addrs := map[string]bool{got[0].Address: true, got[1].Address: true}
	if !addrs["10.29.0.5"] || !addrs["10.31.0.5"] {
		t.Fatalf("both tunnel addresses must be shaped, got %+v", got)
	}

	// The composite must satisfy the shaper's optional interface.
	var _ interface {
		ShapedClients() []ratelimit.Client
	} = c
}

// nopBackend implements Backend with do-nothing methods so stubs only override
// what they care about.
type nopBackend struct{}

func (nopBackend) Started() bool                                     { return true }
func (nopBackend) Version() string                                   { return "" }
func (nopBackend) Logs() <-chan string                               { return nil }
func (nopBackend) Restart() error                                    { return nil }
func (nopBackend) Shutdown()                                         {}
func (nopBackend) SyncUser(context.Context, *common.User) error      { return nil }
func (nopBackend) SyncUsers(context.Context, []*common.User) error   { return nil }
func (nopBackend) UpdateUsers(context.Context, []*common.User) error { return nil }
func (nopBackend) UpdateUsersAndRestart(context.Context, []*common.User) error {
	return nil
}
func (nopBackend) GetSysStats(context.Context) (*common.BackendStatsResponse, error) {
	return &common.BackendStatsResponse{}, nil
}
func (nopBackend) GetStats(context.Context, *common.StatRequest) (*common.StatResponse, error) {
	return &common.StatResponse{}, nil
}
func (nopBackend) GetOutboundsLatency(context.Context, *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{}, nil
}
func (nopBackend) GetUserOnlineStats(context.Context, string) (*common.OnlineStatResponse, error) {
	return &common.OnlineStatResponse{}, nil
}
func (nopBackend) GetUserOnlineIpListStats(context.Context, string) (*common.StatsOnlineIpListResponse, error) {
	return &common.StatsOnlineIpListResponse{}, nil
}
