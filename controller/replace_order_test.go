package controller

import (
	"context"
	"testing"

	"github.com/pooyahpx/HPXNODE/backend"
	"github.com/pooyahpx/HPXNODE/common"
)

// fakeBackend records whether it was shut down.
type fakeBackend struct{ shutdownCalled *bool }

func (f fakeBackend) Started() bool       { return true }
func (f fakeBackend) Version() string     { return "test" }
func (f fakeBackend) Logs() <-chan string { return nil }
func (f fakeBackend) Restart() error      { return nil }
func (f fakeBackend) Shutdown()           { *f.shutdownCalled = true }
func (f fakeBackend) SyncUser(context.Context, *common.User) error {
	return nil
}
func (f fakeBackend) SyncUsers(context.Context, []*common.User) error   { return nil }
func (f fakeBackend) UpdateUsers(context.Context, []*common.User) error { return nil }
func (f fakeBackend) UpdateUsersAndRestart(context.Context, []*common.User) error {
	return nil
}
func (f fakeBackend) GetSysStats(context.Context) (*common.BackendStatsResponse, error) {
	return nil, nil
}
func (f fakeBackend) GetStats(context.Context, *common.StatRequest) (*common.StatResponse, error) {
	return nil, nil
}
func (f fakeBackend) GetOutboundsLatency(context.Context, *common.LatencyRequest) (*common.LatencyResponse, error) {
	return nil, nil
}
func (f fakeBackend) GetUserOnlineStats(context.Context, string) (*common.OnlineStatResponse, error) {
	return nil, nil
}
func (f fakeBackend) GetUserOnlineIpListStats(context.Context, string) (*common.StatsOnlineIpListResponse, error) {
	return nil, nil
}

// A replacement core reuses the previous one's listen port, so the old instance
// has to be gone before the new process starts — otherwise the new one cannot
// bind and both end up dead. StartBackend must therefore shut the old instance
// down (and drop it from the map) before it constructs the replacement. Here we
// drive an invalid config so construction fails, and assert the old instance was
// already retired by then.
func TestStartBackendRetiresOldInstanceBeforeStartingNew(t *testing.T) {
	shutdown := false
	c := New(nil)
	key := backendKey{typ: common.BackendType_OPENVPN, instance: "ovpn-main"}
	c.backends[key] = fakeBackend{shutdownCalled: &shutdown}

	// The config parses (so the instance id resolves) but is missing every
	// required field, so openvpn.NewConfig fails — StartBackend returns before
	// it could ever reach a "swap at the end" step.
	err := c.StartBackend(context.Background(), &common.Backend{
		Type:   common.BackendType_OPENVPN,
		Config: `{"inbound_tag":"ovpn-main"}`,
	})
	if err == nil {
		t.Fatal("expected the broken config to fail")
	}
	if !shutdown {
		t.Fatal("the previous instance must be shut down before the replacement is started")
	}
	if _, still := c.backends[key]; still {
		t.Fatal("the retired instance must not be left in the backend map")
	}
}

// Cores under a different key must survive a neighbour being replaced.
func TestStartBackendLeavesOtherInstancesAlone(t *testing.T) {
	udpShutdown, tcpShutdown := false, false
	c := New(nil)
	udpKey := backendKey{typ: common.BackendType_OPENVPN, instance: "ovpn-main"}
	tcpKey := backendKey{typ: common.BackendType_OPENVPN, instance: "ovpn-tcp"}
	c.backends[udpKey] = fakeBackend{shutdownCalled: &udpShutdown}
	c.backends[tcpKey] = fakeBackend{shutdownCalled: &tcpShutdown}

	_ = c.StartBackend(context.Background(), &common.Backend{
		Type:   common.BackendType_OPENVPN,
		Config: `{"inbound_tag":"ovpn-main"}`, // parses, then fails validation
	})

	if !udpShutdown {
		t.Fatal("the core being replaced should have been shut down")
	}
	if tcpShutdown {
		t.Fatal("replacing the UDP core must not touch the TCP core")
	}
	if _, ok := c.backends[tcpKey]; !ok {
		t.Fatal("the TCP core must stay registered")
	}
}

var _ backend.Backend = fakeBackend{}
