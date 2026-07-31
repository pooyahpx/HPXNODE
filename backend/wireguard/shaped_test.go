package wireguard

import (
	"net"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustCIDR(t *testing.T, cidr string) net.IPNet {
	t.Helper()
	_, ipn, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return *ipn
}

func TestShapedClients(t *testing.T) {
	wg := &WireGuard{
		peerStore: NewPeerStore(),
		userSpeed: map[string]uint32{
			"alice": 8000, // 8 Mbit
			"bob":   0,    // unlimited
		},
	}
	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	wg.peerStore.Init([]*PeerInfo{
		{Email: "alice", PublicKey: k1.PublicKey(), AllowedIPs: []net.IPNet{mustCIDR(t, "10.0.0.5/32")}},
		{Email: "bob", PublicKey: k2.PublicKey(), AllowedIPs: []net.IPNet{mustCIDR(t, "10.0.0.6/32")}},
	})

	clients := wg.ShapedClients()

	if len(clients) != 1 {
		t.Fatalf("only the limited user should be shaped, got %d clients", len(clients))
	}
	c := clients[0]
	if c.User != "alice" || c.Address != "10.0.0.5" || c.LimitKbps != 8000 {
		t.Fatalf("unexpected shaped client: %+v", c)
	}
}

func TestShapedClientsEmptyWhenNoLimits(t *testing.T) {
	wg := &WireGuard{peerStore: NewPeerStore(), userSpeed: map[string]uint32{}}
	k, _ := wgtypes.GeneratePrivateKey()
	wg.peerStore.Init([]*PeerInfo{
		{Email: "carol", PublicKey: k.PublicKey(), AllowedIPs: []net.IPNet{mustCIDR(t, "10.0.0.7/32")}},
	})
	if got := wg.ShapedClients(); len(got) != 0 {
		t.Fatalf("a peer with no limit must not be shaped, got %v", got)
	}
}
