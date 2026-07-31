package openvpn

import (
	"net/netip"
	"testing"
)

func TestNormalizeListenersDefaultsToSingleEndpoint(t *testing.T) {
	c := &Config{Port: 1194, Proto: "udp"}
	if err := c.normalizeListeners(); err != nil {
		t.Fatal(err)
	}
	if len(c.Listeners) != 1 {
		t.Fatalf("expected one listener, got %d", len(c.Listeners))
	}
	if c.Listeners[0] != (Listener{Port: 1194, Proto: "udp"}) {
		t.Fatalf("listener should mirror port/proto, got %+v", c.Listeners[0])
	}
}

func TestNormalizeListenersFillsGapsAndRejectsClashes(t *testing.T) {
	t.Run("missing fields inherit the core defaults", func(t *testing.T) {
		c := &Config{Port: 1194, Proto: "udp", Listeners: []Listener{{}, {Port: 1195, Proto: "TCP"}}}
		if err := c.normalizeListeners(); err != nil {
			t.Fatal(err)
		}
		if c.Listeners[0] != (Listener{Port: 1194, Proto: "udp"}) {
			t.Fatalf("empty listener should inherit port/proto, got %+v", c.Listeners[0])
		}
		if c.Listeners[1] != (Listener{Port: 1195, Proto: "tcp"}) {
			t.Fatalf("proto should be lowercased, got %+v", c.Listeners[1])
		}
	})

	t.Run("duplicate endpoints are rejected", func(t *testing.T) {
		c := &Config{Port: 1194, Proto: "udp", Listeners: []Listener{{Port: 1194, Proto: "udp"}, {Port: 1194, Proto: "udp"}}}
		if err := c.normalizeListeners(); err == nil {
			t.Fatal("two identical listeners must be rejected: the second could never bind")
		}
	})

	t.Run("same port on different protocols is allowed", func(t *testing.T) {
		c := &Config{Port: 1194, Proto: "udp", Listeners: []Listener{{Port: 1194, Proto: "udp"}, {Port: 1194, Proto: "tcp"}}}
		if err := c.normalizeListeners(); err != nil {
			t.Fatalf("udp and tcp on the same port do not clash: %v", err)
		}
	})

	t.Run("nonsense protocol is rejected", func(t *testing.T) {
		c := &Config{Port: 1194, Proto: "udp", Listeners: []Listener{{Port: 1194, Proto: "sctp"}}}
		if err := c.normalizeListeners(); err == nil {
			t.Fatal("expected an unknown protocol to be rejected")
		}
	})

	t.Run("out-of-range port is rejected", func(t *testing.T) {
		c := &Config{Port: 1194, Proto: "udp", Listeners: []Listener{{Port: 70000, Proto: "udp"}}}
		if err := c.normalizeListeners(); err == nil {
			t.Fatal("expected an out-of-range port to be rejected")
		}
	})
}

func TestSplitSubnetGivesEachListenerItsOwnBlock(t *testing.T) {
	t.Run("single listener keeps the subnet untouched", func(t *testing.T) {
		got, err := splitSubnet("10.29.0.0/16", 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		if got != "10.29.0.0/16" {
			t.Fatalf("expected the subnet unchanged, got %s", got)
		}
	})

	t.Run("two listeners get non-overlapping halves", func(t *testing.T) {
		a, err := splitSubnet("10.29.0.0/16", 0, 2)
		if err != nil {
			t.Fatal(err)
		}
		b, err := splitSubnet("10.29.0.0/16", 1, 2)
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Fatal("both listeners got the same block; clients would collide")
		}
		pa, pb := netip.MustParsePrefix(a), netip.MustParsePrefix(b)
		if pa.Overlaps(pb) {
			t.Fatalf("blocks %s and %s overlap", a, b)
		}
		if pa.Bits() != 17 || pb.Bits() != 17 {
			t.Fatalf("a /16 split in two should give two /17s, got %s and %s", a, b)
		}
	})

	t.Run("three listeners still get distinct blocks", func(t *testing.T) {
		seen := map[string]bool{}
		var prefixes []netip.Prefix
		for i := range 3 {
			got, err := splitSubnet("10.29.0.0/16", i, 3)
			if err != nil {
				t.Fatal(err)
			}
			if seen[got] {
				t.Fatalf("block %s handed out twice", got)
			}
			seen[got] = true
			prefixes = append(prefixes, netip.MustParsePrefix(got))
		}
		for i := range prefixes {
			for j := i + 1; j < len(prefixes); j++ {
				if prefixes[i].Overlaps(prefixes[j]) {
					t.Fatalf("%s overlaps %s", prefixes[i], prefixes[j])
				}
			}
		}
	})

	t.Run("a subnet too small to split is rejected", func(t *testing.T) {
		if _, err := splitSubnet("10.29.0.0/24", 0, 2); err == nil {
			t.Fatal("splitting a /24 would leave unusable pools; expected an error")
		}
	})

	t.Run("an invalid subnet is reported", func(t *testing.T) {
		if _, err := splitSubnet("not-a-cidr", 0, 2); err == nil {
			t.Fatal("expected an invalid CIDR to be rejected")
		}
	})
}

func TestDeriveIsolatesEachListener(t *testing.T) {
	base := &Config{
		InboundTag:   "ovpn-main",
		Port:         1194,
		Proto:        "udp",
		ServerSubnet: "10.29.0.0/16",
		Listeners:    []Listener{{Port: 1194, Proto: "udp"}, {Port: 1195, Proto: "tcp"}},
	}

	udp, err := base.derive("/var/lib/hpx-node/generated", base.Listeners[0], 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := base.derive("/var/lib/hpx-node/generated", base.Listeners[1], 1, 2)
	if err != nil {
		t.Fatal(err)
	}

	if udp.Port == tcp.Port && udp.Proto == tcp.Proto {
		t.Fatal("derived listeners must differ")
	}
	if udp.ServerSubnet == tcp.ServerSubnet {
		t.Fatal("each listener needs its own address pool")
	}
	if udp.workDir == tcp.workDir {
		t.Fatal("each listener needs its own work dir, or they clobber each other's socket and status file")
	}
	if base.ServerSubnet != "10.29.0.0/16" || base.Port != 1194 {
		t.Fatal("derive must not mutate the core config it was called on")
	}
	// The shared PKI has to carry over, otherwise clients issued for the core
	// would only work against one of its endpoints.
	if udp.InboundTag != base.InboundTag || tcp.InboundTag != base.InboundTag {
		t.Fatal("derived configs must keep the core's inbound tag")
	}
}
