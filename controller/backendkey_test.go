package controller

import (
	"testing"

	"github.com/pooyahpx/HPXNODE/common"
)

func TestBackendInstanceID(t *testing.T) {
	tests := []struct {
		name   string
		typ    common.BackendType
		config string
		want   string
	}{
		{
			name:   "openvpn is keyed by inbound tag",
			typ:    common.BackendType_OPENVPN,
			config: `{"inbound_tag":"ovpn-udp","port":1194,"proto":"udp"}`,
			want:   "ovpn-udp",
		},
		{
			name:   "a second openvpn core gets a different key",
			typ:    common.BackendType_OPENVPN,
			config: `{"inbound_tag":"ovpn-tcp","port":1195,"proto":"tcp"}`,
			want:   "ovpn-tcp",
		},
		{
			name:   "ikev2 is keyed by inbound tag",
			typ:    common.BackendType_IKEV2,
			config: `{"inbound_tag":"ikev2-main","pool":"10.30.0.0/24"}`,
			want:   "ikev2-main",
		},
		{
			name:   "wireguard is keyed by interface name",
			typ:    common.BackendType_WIREGUARD,
			config: `{"interface_name":"wg0","listen_port":51820}`,
			want:   "wg0",
		},
		{
			name:   "xray stays unkeyed so a new core replaces the old one",
			typ:    common.BackendType_XRAY,
			config: `{"inbounds":[{"tag":"vless-in"}]}`,
			want:   "",
		},
		{
			name:   "surrounding whitespace is trimmed",
			typ:    common.BackendType_OPENVPN,
			config: `{"inbound_tag":"  ovpn-udp  "}`,
			want:   "ovpn-udp",
		},
		{
			name:   "a config without the tag falls back to replace-by-type",
			typ:    common.BackendType_OPENVPN,
			config: `{"port":1194}`,
			want:   "",
		},
		{
			name:   "unparseable config falls back to replace-by-type",
			typ:    common.BackendType_OPENVPN,
			config: `not json`,
			want:   "",
		},
		{
			name:   "a non-string tag falls back to replace-by-type",
			typ:    common.BackendType_OPENVPN,
			config: `{"inbound_tag":42}`,
			want:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := backendInstanceID(tc.typ, tc.config); got != tc.want {
				t.Fatalf("backendInstanceID() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Two OpenVPN cores must occupy distinct map slots, otherwise starting the TCP
// one tears the UDP one down.
func TestBackendKeyDistinguishesSameTypeInstances(t *testing.T) {
	udp := backendKey{
		typ:      common.BackendType_OPENVPN,
		instance: backendInstanceID(common.BackendType_OPENVPN, `{"inbound_tag":"ovpn-udp"}`),
	}
	tcp := backendKey{
		typ:      common.BackendType_OPENVPN,
		instance: backendInstanceID(common.BackendType_OPENVPN, `{"inbound_tag":"ovpn-tcp"}`),
	}
	if udp == tcp {
		t.Fatal("two openvpn cores with different inbound tags must not share a key")
	}

	backends := map[backendKey]struct{}{udp: {}, tcp: {}}
	if len(backends) != 2 {
		t.Fatalf("expected both openvpn cores to be tracked, got %d", len(backends))
	}

	// The same core restarting must reuse its slot rather than pile up.
	same := backendKey{
		typ:      common.BackendType_OPENVPN,
		instance: backendInstanceID(common.BackendType_OPENVPN, `{"inbound_tag":"ovpn-udp","port":1194}`),
	}
	if same != udp {
		t.Fatal("restarting a core must map to the same key so the old instance is replaced")
	}
}

// Different protocols keep working side by side.
func TestBackendKeySeparatesTypes(t *testing.T) {
	ovpn := backendKey{typ: common.BackendType_OPENVPN, instance: "shared-tag"}
	ike := backendKey{typ: common.BackendType_IKEV2, instance: "shared-tag"}
	if ovpn == ike {
		t.Fatal("cores of different types must never collide, even with the same instance id")
	}
}
