package backend

import (
	"reflect"
	"sort"
	"testing"
)

// fakeLimiter is an in-memory DeviceLimiter for exercising the cross-protocol
// allocation logic without a real backend.
type fakeLimiter struct {
	proto  string
	counts map[string]int
	limits map[string]uint32 // users this backend knows
	kept   map[string]int    // recorded KeepDevices calls
}

func (f *fakeLimiter) Protocol() string                  { return f.proto }
func (f *fakeLimiter) OnlineDeviceCounts() map[string]int { return f.counts }
func (f *fakeLimiter) UserLimit(u string) (uint32, bool) {
	l, ok := f.limits[u]
	return l, ok
}
func (f *fakeLimiter) KeepDevices(u string, keep int) {
	if f.kept == nil {
		f.kept = map[string]int{}
	}
	f.kept[u] = keep
}

func TestEnforceGlobalDeviceLimits_ShedsLowestPriority(t *testing.T) {
	// user "1": ip_limit 1, online via ikev2 (1) + l2tp (1) => l2tp must yield.
	ike := &fakeLimiter{proto: "ikev2", counts: map[string]int{"1": 1}, limits: map[string]uint32{"1": 1}}
	l2 := &fakeLimiter{proto: "l2tp", counts: map[string]int{"1": 1}, limits: map[string]uint32{"1": 1}}

	EnforceGlobalDeviceLimits([]DeviceLimiter{l2, ike})

	if ike.kept != nil {
		t.Fatalf("ikev2 (higher priority) must not be shed, got %v", ike.kept)
	}
	if got, want := l2.kept["1"], 0; got != want || len(l2.kept) != 1 {
		t.Fatalf("l2tp should be kept down to %d, got %v", want, l2.kept)
	}
}

func TestEnforceGlobalDeviceLimits_AllocatesByPriority(t *testing.T) {
	// ip_limit 2, ikev2 has 1 device, l2tp has 2 => keep ikev2's 1 + one l2tp.
	ike := &fakeLimiter{proto: "ikev2", counts: map[string]int{"1": 1}, limits: map[string]uint32{"1": 2}}
	l2 := &fakeLimiter{proto: "l2tp", counts: map[string]int{"1": 2}, limits: map[string]uint32{"1": 2}}

	EnforceGlobalDeviceLimits([]DeviceLimiter{ike, l2})

	if ike.kept != nil {
		t.Fatalf("ikev2 within budget must not be shed, got %v", ike.kept)
	}
	if got := l2.kept["1"]; got != 1 {
		t.Fatalf("l2tp should keep 1 (budget left after ikev2), got %v", l2.kept)
	}
}

func TestEnforceGlobalDeviceLimits_UnderLimitNoop(t *testing.T) {
	ike := &fakeLimiter{proto: "ikev2", counts: map[string]int{"1": 1}, limits: map[string]uint32{"1": 3}}
	l2 := &fakeLimiter{proto: "l2tp", counts: map[string]int{"1": 1}, limits: map[string]uint32{"1": 3}}

	EnforceGlobalDeviceLimits([]DeviceLimiter{ike, l2})

	if ike.kept != nil || l2.kept != nil {
		t.Fatalf("under limit: nothing should be shed, got ike=%v l2=%v", ike.kept, l2.kept)
	}
}

func TestEnforceGlobalDeviceLimits_UnlimitedNoop(t *testing.T) {
	// limit 0 = unlimited: never shed regardless of counts.
	ike := &fakeLimiter{proto: "ikev2", counts: map[string]int{"1": 3}, limits: map[string]uint32{"1": 0}}
	l2 := &fakeLimiter{proto: "l2tp", counts: map[string]int{"1": 3}, limits: map[string]uint32{"1": 0}}

	EnforceGlobalDeviceLimits([]DeviceLimiter{ike, l2})

	if ike.kept != nil || l2.kept != nil {
		t.Fatalf("unlimited: nothing should be shed, got ike=%v l2=%v", ike.kept, l2.kept)
	}
}

func TestEnforceGlobalDeviceLimits_SingleBackendNoop(t *testing.T) {
	l2 := &fakeLimiter{proto: "l2tp", counts: map[string]int{"1": 5}, limits: map[string]uint32{"1": 1}}
	EnforceGlobalDeviceLimits([]DeviceLimiter{l2})
	if l2.kept != nil {
		t.Fatalf("single backend is enforced locally, cross-protocol pass must skip it, got %v", l2.kept)
	}
}

func TestDeviceProtoRankOrder(t *testing.T) {
	protos := []string{"l2tp", "ikev2", "openvpn", "wireguard", "xray"}
	sort.SliceStable(protos, func(i, j int) bool {
		return deviceProtoRank(protos[i]) < deviceProtoRank(protos[j])
	})
	want := []string{"xray", "wireguard", "openvpn", "ikev2", "l2tp"}
	if !reflect.DeepEqual(protos, want) {
		t.Fatalf("priority order = %v, want %v", protos, want)
	}
}
