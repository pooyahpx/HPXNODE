package openvpn

import "testing"

// The tunnel address lives in field 4 of a status-3 CLIENT_LIST row; the shaper
// needs it, so a regression here would silently unshape every OpenVPN client.
func TestParseStatusLineExtractsVirtualAddress(t *testing.T) {
	line := "CLIENT_LIST\t3\t1.2.3.4:5555\t10.29.0.7\t\t1000\t2000\t" +
		"2026-07-25 00:00:00\t1784000000\tUNDEF\t42\t0\tAES-256-GCM"
	cs, ok := parseStatusLine(line)
	if !ok {
		t.Fatal("expected the CLIENT_LIST row to parse")
	}
	if cs.CommonName != "3" {
		t.Fatalf("common name = %q", cs.CommonName)
	}
	if cs.VirtualAddr != "10.29.0.7" {
		t.Fatalf("virtual address = %q, want 10.29.0.7", cs.VirtualAddr)
	}
}

func TestSpeedLimitForUnknownUserIsZero(t *testing.T) {
	s := newUserStore("ovpn-main")
	if got := s.speedLimitFor("nobody"); got != 0 {
		t.Fatalf("an unknown user must be unlimited, got %d", got)
	}
}
