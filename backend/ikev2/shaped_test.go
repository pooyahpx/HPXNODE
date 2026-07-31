package ikev2

import "testing"

func TestSpeedLimitForUnknownUserIsZero(t *testing.T) {
	s := newUserStore("ikev2-main")
	if got := s.speedLimitFor("nobody"); got != 0 {
		t.Fatalf("an unknown user must be unlimited, got %d", got)
	}
}

func TestSpeedLimitForKnownUser(t *testing.T) {
	s := newUserStore("ikev2-main")
	s.users["alice"] = userEntry{password: "p", speedLimit: 8000}
	if got := s.speedLimitFor("alice"); got != 8000 {
		t.Fatalf("speedLimitFor = %d, want 8000", got)
	}
}
