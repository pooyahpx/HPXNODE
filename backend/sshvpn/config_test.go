package sshvpn

import "testing"

func TestNewConfigDefaults(t *testing.T) {
	cfg, err := NewConfig(`{"inbound_tag":"ssh-main"}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 2222 {
		t.Fatalf("port = %d, want 2222", cfg.Port)
	}
}

func TestNewConfigRequiresTag(t *testing.T) {
	if _, err := NewConfig(`{}`); err == nil {
		t.Fatal("expected error")
	}
}
