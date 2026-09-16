package pptp

import "testing"

func TestNewConfigDefaults(t *testing.T) {
	cfg, err := NewConfig(`{"inbound_tag":"pptp-main","pool":"10.32.0.0/24"}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 1723 {
		t.Fatalf("port default = %d, want 1723", cfg.Port)
	}
	if cfg.LocalIP != "10.32.0.1" {
		t.Fatalf("local ip default = %q, want 10.32.0.1", cfg.LocalIP)
	}
	if len(cfg.DNS) == 0 {
		t.Fatal("expected DNS defaults")
	}
}

func TestNewConfigRequiresTagAndPool(t *testing.T) {
	if _, err := NewConfig(`{"pool":"10.32.0.0/24"}`); err == nil {
		t.Fatal("expected error when inbound_tag is missing")
	}
	if _, err := NewConfig(`{"inbound_tag":"pptp-main"}`); err == nil {
		t.Fatal("expected error when pool is missing")
	}
}
