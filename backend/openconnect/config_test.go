package openconnect

import "testing"

func TestNewConfigDefaults(t *testing.T) {
	cfg, err := NewConfig(`{"inbound_tag":"oc-main","pool":"10.33.0.0/24"}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 443 {
		t.Fatalf("port = %d, want 443", cfg.Port)
	}
	if len(cfg.DNS) == 0 {
		t.Fatal("expected DNS defaults")
	}
}

func TestNewConfigRequires(t *testing.T) {
	if _, err := NewConfig(`{"pool":"10.33.0.0/24"}`); err == nil {
		t.Fatal("expected inbound_tag error")
	}
	if _, err := NewConfig(`{"inbound_tag":"oc"}`); err == nil {
		t.Fatal("expected pool error")
	}
}
