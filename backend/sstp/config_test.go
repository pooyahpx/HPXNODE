package sstp

import "testing"

func TestNewConfigDefaults(t *testing.T) {
	cfg, err := NewConfig(`{"inbound_tag":"sstp-main"}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 443 {
		t.Fatalf("port = %d", cfg.Port)
	}
}

func TestNewConfigRequiresTag(t *testing.T) {
	if _, err := NewConfig(`{"port":443}`); err == nil {
		t.Fatal("expected error")
	}
}
