package l2tp

import "testing"

func TestNewConfigDefaults(t *testing.T) {
	cfg, err := NewConfig(`{"inbound_tag":"l2tp-main","psk":"s3cr3t","pool":"10.31.0.0/24"}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LocalIP != "10.31.0.1" {
		t.Fatalf("local ip default = %q, want 10.31.0.1", cfg.LocalIP)
	}
	if len(cfg.DNS) == 0 || len(cfg.IKEProposals) == 0 || len(cfg.ESPProposals) == 0 {
		t.Fatal("expected DNS/IKE/ESP proposal defaults to be filled")
	}
}

func TestNewConfigRequiresPSKAndPool(t *testing.T) {
	if _, err := NewConfig(`{"inbound_tag":"l2tp-main","pool":"10.31.0.0/24"}`); err == nil {
		t.Fatal("expected error when psk is missing")
	}
	if _, err := NewConfig(`{"inbound_tag":"l2tp-main","psk":"x"}`); err == nil {
		t.Fatal("expected error when pool is missing")
	}
}

func TestPoolRange(t *testing.T) {
	start, end := poolRange("10.31.0.0/24", "10.31.0.1")
	if start != "10.31.0.2" || end != "10.31.0.254" {
		t.Fatalf("poolRange = %s-%s, want 10.31.0.2-10.31.0.254", start, end)
	}
}
