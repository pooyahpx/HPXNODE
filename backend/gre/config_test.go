package gre

import "testing"

func TestNewConfig(t *testing.T) {
	cfg, err := NewConfig(`{"inbound_tag":"gre1","local":"1.2.3.4","peer":"5.6.7.8"}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Peer != "5.6.7.8" {
		t.Fatal(cfg.Peer)
	}
}

func TestNewConfigRemoteAlias(t *testing.T) {
	cfg, err := NewConfig(`{"inbound_tag":"gre1","local":"1.2.3.4","remote":"5.6.7.8"}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Peer != "5.6.7.8" {
		t.Fatalf("peer = %q", cfg.Peer)
	}
}

func TestNewConfigRequires(t *testing.T) {
	if _, err := NewConfig(`{"inbound_tag":"g"}`); err == nil {
		t.Fatal("expected error")
	}
}
