package amneziawg

import "testing"

func TestNewConfigProxyField(t *testing.T) {
	cfg, err := NewConfig(`{"interface_name":"awg0","private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","listen_port":51822,"address":["10.67.0.1/24"],"jc":4,"jmin":10,"jmax":50}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProxyField != "amneziawg" {
		t.Fatalf("ProxyField = %q", cfg.ProxyField)
	}
	if cfg.JC != 4 || cfg.JMin != 10 {
		t.Fatalf("jc/jmin = %d/%d", cfg.JC, cfg.JMin)
	}
}
