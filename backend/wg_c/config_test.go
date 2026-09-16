package wg_c

import "testing"

func TestNewConfigSetsProxyField(t *testing.T) {
	cfg, err := NewConfig(`{"interface_name":"wgc0","private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","listen_port":51821,"address":["10.66.0.1/24"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProxyField != "wg_c" {
		t.Fatalf("ProxyField = %q", cfg.ProxyField)
	}
	if cfg.InterfaceName != "wgc0" {
		t.Fatalf("InterfaceName = %q", cfg.InterfaceName)
	}
}
