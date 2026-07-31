package l2tp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Config is the L2TP/IPsec backend configuration decoded from Backend.config
// (an opaque JSON string produced by the panel's L2TPConfig.to_str()).
//
// L2TP/IPsec is a two-layer stack: strongSwan (the shared charon daemon) brings
// up an IPsec transport-mode SA authenticated with a shared PSK, and xl2tpd +
// pppd run the L2TP tunnel inside it with per-user CHAP credentials. So unlike
// IKEv2 there is no server certificate — just the PSK and the PPP users.
type Config struct {
	InboundTag      string   `json:"inbound_tag"`
	ServerAddr      string   `json:"server_addr"`
	PSK             string   `json:"psk"`
	Pool            string   `json:"pool"`
	LocalIP         string   `json:"local_ip"`
	EgressInterface string   `json:"egress_interface"`
	DNS             []string `json:"dns"`
	IKEProposals    []string `json:"ike_proposals"`
	ESPProposals    []string `json:"esp_proposals"`

	workDir string
}

// NewConfig parses the config string and applies defaults.
func NewConfig(configStr string) (*Config, error) {
	cfg := &Config{}
	if strings.TrimSpace(configStr) == "" {
		return nil, fmt.Errorf("l2tp config string must not be empty")
	}
	if err := json.Unmarshal([]byte(configStr), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse l2tp config: %w", err)
	}

	if cfg.InboundTag == "" {
		return nil, fmt.Errorf("inbound_tag is required")
	}
	if cfg.PSK == "" {
		return nil, fmt.Errorf("psk is required")
	}
	if cfg.Pool == "" {
		return nil, fmt.Errorf("pool is required")
	}
	if cfg.LocalIP == "" {
		// The server's address inside the tunnel — first host of the pool by
		// default (xl2tpd assigns the rest of the range to clients).
		cfg.LocalIP = firstHost(cfg.Pool)
	}
	if len(cfg.DNS) == 0 {
		cfg.DNS = []string{"1.1.1.1", "8.8.8.8"}
	}
	// L2TP/IPsec clients (Windows, older Android) negotiate IKEv1, so the
	// proposals here feed the IKEv1 transport connection charon loads.
	if len(cfg.IKEProposals) == 0 {
		cfg.IKEProposals = []string{"aes256-sha1-modp2048", "aes128-sha1-modp1024", "3des-sha1-modp1024"}
	}
	if len(cfg.ESPProposals) == 0 {
		cfg.ESPProposals = []string{"aes256-sha1", "aes128-sha1", "3des-sha1"}
	}

	return cfg, nil
}

// firstHost returns the first usable host address of a CIDR (e.g. 10.31.0.0/24
// -> 10.31.0.1). It is deliberately simple; the panel validates the pool.
func firstHost(pool string) string {
	cidr := strings.TrimSpace(pool)
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		cidr = cidr[:i]
	}
	parts := strings.Split(cidr, ".")
	if len(parts) != 4 {
		return cidr
	}
	parts[3] = "1"
	return strings.Join(parts, ".")
}
