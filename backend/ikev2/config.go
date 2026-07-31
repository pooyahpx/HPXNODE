package ikev2

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Config is the IKEv2 backend configuration decoded from Backend.config (an
// opaque JSON string produced by the panel's IKEv2Config.to_str()).
type Config struct {
	InboundTag      string   `json:"inbound_tag"`
	ServerAddr      string   `json:"server_addr"`
	Identity        string   `json:"identity"`
	Pool            string   `json:"pool"`
	EgressInterface string   `json:"egress_interface"`
	DNS             []string `json:"dns"`
	IKEProposals    []string `json:"ike_proposals"`
	ESPProposals    []string `json:"esp_proposals"`
	CACert          string   `json:"ca_cert"`
	ServerCert      string   `json:"server_cert"`
	ServerKey       string   `json:"server_key"`

	workDir string
}

// NewConfig parses the config string and applies defaults.
func NewConfig(configStr string) (*Config, error) {
	cfg := &Config{}
	if strings.TrimSpace(configStr) == "" {
		return nil, fmt.Errorf("ikev2 config string must not be empty")
	}
	if err := json.Unmarshal([]byte(configStr), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse ikev2 config: %w", err)
	}

	if cfg.InboundTag == "" {
		return nil, fmt.Errorf("inbound_tag is required")
	}
	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("server_addr is required")
	}
	if cfg.Identity == "" {
		cfg.Identity = cfg.ServerAddr
	}
	if cfg.Pool == "" {
		return nil, fmt.Errorf("pool is required")
	}
	if len(cfg.DNS) == 0 {
		cfg.DNS = []string{"1.1.1.1", "8.8.8.8"}
	}
	if len(cfg.IKEProposals) == 0 {
		cfg.IKEProposals = []string{"aes256-sha256-modp2048", "aes128-sha256-modp2048"}
	}
	if len(cfg.ESPProposals) == 0 {
		cfg.ESPProposals = []string{"aes256-sha256", "aes128-sha256"}
	}
	if cfg.CACert == "" || cfg.ServerCert == "" || cfg.ServerKey == "" {
		return nil, fmt.Errorf("ca_cert, server_cert and server_key are required")
	}

	return cfg, nil
}
