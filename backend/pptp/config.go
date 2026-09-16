package pptp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Config is the PPTP backend configuration decoded from Backend.config.
type Config struct {
	InboundTag      string   `json:"inbound_tag"`
	Port            int      `json:"port"`
	Pool            string   `json:"pool"`
	LocalIP         string   `json:"local_ip"`
	ServerAddr      string   `json:"server_addr"`
	EgressInterface string   `json:"egress_interface"`
	DNS             []string `json:"dns"`

	workDir string
}

// NewConfig parses the config string and applies defaults.
func NewConfig(configStr string) (*Config, error) {
	cfg := &Config{}
	if strings.TrimSpace(configStr) == "" {
		return nil, fmt.Errorf("pptp config string must not be empty")
	}
	if err := json.Unmarshal([]byte(configStr), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse pptp config: %w", err)
	}
	if cfg.InboundTag == "" {
		return nil, fmt.Errorf("inbound_tag is required")
	}
	if cfg.Pool == "" {
		return nil, fmt.Errorf("pool is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 1723
	}
	if cfg.LocalIP == "" {
		cfg.LocalIP = firstHost(cfg.Pool)
	}
	if len(cfg.DNS) == 0 {
		cfg.DNS = []string{"1.1.1.1", "8.8.8.8"}
	}
	return cfg, nil
}

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
