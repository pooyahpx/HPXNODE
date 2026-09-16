package openconnect

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Config struct {
	InboundTag string   `json:"inbound_tag"`
	Port       int      `json:"port"`
	Pool       string   `json:"pool"`
	ServerAddr string   `json:"server_addr"`
	DNS        []string `json:"dns"`

	workDir string
}

func NewConfig(configStr string) (*Config, error) {
	cfg := &Config{}
	if strings.TrimSpace(configStr) == "" {
		return nil, fmt.Errorf("openconnect config string must not be empty")
	}
	if err := json.Unmarshal([]byte(configStr), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse openconnect config: %w", err)
	}
	if cfg.InboundTag == "" {
		return nil, fmt.Errorf("inbound_tag is required")
	}
	if cfg.Pool == "" {
		return nil, fmt.Errorf("pool is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 443
	}
	if len(cfg.DNS) == 0 {
		cfg.DNS = []string{"1.1.1.1", "8.8.8.8"}
	}
	return cfg, nil
}
