package wg_c

import (
	"github.com/pooyahpx/HPXNODE/backend/wireguard"
	"github.com/pooyahpx/HPXNODE/common"
	"github.com/pooyahpx/HPXNODE/config"
)

// CheckDeps reuses the wireguard dependency probe.
func CheckDeps() error { return wireguard.CheckDeps() }

// DetectVersion reuses the wireguard version probe.
func DetectVersion() string { return wireguard.DetectVersion() }

// NewConfig parses a wireguard-compatible core config for WG-C.
func NewConfig(configStr string) (*wireguard.Config, error) {
	cfg, err := wireguard.NewConfig(configStr)
	if err != nil {
		return nil, err
	}
	cfg.ProxyField = "wg_c"
	return cfg, nil
}

// New starts a wireguard backend that reads peers from Proxy.wg_c.
func New(cfg *config.Config, wgConfig *wireguard.Config, users []*common.User) (*wireguard.WireGuard, error) {
	if wgConfig != nil {
		wgConfig.ProxyField = "wg_c"
	}
	return wireguard.New(cfg, wgConfig, users)
}
