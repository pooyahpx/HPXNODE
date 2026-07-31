package openvpn

import (
	"fmt"

	"github.com/pooyahpx/HPXNODE/backend"
	"github.com/pooyahpx/HPXNODE/common"
	"github.com/pooyahpx/HPXNODE/config"
)

// NewBackend starts every listener declared by one core config and returns a
// single Backend over them. With one listener (the default, and every config
// written before multi-listener support) this is just New; with more it starts
// one OpenVPN server per endpoint — UDP and TCP from the same core — and hides
// them behind a composite so the controller keeps dealing with one backend.
//
// If any listener fails to start, the ones already up are shut down again so a
// partially-running core never lingers.
func NewBackend(cfg *config.Config, ovConfig *Config, users []*common.User) (backend.Backend, error) {
	if ovConfig == nil {
		return nil, fmt.Errorf("openvpn config must not be nil")
	}

	total := len(ovConfig.Listeners)
	if total <= 1 {
		return New(cfg, ovConfig, users)
	}

	started := make([]backend.Backend, 0, total)
	for i, l := range ovConfig.Listeners {
		derived, err := ovConfig.derive(cfg.GeneratedConfigPath, l, i, total)
		if err != nil {
			shutdownAll(started)
			return nil, err
		}
		instance, err := New(cfg, derived, users)
		if err != nil {
			shutdownAll(started)
			return nil, fmt.Errorf("start openvpn listener %s/%d: %w", l.Proto, l.Port, err)
		}
		started = append(started, instance)
	}

	return backend.NewComposite(started), nil
}

func shutdownAll(list []backend.Backend) {
	for _, b := range list {
		b.Shutdown()
	}
}
