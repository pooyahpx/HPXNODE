package wireguard

import (
	"log"
	"time"

	"github.com/pooyahpx/HPXNODE/backend/ratelimit"
	"github.com/pooyahpx/HPXNODE/common"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// Distinct endpoint IPs seen within this window count as "simultaneous".
	// WireGuard peers roam (one endpoint at a time), so this is an approximation.
	wgIPWindow = 120 * time.Second
	// How long an over-limit peer stays removed before being re-admitted.
	wgIPLimitCooldown = 60 * time.Second
	// Consecutive over-limit polls required before disconnecting, so a device
	// briefly changing networks (two endpoints during the switch) isn't kicked.
	wgIPLimitStrikes = 2
)

// rememberLimits records each user's ip_limit (email-keyed). replace=true
// rebuilds the map from an authoritative full list.
func (wg *WireGuard) rememberLimits(users []*common.User, replace bool) {
	wg.limitMu.Lock()
	defer wg.limitMu.Unlock()
	if replace {
		next := make(map[string]uint32, len(users))
		nextSpeed := make(map[string]uint32, len(users))
		for _, u := range users {
			if e := u.GetEmail(); e != "" {
				next[e] = u.GetIpLimit()
				nextSpeed[e] = u.GetSpeedLimit()
			}
		}
		wg.userLimits = next
		wg.userSpeed = nextSpeed
		return
	}
	if wg.userLimits == nil {
		wg.userLimits = make(map[string]uint32)
	}
	if wg.userSpeed == nil {
		wg.userSpeed = make(map[string]uint32)
	}
	for _, u := range users {
		if e := u.GetEmail(); e != "" {
			wg.userLimits[e] = u.GetIpLimit()
			wg.userSpeed[e] = u.GetSpeedLimit()
			delete(wg.kicked, e) // an explicit (re)sync clears a pending kick
		}
	}
}

// ShapedClients lists this backend's peers that carry a speed limit, together
// with their tunnel addresses, for the node's traffic shaper. WireGuard peers
// have fixed tunnel addresses, so every configured peer with a limit is
// returned regardless of whether it is currently connected.
func (wg *WireGuard) ShapedClients() []ratelimit.Client {
	wg.limitMu.Lock()
	speed := make(map[string]uint32, len(wg.userSpeed))
	for e, s := range wg.userSpeed {
		speed[e] = s
	}
	wg.limitMu.Unlock()

	var clients []ratelimit.Client
	for _, peer := range wg.peerStore.GetAll() {
		limit := speed[peer.Email]
		if limit == 0 {
			continue
		}
		for _, ipnet := range peer.AllowedIPs {
			clients = append(clients, ratelimit.Client{
				User:      peer.Email,
				Address:   ipnet.IP.String(),
				LimitKbps: limit,
			})
		}
	}
	return clients
}

type wgLimitAction struct {
	kick    bool
	readmit bool
	limit   uint32
	ipCount int
}

// enforceIpLimits folds this poll's endpoints into a sliding window and, per
// user, disconnects peers whose distinct recent endpoint IPs exceed their device
// limit — re-admitting them after a cooldown. Kernel operations run outside
// limitMu (lock ordering: never hold limitMu while calling the manager).
func (wg *WireGuard) enforceIpLimits(mgr *Manager, activeIPs map[string]map[string]struct{}) {
	if mgr == nil {
		return
	}
	now := time.Now()

	wg.limitMu.Lock()
	// 1) fold this poll's endpoints into the window and prune stale entries.
	for email, ips := range activeIPs {
		w := wg.ipWindow[email]
		if w == nil {
			w = make(map[string]time.Time)
			wg.ipWindow[email] = w
		}
		for ip := range ips {
			w[ip] = now
		}
	}
	for email, w := range wg.ipWindow {
		for ip, seen := range w {
			if now.Sub(seen) > wgIPWindow {
				delete(w, ip)
			}
		}
		if len(w) == 0 {
			delete(wg.ipWindow, email)
		}
	}
	// 2) decide kicks / re-admits.
	actions := make(map[string]wgLimitAction)
	for email, limit := range wg.userLimits {
		if kickedAt, ok := wg.kicked[email]; ok {
			if now.Sub(kickedAt) >= wgIPLimitCooldown {
				actions[email] = wgLimitAction{readmit: true}
			}
			continue
		}
		if limit == 0 {
			continue
		}
		count := len(wg.ipWindow[email])
		if uint32(count) > limit {
			wg.overStrikes[email]++
			if wg.overStrikes[email] >= wgIPLimitStrikes {
				actions[email] = wgLimitAction{kick: true, limit: limit, ipCount: count}
			}
		} else {
			delete(wg.overStrikes, email)
		}
	}
	wg.limitMu.Unlock()

	// 3) apply kernel changes.
	for email, a := range actions {
		pi := wg.peerStore.GetByEmail(email)
		if pi == nil {
			continue
		}
		switch {
		case a.kick:
			if err := mgr.ApplyPeers([]wgtypes.PeerConfig{buildRemoveConfig(pi.PublicKey)}); err != nil {
				continue
			}
			wg.limitMu.Lock()
			wg.kicked[email] = now
			delete(wg.overStrikes, email)
			delete(wg.ipWindow, email)
			wg.limitMu.Unlock()
			log.Printf("wireguard: user %s over device limit (%d IPs > %d), disconnecting for %s",
				email, a.ipCount, a.limit, wgIPLimitCooldown)
			wg.emitWarningLogf("wireguard: user %s over device limit (%d IPs > %d), disconnected for %s",
				email, a.ipCount, a.limit, wgIPLimitCooldown)
		case a.readmit:
			psk, _ := wg.config.GetPreSharedKey()
			cfg, err := buildAddConfigFromPeerInfo(pi, psk)
			if err != nil {
				continue
			}
			if err := mgr.ApplyPeers([]wgtypes.PeerConfig{cfg}); err != nil {
				continue
			}
			wg.limitMu.Lock()
			delete(wg.kicked, email)
			delete(wg.ipWindow, email)
			delete(wg.overStrikes, email)
			wg.limitMu.Unlock()
			log.Printf("wireguard: re-admitted user %s after device-limit cooldown", email)
		}
	}
}
