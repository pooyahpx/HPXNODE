package xray

import (
	"context"
	"log"
	"time"

	"github.com/pooyahpx/HPXNODE/common"
)

const (
	// How often to compare each user's online IP count against their limit.
	ipLimitCheckInterval = 20 * time.Second
	// How long an over-limit user stays disconnected before being re-admitted.
	ipLimitCooldown = 60 * time.Second
)

// rememberUsers records each user's ip_limit and the user object (needed to
// re-admit after a cooldown). replace=true rebuilds the maps from an
// authoritative full list (and clears kick state, since those paths restart
// xray); replace=false upserts the given users.
func (x *Xray) rememberUsers(users []*common.User, replace bool) {
	x.limitMu.Lock()
	defer x.limitMu.Unlock()
	if replace {
		x.userLimits = make(map[string]uint32, len(users))
		x.userByEmail = make(map[string]*common.User, len(users))
		x.kicked = make(map[string]time.Time)
	}
	for _, u := range users {
		email := u.GetEmail()
		if email == "" {
			continue
		}
		x.userLimits[email] = u.GetIpLimit()
		x.userByEmail[email] = u
		// An explicit (re)sync of a user clears any pending kick for them.
		delete(x.kicked, email)
	}
}

// enforceIpLimits periodically disconnects users whose distinct online source-IP
// count exceeds their device limit, and re-admits them once the cooldown passes.
func (x *Xray) enforceIpLimits(ctx context.Context) {
	ticker := time.NewTicker(ipLimitCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			x.enforceIpLimitsOnce(ctx)
		}
	}
}

func (x *Xray) enforceIpLimitsOnce(ctx context.Context) {
	// Snapshot the state so the checks below don't hold limitMu across gRPC calls.
	x.limitMu.Lock()
	limits := make(map[string]uint32, len(x.userLimits))
	for email, limit := range x.userLimits {
		limits[email] = limit
	}
	users := make(map[string]*common.User, len(x.userByEmail))
	for email, u := range x.userByEmail {
		users[email] = u
	}
	kicked := make(map[string]time.Time, len(x.kicked))
	for email, at := range x.kicked {
		kicked[email] = at
	}
	x.limitMu.Unlock()

	now := time.Now()
	for email, limit := range limits {
		// A disconnected user is re-admitted once their cooldown elapses; while
		// still cooling down their IP count is not re-checked.
		if kickedAt, ok := kicked[email]; ok {
			if now.Sub(kickedAt) < ipLimitCooldown {
				continue
			}
			if u := users[email]; u != nil {
				if err := x.SyncUser(ctx, u); err != nil {
					continue // keep the kick; try again next tick
				}
			}
			x.limitMu.Lock()
			delete(x.kicked, email)
			x.limitMu.Unlock()
			log.Printf("xray: re-admitted user %s after device-limit cooldown", email)
			continue
		}

		if limit == 0 {
			continue
		}
		resp, err := x.GetUserOnlineIpListStats(ctx, email)
		if err != nil || resp == nil {
			continue
		}
		if uint32(len(resp.GetIps())) <= limit {
			continue
		}
		x.disconnectUser(ctx, email)
		x.limitMu.Lock()
		x.kicked[email] = now
		x.limitMu.Unlock()
		log.Printf("xray: user %s over device limit (%d IPs > %d), disconnecting for %s",
			email, len(resp.GetIps()), limit, ipLimitCooldown)
	}
}

// disconnectUser removes a user from every (non-excluded) inbound, dropping all
// of their live connections. They are re-admitted by enforceIpLimitsOnce after
// the cooldown.
func (x *Xray) disconnectUser(ctx context.Context, email string) {
	for _, inbound := range x.config.InboundConfigs {
		if inbound.exclude {
			continue
		}
		_ = x.handler.RemoveInboundUser(ctx, inbound.Tag, email)
	}
}
