package l2tp

import (
	"context"
	"errors"
	"runtime"
	"sort"
	"time"

	"github.com/pooyahpx/HPXNODE/common"
	"github.com/pooyahpx/HPXNODE/pkg/stats"
)

func (o *L2TP) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(o.updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.poll()
		}
	}
}

// poll attributes each live PPP session's interface counters to its user,
// accumulates traffic across session churn, refreshes the online snapshot and
// enforces the per-user device limit. Sessions come from the pppd ip-up hook
// (interface -> username); byte counters from the interface statistics.
func (o *L2TP) poll() {
	sessions := readSessions()
	perUser := make(map[string][]l2tpSession)
	present := make(map[string]struct{})
	for _, s := range sessions {
		perUser[s.user] = append(perUser[s.user], s)
		present[s.ifname] = struct{}{}
	}

	var samples []stats.Sample

	o.mu.Lock()
	growthRx := make(map[string]int64)
	growthTx := make(map[string]int64)
	for _, s := range sessions {
		rx, tx := ifaceBytes(s.ifname)
		last := o.ifSeen[s.ifname]
		dRx, dTx := rx-last[0], tx-last[1]
		if dRx < 0 {
			dRx = rx
		}
		if dTx < 0 {
			dTx = tx
		}
		o.ifSeen[s.ifname] = [2]int64{rx, tx}
		growthRx[s.user] += dRx
		growthTx[s.user] += dTx
	}
	// Forget interfaces whose session has ended (their final bytes are counted).
	for ifn := range o.ifSeen {
		if _, ok := present[ifn]; !ok {
			delete(o.ifSeen, ifn)
		}
	}
	now := time.Now().Unix()
	onlineIPs := make(map[string]map[string]int64, len(perUser))
	for user, list := range perUser {
		o.cumRx[user] += growthRx[user]
		o.cumTx[user] += growthTx[user]
		o.totalRx += growthRx[user]
		o.totalTx += growthTx[user]
		ips := make(map[string]int64, len(list))
		endpoint := ""
		for _, s := range list {
			ip := s.clientIP
			if ip == "" {
				ip = s.tunnelIP
			}
			if ip != "" {
				ips[ip] = now
				if endpoint == "" {
					endpoint = ip
				}
			}
		}
		onlineIPs[user] = ips
		samples = append(samples, stats.Sample{
			PublicKey:  user,
			Email:      user,
			Rx:         o.cumRx[user],
			Tx:         o.cumTx[user],
			EndpointIP: endpoint,
		})
	}
	o.onlineIPs = onlineIPs
	o.mu.Unlock()

	if len(samples) > 0 {
		o.statsTracker.UpdateStatsBatch(samples)
	}
	o.enforceDeviceLimits(perUser)
}

// enforceDeviceLimits disconnects the excess sessions of any user running more
// simultaneous devices than their ip_limit. The oldest sessions are kept so the
// same devices stay connected across polls.
func (o *L2TP) enforceDeviceLimits(perUser map[string][]l2tpSession) {
	for user, list := range perUser {
		limit := o.users.limitFor(user)
		if limit == 0 || uint32(len(list)) <= limit {
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i].started < list[j].started })
		for _, s := range list[limit:] {
			if s.pid > 0 && terminateSession(s.pid) {
				o.emitLogf("Info", "l2tp: user %s over device limit (%d > %d), disconnecting %s",
					user, len(list), limit, s.ifname)
			}
		}
	}
}

func (o *L2TP) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	if state != lifecycleRunning {
		return nil, errNotStarted
	}
	switch request.GetType() {
	case common.StatType_UserStat:
		return o.statsTracker.GetStats(ctx, []string{request.GetName()}, request.GetReset_()), nil
	case common.StatType_UsersStat:
		return o.statsTracker.GetUsersStats(ctx, request.GetReset_()), nil
	case common.StatType_Outbound, common.StatType_Outbounds:
		o.mu.Lock()
		totalRx, totalTx := o.totalRx, o.totalTx
		o.mu.Unlock()
		dRx, dTx := o.interfaceStats.Delta(totalRx, totalTx, request.GetReset_())
		return &common.StatResponse{
			Stats: stats.BuildInterfaceStats(o.config.InboundTag, "outbound", dRx, dTx),
		}, nil
	default:
		return nil, errors.New("unsupported stat type for l2tp")
	}
}

func (o *L2TP) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	if state != lifecycleRunning {
		return nil, errNotStarted
	}
	value := int64(0)
	if o.statsTracker.AnyActiveSince([]string{email}, time.Now().Add(-onlineActivityThreshold)) {
		value = 1
	}
	return &common.OnlineStatResponse{Name: email, Value: value}, nil
}

func (o *L2TP) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	if state != lifecycleRunning {
		return nil, errNotStarted
	}
	response := &common.StatsOnlineIpListResponse{Name: email, Ips: make(map[string]int64)}
	o.mu.RLock()
	for ip, ts := range o.onlineIPs[email] {
		response.Ips[ip] = ts
	}
	o.mu.RUnlock()
	return response, nil
}

func (o *L2TP) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	if state != lifecycleRunning {
		return nil, errNotStarted
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &common.BackendStatsResponse{
		NumGoroutine: uint32(runtime.NumGoroutine()),
		NumGc:        m.NumGC,
		Alloc:        m.Alloc,
		TotalAlloc:   m.TotalAlloc,
		Sys:          m.Sys,
		Mallocs:      m.Mallocs,
		Frees:        m.Frees,
		LiveObjects:  m.Mallocs - m.Frees,
		PauseTotalNs: m.PauseTotalNs,
		Uptime:       uint32(time.Since(o.startTime).Seconds()),
	}, nil
}
