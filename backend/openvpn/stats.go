package openvpn

import (
	"context"
	"errors"
	"runtime"
	"time"

	"github.com/pooyahpx/HPXNODE/common"
	"github.com/pooyahpx/HPXNODE/pkg/stats"
)

// statsLoop polls the management interface and feeds per-user byte deltas into
// the shared stats tracker (same delta/reset engine the wireguard backend uses).
func (o *OpenVPN) statsLoop(ctx context.Context) {
	ticker := time.NewTicker(o.updateInterval)
	defer ticker.Stop()

	cleanup := time.NewTicker(5 * time.Minute)
	defer cleanup.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.collectStats()
		case <-cleanup.C:
			o.statsTracker.CleanupDeletedEntries()
		}
	}
}

// collectStats reads `status 3` and accumulates per-CN cumulative counters.
//
// OpenVPN reports per-session (per ClientID) cumulative byte counts. A user (CN)
// may have several concurrent sessions (duplicate-cn) and reconnects create new
// ClientIDs. We accumulate each session's growth into a per-CN cumulative total
// and hand that to the tracker, which computes the reset-delta for the panel.
func (o *OpenVPN) collectStats() {
	if o.mgmt == nil {
		return
	}
	rows := o.mgmt.requestStatus(5 * time.Second)

	// Sum growth per CN across all live sessions since the last poll.
	perCN := make(map[string]*clientStatus)
	seenSessions := make(map[string]struct{})

	o.mu.Lock()
	for _, row := range rows {
		seenSessions[row.ClientID] = struct{}{}
		prev, ok := o.sessionSeen[row.ClientID]
		var dRx, dTx int64
		if ok {
			dRx = row.BytesReceived - prev.BytesReceived
			dTx = row.BytesSent - prev.BytesSent
			if dRx < 0 {
				dRx = row.BytesReceived
			}
			if dTx < 0 {
				dTx = row.BytesSent
			}
		} else {
			dRx = row.BytesReceived
			dTx = row.BytesSent
		}
		o.sessionSeen[row.ClientID] = row

		agg := perCN[row.CommonName]
		if agg == nil {
			agg = &clientStatus{CommonName: row.CommonName, RealAddress: row.RealAddress}
			perCN[row.CommonName] = agg
		}
		agg.BytesReceived += dRx
		agg.BytesSent += dTx
		if row.RealAddress != "" {
			agg.RealAddress = row.RealAddress
		}
	}
	// Drop sessions that disappeared between polls.
	for cid := range o.sessionSeen {
		if _, ok := seenSessions[cid]; !ok {
			delete(o.sessionSeen, cid)
		}
	}
	// Fold per-poll growth into a per-CN cumulative counter for the tracker.
	if o.cnCumulative == nil {
		o.cnCumulative = make(map[string]*clientStatus)
	}
	var samples []stats.Sample
	for cn, growth := range perCN {
		cum := o.cnCumulative[cn]
		if cum == nil {
			cum = &clientStatus{CommonName: cn}
			o.cnCumulative[cn] = cum
		}
		cum.BytesReceived += growth.BytesReceived
		cum.BytesSent += growth.BytesSent
		samples = append(samples, stats.Sample{
			PublicKey:  cn, // tracker key = common name = user id
			Email:      cn,
			Rx:         cum.BytesReceived,
			Tx:         cum.BytesSent,
			EndpointIP: extractIP(growth.RealAddress),
		})
		// Node-level running totals (separate from the per-user tracker).
		o.totalRx += growth.BytesReceived
		o.totalTx += growth.BytesSent
	}
	o.mu.Unlock()

	if len(samples) > 0 {
		o.statsTracker.UpdateStatsBatch(samples)
	}
}

func extractIP(realAddress string) string {
	// RealAddress is "ip:port"; strip the port. IPv6 is bracketed.
	if realAddress == "" {
		return ""
	}
	if realAddress[0] == '[' {
		if end := indexByte(realAddress, ']'); end > 0 {
			return realAddress[1:end]
		}
		return realAddress
	}
	if idx := lastIndexByte(realAddress, ':'); idx > 0 {
		return realAddress[:idx]
	}
	return realAddress
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func (o *OpenVPN) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
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
		// Node-level traffic = sum of all user traffic, tracked separately so this
		// poll does not drain the per-user deltas consumed by UsersStat.
		o.mu.Lock()
		totalRx, totalTx := o.totalRx, o.totalTx
		o.mu.Unlock()
		dRx, dTx := o.interfaceStats.Delta(totalRx, totalTx, request.GetReset_())
		return &common.StatResponse{
			Stats: stats.BuildInterfaceStats(o.config.InboundTag, "outbound", dRx, dTx),
		}, nil
	default:
		return nil, errors.New("unsupported stat type for openvpn")
	}
}

func (o *OpenVPN) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
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

func (o *OpenVPN) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	if state != lifecycleRunning {
		return nil, errNotStarted
	}
	response := &common.StatsOnlineIpListResponse{Name: email, Ips: make(map[string]int64)}
	for ip, ts := range o.statsTracker.EndpointActivity([]string{email}) {
		response.Ips[ip] = ts
	}
	return response, nil
}

func (o *OpenVPN) GetOutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
}

func (o *OpenVPN) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	if state != lifecycleRunning {
		return nil, errNotStarted
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return &common.BackendStatsResponse{
		NumGoroutine: uint32(runtime.NumGoroutine()),
		NumGc:        memStats.NumGC,
		Alloc:        memStats.Alloc,
		TotalAlloc:   memStats.TotalAlloc,
		Sys:          memStats.Sys,
		Mallocs:      memStats.Mallocs,
		Frees:        memStats.Frees,
		LiveObjects:  memStats.Mallocs - memStats.Frees,
		PauseTotalNs: memStats.PauseTotalNs,
		Uptime:       uint32(time.Since(o.startTime).Seconds()),
	}, nil
}
