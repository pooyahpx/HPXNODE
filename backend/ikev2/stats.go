package ikev2

import (
	"context"
	"errors"
	"runtime"
	"sort"
	"time"

	"github.com/pooyahpx/HPXNODE/common"
	"github.com/pooyahpx/HPXNODE/pkg/stats"
)

func (o *IKEv2) pollLoop(ctx context.Context) {
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

func (o *IKEv2) poll() {
	sas, err := o.vici.listSAs()
	if err != nil {
		return
	}

	// Count SAs per identity (device-limit) and remember which ike ids to keep.
	perIdentitySAs := make(map[string][]saInfo)
	present := make(map[uint32]struct{})
	for _, sa := range sas {
		present[sa.IKEID] = struct{}{}
		perIdentitySAs[sa.Identity] = append(perIdentitySAs[sa.Identity], sa)
	}

	var samples []stats.Sample

	o.mu.Lock()
	// Accumulate byte deltas per identity across SA churn.
	growthRx := make(map[string]int64)
	growthTx := make(map[string]int64)
	for _, sa := range sas {
		last := o.saSeen[sa.IKEID]
		dRx := sa.BytesIn - last[0]
		dTx := sa.BytesOut - last[1]
		if dRx < 0 {
			dRx = sa.BytesIn
		}
		if dTx < 0 {
			dTx = sa.BytesOut
		}
		o.saSeen[sa.IKEID] = [2]int64{sa.BytesIn, sa.BytesOut}
		growthRx[sa.Identity] += dRx
		growthTx[sa.Identity] += dTx
	}
	// Drop SAs that are gone (their final bytes were already counted).
	for id := range o.saSeen {
		if _, ok := present[id]; !ok {
			delete(o.saSeen, id)
		}
	}
	now := time.Now().Unix()
	onlineIPs := make(map[string]map[string]int64, len(perIdentitySAs))
	for identity, saList := range perIdentitySAs {
		o.cumRx[identity] += growthRx[identity]
		o.cumTx[identity] += growthTx[identity]
		o.totalRx += growthRx[identity]
		o.totalTx += growthTx[identity]
		endpoint := ""
		if len(saList) > 0 {
			endpoint = saList[0].Remote
		}
		// Snapshot every distinct client IP this identity currently holds an SA
		// from (a user can be online from several devices/IPs at once).
		ips := make(map[string]int64, len(saList))
		for _, sa := range saList {
			if sa.Remote != "" {
				ips[sa.Remote] = now
			}
		}
		onlineIPs[identity] = ips
		samples = append(samples, stats.Sample{
			PublicKey:  identity,
			Email:      identity,
			Rx:         o.cumRx[identity],
			Tx:         o.cumTx[identity],
			EndpointIP: endpoint,
		})
	}
	o.onlineIPs = onlineIPs
	o.mu.Unlock()

	if len(samples) > 0 {
		o.statsTracker.UpdateStatsBatch(samples)
	}

	o.enforceDeviceLimits(perIdentitySAs)
}

// enforceDeviceLimits terminates the SAs of the client IPs that exceed a user's
// device limit. The limit counts distinct simultaneous client IPs (not raw SA
// count), so rekeys/duplicate SAs from one device never trip it. Eviction is
// stable (lowest IPs kept) so the same devices stay connected across polls.
func (o *IKEv2) enforceDeviceLimits(perIdentity map[string][]saInfo) {
	for identity, saList := range perIdentity {
		limit := o.users.limitFor(identity)
		if limit == 0 {
			continue
		}
		byIP := make(map[string][]saInfo)
		for _, sa := range saList {
			byIP[sa.Remote] = append(byIP[sa.Remote], sa)
		}
		if uint32(len(byIP)) <= limit {
			continue
		}
		ips := make([]string, 0, len(byIP))
		for ip := range byIP {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		for _, ip := range ips[limit:] {
			for _, sa := range byIP[ip] {
				if err := o.vici.terminateIKE(sa.IKEID); err == nil {
					o.emitLogf("Info", "ikev2: user %s over device limit (%d IPs > %d), terminating SA %d from %s",
						identity, len(byIP), limit, sa.IKEID, ip)
				}
			}
		}
	}
}

func (o *IKEv2) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
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
		return nil, errors.New("unsupported stat type for ikev2")
	}
}

func (o *IKEv2) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
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

func (o *IKEv2) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
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

func (o *IKEv2) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
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
