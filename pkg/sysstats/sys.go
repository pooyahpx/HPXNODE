package sysstats

import (
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/pooyahpx/HPXNODE/common"
)

// Non-blocking sampling: cpu.Percent(0) and net counter deltas reuse the
// previous observation instead of sleeping 1s+1s on every call (which made
// idle nodes look pegged at high CPU).
var (
	sampleMu     sync.Mutex
	prevNet      map[string]net.IOCountersStat
	prevNetAt    time.Time
	cpuPrimed    bool
)

func GetSystemStats() (*common.SystemStatsResponse, error) {
	stats := &common.SystemStatsResponse{}

	vm, err := mem.VirtualMemory()
	if err != nil {
		return stats, err
	}
	stats.MemTotal = vm.Total
	stats.MemUsed = vm.Used

	cores, err := cpu.Counts(true)
	if err != nil {
		return stats, err
	}
	stats.CpuCores = uint64(cores)

	sampleMu.Lock()
	defer sampleMu.Unlock()

	if !cpuPrimed {
		// Prime the counter so the next Percent(0) is a real delta (no long block).
		_, _ = cpu.Percent(0, false)
		cpuPrimed = true
	}
	percentages, err := cpu.Percent(0, false)
	if err != nil {
		return stats, err
	}
	if len(percentages) > 0 {
		stats.CpuUsage = percentages[0]
	}

	incomingSpeed, outgoingSpeed, err := getBandwidthSpeedLocked()
	if err != nil {
		return stats, err
	}
	stats.IncomingBandwidthSpeed = incomingSpeed
	stats.OutgoingBandwidthSpeed = outgoingSpeed

	return stats, nil
}

// getBandwidthSpeedLocked returns aggregate rx/tx bytes per second using the
// delta since the previous sample. Caller must hold sampleMu.
func getBandwidthSpeedLocked() (uint64, uint64, error) {
	current, err := net.IOCounters(true)
	if err != nil {
		return 0, 0, err
	}
	now := time.Now()

	curMap := make(map[string]net.IOCountersStat, len(current))
	for _, c := range current {
		if c.Name == "lo" {
			continue
		}
		curMap[c.Name] = c
	}

	if prevNet == nil || prevNetAt.IsZero() {
		prevNet = curMap
		prevNetAt = now
		return 0, 0, nil
	}

	elapsed := now.Sub(prevNetAt).Seconds()
	if elapsed < 0.2 {
		// Too soon — keep previous baseline, report 0 rather than huge spikes.
		return 0, 0, nil
	}

	var totalRxBytes, totalTxBytes uint64
	for name, c := range curMap {
		if p, ok := prevNet[name]; ok {
			if c.BytesRecv >= p.BytesRecv {
				totalRxBytes += c.BytesRecv - p.BytesRecv
			}
			if c.BytesSent >= p.BytesSent {
				totalTxBytes += c.BytesSent - p.BytesSent
			}
		}
	}

	prevNet = curMap
	prevNetAt = now

	return uint64(float64(totalRxBytes) / elapsed), uint64(float64(totalTxBytes) / elapsed), nil
}
