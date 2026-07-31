package backend

import "sort"

// DeviceLimiter is implemented by backends that can report and shed a user's
// online devices, so the controller can enforce a single ip_limit across every
// protocol running on the node — not just per protocol. Backends that do not
// implement it keep enforcing their own limit locally and are simply ignored by
// the cross-protocol pass.
type DeviceLimiter interface {
	// Protocol is a stable identifier used for cross-protocol priority
	// ("ikev2", "l2tp", ...).
	Protocol() string
	// OnlineDeviceCounts returns the current online device count per user, keyed
	// the same way across backends (users with zero devices may be omitted).
	OnlineDeviceCounts() map[string]int
	// UserLimit returns the user's ip_limit and whether this backend knows the
	// user at all. A limit of 0 means unlimited.
	UserLimit(user string) (uint32, bool)
	// KeepDevices disconnects a user's online devices down to keep, retaining the
	// longest-lived ones. keep <= 0 disconnects every device the user has on this
	// backend.
	KeepDevices(user string, keep int)
}

// deviceProtocolPriority ranks protocols when a user is over their global
// ip_limit: a lower value is kept first, so its devices survive and lower
// ranked protocols shed the excess. Unlisted protocols sort last.
var deviceProtocolPriority = map[string]int{
	"xray":      0,
	"wireguard": 1,
	"openvpn":   2,
	"ikev2":     3,
	"l2tp":      4,
}

func deviceProtoRank(p string) int {
	if r, ok := deviceProtocolPriority[p]; ok {
		return r
	}
	return 1 << 30
}

// EnforceGlobalDeviceLimits shares one ip_limit across every protocol on the
// node. For each user whose total online devices exceed their limit, it keeps
// the highest-priority protocols' devices (up to the limit) and disconnects the
// excess from the lowest-priority ones. It is a no-op when fewer than two
// limiter-capable backends are present, since a lone backend already enforces
// its own limit.
func EnforceGlobalDeviceLimits(limiters []DeviceLimiter) {
	if len(limiters) < 2 {
		return
	}

	order := make([]DeviceLimiter, len(limiters))
	copy(order, limiters)
	sort.SliceStable(order, func(i, j int) bool {
		return deviceProtoRank(order[i].Protocol()) < deviceProtoRank(order[j].Protocol())
	})

	counts := make([]map[string]int, len(order))
	users := map[string]struct{}{}
	for i, l := range order {
		c := l.OnlineDeviceCounts()
		counts[i] = c
		for u, n := range c {
			if n > 0 {
				users[u] = struct{}{}
			}
		}
	}

	for user := range users {
		limit, known := uint32(0), false
		for _, l := range order {
			if lim, ok := l.UserLimit(user); ok {
				limit, known = lim, true
				break
			}
		}
		if !known || limit == 0 {
			continue // unknown user or unlimited
		}

		total := 0
		for i := range order {
			total += counts[i][user]
		}
		if uint32(total) <= limit {
			continue
		}

		// Hand out the budget by priority; shed whatever a lower-priority backend
		// cannot fit.
		remaining := int(limit)
		for i, l := range order {
			c := counts[i][user]
			if c == 0 {
				continue
			}
			keep := c
			if keep > remaining {
				keep = remaining
			}
			if keep < c {
				l.KeepDevices(user, keep)
			}
			remaining -= keep
		}
	}
}
