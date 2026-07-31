package l2tp

import "sort"

// This file implements backend.DeviceLimiter so the controller can enforce a
// user's ip_limit across every protocol on the node, not just within L2TP.

// Protocol identifies this backend for cross-protocol priority.
func (o *L2TP) Protocol() string { return "l2tp" }

// OnlineDeviceCounts reports the number of live sessions (each a connected
// device) per user, read from the poll snapshot.
func (o *L2TP) OnlineDeviceCounts() map[string]int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make(map[string]int, len(o.onlineIPs))
	for user, ips := range o.onlineIPs {
		if n := len(ips); n > 0 {
			out[user] = n
		}
	}
	return out
}

// UserLimit returns the user's ip_limit and whether L2TP serves them.
func (o *L2TP) UserLimit(user string) (uint32, bool) {
	return o.users.limitKnown(user)
}

// KeepDevices disconnects a user's newest PPP sessions until keep remain. The
// oldest sessions are kept, matching the per-poll enforcement so the same
// devices stay connected across passes.
func (o *L2TP) KeepDevices(user string, keep int) {
	if keep < 0 {
		keep = 0
	}
	var list []l2tpSession
	for _, s := range readSessions() {
		if s.user == user {
			list = append(list, s)
		}
	}
	if len(list) <= keep {
		return
	}
	sort.Slice(list, func(i, j int) bool { return list[i].started < list[j].started })
	for _, s := range list[keep:] {
		if s.pid > 0 && terminateSession(s.pid) {
			o.emitLogf("Info", "l2tp: user %s over global device limit, disconnecting %s", user, s.ifname)
		}
	}
}
