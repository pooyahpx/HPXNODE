package ikev2

import "sort"

// This file implements backend.DeviceLimiter so the controller can enforce a
// user's ip_limit across every protocol on the node, not just within IKEv2.

// Protocol identifies this backend for cross-protocol priority.
func (o *IKEv2) Protocol() string { return "ikev2" }

// OnlineDeviceCounts reports the number of distinct client IPs each user is
// currently online from (one IP = one device), read from the poll snapshot.
func (o *IKEv2) OnlineDeviceCounts() map[string]int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make(map[string]int, len(o.onlineIPs))
	for identity, ips := range o.onlineIPs {
		if n := len(ips); n > 0 {
			out[identity] = n
		}
	}
	return out
}

// UserLimit returns the user's ip_limit and whether IKEv2 serves them.
func (o *IKEv2) UserLimit(user string) (uint32, bool) {
	return o.users.limitKnown(user)
}

// KeepDevices terminates the IKE SAs of a user's excess client IPs until only
// keep distinct IPs remain. Eviction is stable (lowest-sorted IPs kept) so it
// agrees with the per-poll enforcement and the same devices stay connected.
func (o *IKEv2) KeepDevices(user string, keep int) {
	if keep < 0 {
		keep = 0
	}
	sas, err := o.vici.listSAs()
	if err != nil {
		return
	}
	byIP := make(map[string][]saInfo)
	for _, sa := range sas {
		if sa.Identity != user {
			continue
		}
		byIP[sa.Remote] = append(byIP[sa.Remote], sa)
	}
	if len(byIP) <= keep {
		return
	}
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips[keep:] {
		for _, sa := range byIP[ip] {
			if err := o.vici.terminateIKE(sa.IKEID); err == nil {
				o.emitLogf("Info", "ikev2: user %s over global device limit, terminating SA %d from %s",
					user, sa.IKEID, ip)
			}
		}
	}
}
