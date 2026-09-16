package pptp

import "sort"

func (o *PPTP) Protocol() string { return "pptp" }

func (o *PPTP) OnlineDeviceCounts() map[string]int {
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

func (o *PPTP) UserLimit(user string) (uint32, bool) {
	return o.users.limitKnown(user)
}

func (o *PPTP) KeepDevices(user string, keep int) {
	if keep < 0 {
		keep = 0
	}
	var list []pptpSession
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
			o.emitLogf("Info", "pptp: user %s over global device limit, disconnecting %s", user, s.ifname)
		}
	}
}
