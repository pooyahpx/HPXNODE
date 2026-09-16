package pptp

import "github.com/pooyahpx/HPXNODE/backend/ratelimit"

func (o *PPTP) ShapedClients() []ratelimit.Client {
	var clients []ratelimit.Client
	for _, s := range readSessions() {
		limit := o.users.speedLimitFor(s.user)
		if limit == 0 || s.tunnelIP == "" {
			continue
		}
		clients = append(clients, ratelimit.Client{
			User:      s.user,
			Address:   s.tunnelIP,
			LimitKbps: limit,
		})
	}
	return clients
}
