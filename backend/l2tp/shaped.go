package l2tp

import "github.com/pooyahpx/HPXNODE/backend/ratelimit"

// ShapedClients lists connected L2TP clients that carry a speed limit, paired
// with the tunnel address pppd assigned them, for the node's shaper. Each live
// PPP session (one per device) is shaped on its assigned tunnel IP; marking (and
// therefore shaping) happens in FORWARD on that address.
func (o *L2TP) ShapedClients() []ratelimit.Client {
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
