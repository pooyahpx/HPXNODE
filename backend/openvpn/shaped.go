package openvpn

import "github.com/pooyahpx/HPXNODE/backend/ratelimit"

// ShapedClients lists the connected OpenVPN clients that carry a speed limit,
// paired with the address they hold inside the tunnel, for the node's shaper.
//
// Unlike WireGuard, OpenVPN assigns a tunnel address only while a client is
// connected, so this reflects the last status snapshot: a client that is not
// connected has no address to shape and simply isn't listed.
func (o *OpenVPN) ShapedClients() []ratelimit.Client {
	o.mu.RLock()
	mgmt := o.mgmt
	users := o.users
	o.mu.RUnlock()
	if mgmt == nil || users == nil {
		return nil
	}

	var clients []ratelimit.Client
	for _, cs := range mgmt.statusSnapshot() {
		if cs.VirtualAddr == "" {
			continue
		}
		limit := users.speedLimitFor(cs.CommonName)
		if limit == 0 {
			continue
		}
		clients = append(clients, ratelimit.Client{
			User:      cs.CommonName,
			Address:   cs.VirtualAddr,
			LimitKbps: limit,
		})
	}
	return clients
}
