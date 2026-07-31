package ikev2

import "github.com/pooyahpx/HPXNODE/backend/ratelimit"

// ShapedClients lists connected IKEv2 clients that carry a speed limit, paired
// with the pool address they were assigned, for the node's shaper.
//
// IKEv2 hands out a virtual IP per SA only while connected, so this reflects the
// live SA list. Marking (and therefore shaping) happens in FORWARD on that
// virtual address, which is readable there even though the client's packets are
// ESP-encrypted by the time they egress.
func (o *IKEv2) ShapedClients() []ratelimit.Client {
	o.mu.RLock()
	vici := o.vici
	users := o.users
	o.mu.RUnlock()
	if vici == nil || users == nil {
		return nil
	}

	sas, err := vici.listSAs()
	if err != nil {
		return nil
	}

	var clients []ratelimit.Client
	for _, sa := range sas {
		limit := users.speedLimitFor(sa.Identity)
		if limit == 0 {
			continue
		}
		for _, vip := range sa.VirtualIPs {
			if vip == "" {
				continue
			}
			clients = append(clients, ratelimit.Client{
				User:      sa.Identity,
				Address:   vip,
				LimitKbps: limit,
			})
		}
	}
	return clients
}
