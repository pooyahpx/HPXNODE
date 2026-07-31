package controller

import (
	"log"
	"os"
	"strings"

	"github.com/pooyahpx/HPXNODE/backend/ratelimit"
)

// shapedBackend is implemented by the tunnel backends that can report which of
// their clients carry a speed limit and what tunnel address to shape.
type shapedBackend interface {
	ShapedClients() []ratelimit.Client
}

// refreshShaping collects every shaped client across the node's backends and
// hands them to the traffic shaper. It is a no-op until at least one client
// actually has a limit, so nodes that never use speed limits pay nothing.
func (c *Controller) refreshShaping() {
	c.mu.RLock()
	backends := make([]interface{}, 0, len(c.backends))
	for _, b := range c.backends {
		backends = append(backends, b)
	}
	shaper := c.shaper
	c.mu.RUnlock()

	var clients []ratelimit.Client
	for _, b := range backends {
		if sb, ok := b.(shapedBackend); ok {
			clients = append(clients, sb.ShapedClients()...)
		}
	}

	if shaper == nil {
		if len(clients) == 0 {
			return // nothing to shape and nothing set up — stay idle.
		}
		iface := egressInterface()
		if iface == "" {
			log.Printf("ratelimit: no egress interface detected; speed limits not applied")
			return
		}
		shaper = ratelimit.New(iface)
		c.mu.Lock()
		c.shaper = shaper
		c.mu.Unlock()
	}

	if err := shaper.Apply(clients); err != nil {
		log.Printf("ratelimit: applying speed limits failed: %v", err)
	}
}

// closeShaping tears down all shaping when the node disconnects.
func (c *Controller) closeShaping() {
	c.mu.Lock()
	shaper := c.shaper
	c.shaper = nil
	c.mu.Unlock()
	if shaper != nil {
		shaper.Close()
	}
}

// egressInterface picks the interface shaping hangs off. It reuses the same
// override the WireGuard host-routing NAT uses so a node only has to be told
// its egress interface once, then falls back to the default route.
func egressInterface() string {
	if v := strings.TrimSpace(os.Getenv("HPX_NODE_WG_NAT_OUTPUT_INTERFACE")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("HPX_NODE_SHAPING_INTERFACE")); v != "" {
		return v
	}
	if iface := defaultRouteInterface(); iface != "" {
		return iface
	}
	return "eth0"
}
