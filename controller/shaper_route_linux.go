//go:build linux

package controller

import "github.com/vishvananda/netlink"

// defaultRouteInterface returns the interface carrying the default route, which
// is where client traffic egresses and therefore where shaping must hang.
func defaultRouteInterface() string {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return ""
	}
	for _, r := range routes {
		if r.Dst == nil && r.LinkIndex > 0 { // Dst nil == default route.
			if link, err := netlink.LinkByIndex(r.LinkIndex); err == nil {
				return link.Attrs().Name
			}
		}
	}
	return ""
}
