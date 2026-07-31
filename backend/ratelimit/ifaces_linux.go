//go:build linux

package ratelimit

import (
	"net"
	"strings"
)

// tunnelPrefixes are the interface name prefixes a client's download leaves by.
// WireGuard uses its configured name (wg…), OpenVPN a tun device, IPsec has no
// interface (its download egresses the main interface encrypted).
var tunnelPrefixes = []string{"wg", "tun", "ipsec", "gre"}

// shapingInterfaces lists the interfaces a class tree must hang on: the egress
// (upload leaves here) plus every up tunnel interface (download leaves there).
func (m *Manager) shapingInterfaces() []string {
	out := []string{m.egress}
	seen := map[string]struct{}{m.egress: {}}

	links, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, l := range links {
		if l.Flags&net.FlagUp == 0 {
			continue
		}
		if _, ok := seen[l.Name]; ok {
			continue
		}
		for _, p := range tunnelPrefixes {
			if strings.HasPrefix(l.Name, p) {
				out = append(out, l.Name)
				seen[l.Name] = struct{}{}
				break
			}
		}
	}
	return out
}
