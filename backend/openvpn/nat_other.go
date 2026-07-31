//go:build !linux

package openvpn

// applyHostRouting is a no-op on non-Linux platforms (OpenVPN NAT relies on
// iptables/ip_forward which are Linux-only). Returns nil so callers skip cleanup.
func applyHostRouting(serverSubnet, egressIface string) func() {
	return nil
}
