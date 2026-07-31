//go:build !linux

package ikev2

// setupNAT is a no-op on non-Linux platforms (IKEv2 forwarding relies on the
// Linux kernel IPsec stack and iptables).
func (o *IKEv2) setupNAT() error { return nil }
