//go:build !linux

package l2tp

// setupNAT is a no-op on non-Linux platforms (L2TP forwarding relies on the
// Linux kernel IPsec stack and iptables).
func (o *L2TP) setupNAT() error { return nil }
