//go:build !linux

package wireguard

// applyLinuxHostRouting is a no-op on non-Linux platforms.
func applyLinuxHostRouting(_, _, _ string) func() { return nil }
