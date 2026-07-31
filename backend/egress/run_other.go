//go:build !linux

package egress

// Policy routing is Linux-only; elsewhere the runner is a no-op so Apply does
// nothing on non-Linux builds.
func init() {
	runCmd = func(name string, args ...string) error { return nil }
}
