//go:build linux

package l2tp

import "syscall"

// terminateSession sends SIGTERM to a pppd process to drop one L2TP session.
// pppd tears the PPP link (and its ppp<N> interface) down cleanly on SIGTERM.
func terminateSession(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, syscall.SIGTERM) == nil
}
