//go:build linux

package pptp

import "syscall"

func terminateSession(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, syscall.SIGTERM) == nil
}
