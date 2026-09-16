//go:build !linux

package pptp

func terminateSession(pid int) bool { return false }
