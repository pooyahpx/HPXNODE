//go:build !linux

package l2tp

// terminateSession is a no-op on non-Linux platforms (pppd is Linux-only).
func terminateSession(pid int) bool { return false }
