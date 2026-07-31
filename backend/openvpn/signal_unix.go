//go:build !windows

package openvpn

import (
	"os"
	"syscall"
)

func terminateSignal() os.Signal {
	return syscall.SIGTERM
}
