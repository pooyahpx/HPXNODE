//go:build windows

package openvpn

import "os"

func terminateSignal() os.Signal {
	return os.Kill
}
