package openvpn

import (
	"fmt"
	"time"
)

const openvpnLogTimestampFormat = "2006/01/02 15:04:05"

func (o *OpenVPN) emitLogf(severity, format string, args ...any) {
	o.emitLog(severity, fmt.Sprintf(format, args...))
}

func (o *OpenVPN) emitLog(severity, message string) {
	o.mu.RLock()
	ch := o.logChan
	o.mu.RUnlock()
	if ch == nil {
		return
	}
	line := fmt.Sprintf("%s [%s] %s", time.Now().UTC().Format(openvpnLogTimestampFormat), severity, message)
	select {
	case ch <- line:
	default:
	}
}
