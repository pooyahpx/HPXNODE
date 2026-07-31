package ikev2

import (
	"fmt"
	"time"
)

const ikev2LogTimestampFormat = "2006/01/02 15:04:05"

func (o *IKEv2) emitLogf(severity, format string, args ...any) {
	o.emitLog(severity, fmt.Sprintf(format, args...))
}

func (o *IKEv2) emitLog(severity, message string) {
	o.mu.RLock()
	ch := o.logChan
	o.mu.RUnlock()
	if ch == nil {
		return
	}
	line := fmt.Sprintf("%s [%s] %s", time.Now().UTC().Format(ikev2LogTimestampFormat), severity, message)
	select {
	case ch <- line:
	default:
	}
}
