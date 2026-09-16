package pptp

import (
	"fmt"
	"time"
)

const pptpLogTimestampFormat = "2006/01/02 15:04:05"

func (o *PPTP) emitLogf(severity, format string, args ...any) {
	o.emitLog(severity, fmt.Sprintf(format, args...))
}

func (o *PPTP) emitLog(severity, message string) {
	o.mu.RLock()
	ch := o.logChan
	o.mu.RUnlock()
	if ch == nil {
		return
	}
	line := fmt.Sprintf("%s [%s] %s", time.Now().UTC().Format(pptpLogTimestampFormat), severity, message)
	select {
	case ch <- line:
	default:
	}
}
