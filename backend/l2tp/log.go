package l2tp

import (
	"fmt"
	"time"
)

const l2tpLogTimestampFormat = "2006/01/02 15:04:05"

func (o *L2TP) emitLogf(severity, format string, args ...any) {
	o.emitLog(severity, fmt.Sprintf(format, args...))
}

func (o *L2TP) emitLog(severity, message string) {
	o.mu.RLock()
	ch := o.logChan
	o.mu.RUnlock()
	if ch == nil {
		return
	}
	line := fmt.Sprintf("%s [%s] %s", time.Now().UTC().Format(l2tpLogTimestampFormat), severity, message)
	select {
	case ch <- line:
	default:
	}
}
