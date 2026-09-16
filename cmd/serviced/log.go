package main

import (
	"fmt"
	"os"
	"time"
)

// logf writes timestamped messages to stderr.
func logf(format string, args ...interface{}) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[%s] %s\n", ts, msg)
}
