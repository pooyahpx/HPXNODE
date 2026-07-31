//go:build !linux

package ratelimit

// nft only exists on Linux, so shaping never runs elsewhere: this invoker does
// nothing and the shared syncMarks/teardownMarks call it.
var defaultNFT = func(args ...string) error { return nil }
