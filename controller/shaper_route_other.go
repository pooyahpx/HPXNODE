//go:build !linux

package controller

// defaultRouteInterface is Linux-only; other platforms never shape.
func defaultRouteInterface() string { return "" }
