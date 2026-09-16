//go:build !linux

package pptp

func (o *PPTP) setupNAT() error { return nil }
