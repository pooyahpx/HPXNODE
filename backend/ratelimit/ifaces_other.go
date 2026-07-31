//go:build !linux

package ratelimit

// Shaping is Linux-only; elsewhere just the egress, which is never used.
func (m *Manager) shapingInterfaces() []string { return []string{m.egress} }
