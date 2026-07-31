//go:build !linux

package hostroute

// The host firewall rules only exist on Linux; everywhere else these are no-ops
// so the backends can call them unconditionally.

func EnsureForwardAcceptForSubnet(subnet, ownerID string) ([]string, error) { return nil, nil }

func RemoveForwardRules(ownerID string) error { return nil }
