// Package egress routes one VPN subnet out a chosen interface.
//
// A node can host several VPN cores, each with its own client subnet, and an
// operator may want each subnet to leave through a different upstream tunnel —
// clients on one port exit via a Germany tunnel, another port via a US tunnel.
// Masquerade alone cannot do that: it only rewrites the source of packets the
// routing table already sent out a given interface. So this package adds the
// policy routing that actually steers a subnet's traffic:
//
//   - a dedicated routing table whose default route points at the egress
//     interface, and
//   - an `ip rule` sending every packet FROM the subnet to that table.
//
// The NAT (masquerade on the egress interface) is left to the caller, which
// already installs a per-subnet masquerade — it just targets the egress
// interface. The table number is derived from the subnet so it is stable across
// restarts and never collides between different subnets.
package egress

import (
	"fmt"
	"hash/fnv"
	"strings"
)

// tableFor maps a subnet to a stable routing-table id in [tableBase, tableBase+
// tableSpan). Different subnets almost never collide; two that did would simply
// share a table, still correct as long as they egress the same way (and the
// caller keys everything by subnet).
const (
	tableBase = 100
	tableSpan = 900
)

func tableFor(subnet string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(subnet))
	return tableBase + int(h.Sum32()%uint32(tableSpan))
}

// runCmd runs a command; swapped out in tests. Set by the platform file.
var runCmd func(name string, args ...string) error

// Apply steers traffic from subnet out iface and returns a cleanup func that
// removes exactly what it installed. Both empty means "do nothing", so callers
// can invoke it unconditionally. The cleanup is safe to call more than once.
func Apply(subnet, iface string) (func(), error) {
	subnet = strings.TrimSpace(subnet)
	iface = strings.TrimSpace(iface)
	if subnet == "" || iface == "" {
		return func() {}, nil
	}

	table := fmt.Sprintf("%d", tableFor(subnet))

	// Default route for this subnet's own table, pointing at the egress iface.
	// `replace` is idempotent, so a restart re-asserts cleanly.
	if err := runCmd("ip", "route", "replace", "default", "dev", iface, "table", table); err != nil {
		return func() {}, fmt.Errorf("egress route for %s via %s: %w", subnet, iface, err)
	}

	// Send everything sourced from the subnet to that table. Delete any stale
	// copy first so re-applying never stacks duplicate rules.
	_ = runCmd("ip", "rule", "del", "from", subnet, "lookup", table)
	if err := runCmd("ip", "rule", "add", "from", subnet, "lookup", table); err != nil {
		_ = runCmd("ip", "route", "flush", "table", table)
		return func() {}, fmt.Errorf("egress rule for %s: %w", subnet, err)
	}

	return func() {
		_ = runCmd("ip", "rule", "del", "from", subnet, "lookup", table)
		_ = runCmd("ip", "route", "flush", "table", table)
	}, nil
}
