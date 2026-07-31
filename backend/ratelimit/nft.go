package ratelimit

import "fmt"

// Packet marking is done with nft, not iptables: Docker/host nodes run an
// nftables ruleset, and legacy `iptables -t mangle` refuses to touch a FORWARD
// chain that already holds native nft rules ("chain is incompatible, use nft").
// A dedicated table keeps our rules isolated and easy to remove wholesale. The
// actual nft invocation is m.nft, which is the real binary on Linux and a no-op
// elsewhere (see defaultNFT).
const (
	nftFamily = "inet"
	nftTable  = "pg_shaper"
	// Not "mark": that is an nft keyword and the parser rejects it as a chain name.
	nftChain = "shape"
)

// ensureMarkChain creates the table and the forward-hook chain if absent. The
// chain marks packets in the forward hook at the mangle-equivalent priority,
// where a client's tunnel address is still readable (including for IPsec, whose
// packets are ESP-encrypted by the time they reach the egress qdisc). The mark
// then survives to the qdisc, where tc's fw filter selects the class.
func (m *Manager) ensureMarkChain() error {
	if err := m.nft("add", "table", nftFamily, nftTable); err != nil {
		return err
	}
	return m.nft("add", "chain", nftFamily, nftTable, nftChain,
		"{ type filter hook forward priority mangle ; policy accept ; }")
}

// syncMarks rebuilds the whole mark chain from the applied set. Rebuilding
// wholesale avoids tracking per-rule nft handles: the set is small and only
// changes when a client is added or removed.
func (m *Manager) syncMarks() error {
	if err := m.ensureMarkChain(); err != nil {
		return err
	}
	if err := m.nft("flush", "chain", nftFamily, nftTable, nftChain); err != nil {
		return err
	}
	for addr := range m.applied {
		mark, ok := m.marks[addr]
		if !ok {
			continue
		}
		for _, dir := range []Direction{Download, Upload} {
			match := "daddr" // download: traffic heading to the client
			if dir == Upload {
				match = "saddr" // upload: traffic coming from the client
			}
			if err := m.nft("add", "rule", nftFamily, nftTable, nftChain,
				"ip", match, addr,
				"meta", "mark", "set", fmt.Sprintf("0x%x", markValue(mark, dir)),
				"comment", fmt.Sprintf("%q", commentFor(addr, dir)),
			); err != nil {
				return err
			}
		}
	}
	return nil
}

// teardownMarks removes our table entirely.
func (m *Manager) teardownMarks() {
	_ = m.nft("delete", "table", nftFamily, nftTable)
}
