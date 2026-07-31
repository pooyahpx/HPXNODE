package openvpn

// Multi-listener support: one core config, several OpenVPN servers.
//
// A single OpenVPN process binds exactly one port/protocol pair, so a core that
// offers both UDP and TCP has to run one server per endpoint. Each server also
// needs its own client address range — two servers handing out addresses from
// the same pool would eventually assign the same IP to two clients — so the
// core's subnet is split into one equal block per listener.

import (
	"fmt"
	"math/bits"
	"net/netip"
	"path/filepath"
)

// derive returns a copy of the config bound to a single listener, with its own
// subnet block and its own working directory under generatedPath. index selects
// which block of the split subnet this listener gets.
func (c *Config) derive(generatedPath string, l Listener, index, total int) (*Config, error) {
	sub, err := splitSubnet(c.ServerSubnet, index, total)
	if err != nil {
		return nil, err
	}

	clone := *c
	clone.Port = l.Port
	clone.Proto = l.Proto
	clone.ServerSubnet = sub
	clone.Listeners = []Listener{l}
	// Keep each server's generated files, management socket and status log
	// apart. The single-listener case keeps the original path so existing
	// installs are untouched.
	if total > 1 {
		clone.workDir = filepath.Join(generatedPath, "openvpn", c.InboundTag, fmt.Sprintf("%s%d", l.Proto, l.Port))
	}
	return &clone, nil
}

// splitSubnet carves the index-th of total equal blocks out of cidr. With a
// single listener the subnet is returned unchanged.
func splitSubnet(cidr string, index, total int) (string, error) {
	if total <= 1 {
		return cidr, nil
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", fmt.Errorf("server_subnet %q is not a valid CIDR: %w", cidr, err)
	}
	if !prefix.Addr().Is4() {
		return "", fmt.Errorf("server_subnet %q must be IPv4 to be split across listeners", cidr)
	}

	// Widen the prefix by enough bits to fit every listener.
	extra := bitsNeeded(total)
	newBits := prefix.Bits() + extra
	// Each server needs room for a /30-ish pool at the very least; stop well
	// before that so the split can never produce an unusable range.
	if newBits > 24 {
		return "", fmt.Errorf(
			"server_subnet %s is too small to split across %d listeners (would need a /%d per listener)",
			cidr, total, newBits,
		)
	}

	base := prefix.Masked().Addr().As4()
	blockSize := uint32(1) << (32 - newBits)
	start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	start += blockSize * uint32(index)

	addr := netip.AddrFrom4([4]byte{
		byte(start >> 24), byte(start >> 16), byte(start >> 8), byte(start),
	})
	return netip.PrefixFrom(addr, newBits).String(), nil
}

// bitsNeeded is the number of prefix bits required to address n blocks.
func bitsNeeded(n int) int {
	if n <= 1 {
		return 0
	}
	return bits.Len(uint(n - 1))
}
