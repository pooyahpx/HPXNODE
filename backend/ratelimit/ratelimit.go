// Package ratelimit caps how fast an individual VPN client may move traffic.
//
// The panel gives a user a throughput ceiling in kbit/s; this package turns
// that into Linux traffic-control state on the node. It works for the tunnel
// backends — openvpn, wireguard and ikev2 — because each of those hands every
// client its own address inside the tunnel, which is what a shaper needs to
// tell clients apart. Xray users all share the proxy's own egress and cannot be
// separated at the packet level, so they are out of scope.
//
// How it is wired:
//
//   - An HTB qdisc with a class per (user, direction) is installed on the egress
//     interface AND on each tunnel interface. This matters because tc only
//     shapes traffic leaving the interface it hangs on: a client's UPLOAD
//     egresses eth0, but its DOWNLOAD egresses the tunnel interface (wg/tun) —
//     so shaping only eth0 would cap upload and leave download wide open.
//   - Packets are classified by firewall mark, not address, so one filter
//     serves every interface and backend. Marks are set with nft in the forward
//     hook, where the client's tunnel address is still visible, and persist to
//     whichever interface the packet finally leaves by.
//   - Download and upload get separate classes, so an "8 Mbit" user gets 8
//     Mbit each way rather than 8 shared.
//
// Everything installed here is tagged and removed again on Close, so a node
// restart never leaves stale shaping behind.
package ratelimit

import (
	"fmt"
	"log"
	"sort"
	"sync"
)

// Direction distinguishes the two classes a user gets.
type Direction int

const (
	// Download is traffic heading to the client (matched on destination).
	Download Direction = iota
	// Upload is traffic coming from the client (matched on source).
	Upload
)

func (d Direction) String() string {
	if d == Upload {
		return "up"
	}
	return "down"
}

// Client is one shaped tunnel address.
type Client struct {
	// User identifies the account the address belongs to, for logging.
	User string
	// Address is the client's address inside the tunnel (host address, no mask).
	Address string
	// LimitKbps is the ceiling per direction. Zero means unshaped.
	LimitKbps uint32
}

// Manager owns the tc and mark state for one node.
type Manager struct {
	mu sync.Mutex
	// egress is the node's internet-facing interface (upload leaves here).
	egress string
	// applied is the state currently installed, keyed by tunnel address.
	applied map[string]Client
	// marks maps an address to the firewall mark handed to it.
	marks map[string]uint32
	// freed holds marks whose client went away, for reuse.
	freed []uint32
	// nextMark is the next never-used mark.
	nextMark uint32
	// ifaceSet is the set of interfaces the shaping tree was last installed on,
	// so departed clients and Close can be cleaned off exactly those.
	ifaceSet map[string]struct{}
	runner   commandRunner
	// nft runs an nft command; swappable so tests observe marking without a
	// live nftables. Defaults to the real nft on Linux, a no-op elsewhere.
	nft func(args ...string) error
	// interfaces returns every interface a class tree must hang on: the egress
	// (for upload) plus the tunnel interfaces (for download, which leaves via
	// wg/tun, not egress). Swappable for tests.
	interfaces func() []string
}

// commandRunner exists so tests can observe the commands without a live kernel.
type commandRunner interface {
	run(name string, args ...string) error
	output(name string, args ...string) (string, error)
}

const (
	// firstMark starts our marks high enough to stay clear of the low values
	// other tools on the host tend to use, and markMask means we only ever read
	// or write our own bits.
	firstMark uint32 = 0x00100000
	markMask  uint32 = 0x00ff0000
	// maxClients bounds the mark range so a runaway user list cannot walk past
	// markMask into somebody else's bits.
	maxClients = 0xfe
)

// New returns a Manager whose egress interface is iface.
func New(iface string) *Manager {
	m := &Manager{
		egress:   iface,
		applied:  map[string]Client{},
		marks:    map[string]uint32{},
		ifaceSet: map[string]struct{}{},
		nextMark: firstMark,
		runner:   execRunner{},
		nft:      defaultNFT,
	}
	m.interfaces = m.shapingInterfaces
	return m
}

// Apply makes the installed shaping match clients exactly, declaratively: it is
// safe to run every poll. It reconciles the mark chain and re-asserts the class
// tree on every current interface — so a client's cap is enforced on both the
// egress (upload) and the tunnel interface its download leaves by (wg/tun),
// and interfaces that appear later (an OpenVPN tun once a client connects) are
// picked up on the next pass. Clients with a zero limit count as absent.
func (m *Manager) Apply(clients []Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	wanted := make(map[string]Client, len(clients))
	for _, c := range clients {
		if c.Address == "" || c.LimitKbps == 0 {
			continue
		}
		wanted[c.Address] = c
	}

	ifaces := m.interfaces()

	// Drop departed clients' classes/filters from every interface, and free
	// their marks, before new ones allocate.
	for addr := range m.applied {
		if _, keep := wanted[addr]; keep {
			continue
		}
		if mark, ok := m.marks[addr]; ok {
			for _, iface := range m.ifaceList() {
				for _, dir := range []Direction{Download, Upload} {
					m.delClass(iface, mark, dir)
				}
			}
			delete(m.marks, addr)
			m.freed = append(m.freed, mark)
		}
		delete(m.applied, addr)
	}

	// Nothing to shape: tear the whole thing down so an idle node is clean.
	if len(wanted) == 0 {
		m.teardownAll()
		return nil
	}

	// Roots first, on every interface (idempotent replace).
	var firstErr error
	setErr := func(e error) {
		if e != nil && firstErr == nil {
			firstErr = e
		}
	}
	for _, iface := range ifaces {
		setErr(m.ensureRoot(iface))
	}

	// Deterministic order keeps class ids stable across runs.
	addrs := make([]string, 0, len(wanted))
	for addr := range wanted {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)

	for _, addr := range addrs {
		c := wanted[addr]
		mark, err := m.allocMark(addr)
		if err != nil {
			setErr(err)
			continue
		}
		prev, existed := m.applied[addr]
		for _, iface := range ifaces {
			for _, dir := range []Direction{Download, Upload} {
				setErr(m.ensureClass(iface, mark, dir, c.LimitKbps))
			}
		}
		m.applied[addr] = c
		if !existed {
			log.Printf("ratelimit: %s (%s) capped at %d kbit/s per direction", c.User, addr, c.LimitKbps)
		} else if prev.LimitKbps != c.LimitKbps {
			log.Printf("ratelimit: %s (%s) cap changed to %d kbit/s per direction", c.User, addr, c.LimitKbps)
		}
	}

	// Record the interface set so departed clients and Close clean the right
	// ones even if the interface list changes later.
	m.ifaceSet = make(map[string]struct{}, len(ifaces))
	for _, iface := range ifaces {
		m.ifaceSet[iface] = struct{}{}
	}

	setErr(m.syncMarks())
	return firstErr
}

// ifaceList returns the interfaces the tree was last installed on, unioned with
// the current set, so cleanup covers both.
func (m *Manager) ifaceList() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(i string) {
		if _, ok := seen[i]; !ok {
			seen[i] = struct{}{}
			out = append(out, i)
		}
	}
	for i := range m.ifaceSet {
		add(i)
	}
	for _, i := range m.interfaces() {
		add(i)
	}
	return out
}

// Close removes every rule and qdisc this manager installed.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.teardownAll()
}

func (m *Manager) teardownAll() {
	for _, iface := range m.ifaceList() {
		m.delRoot(iface)
	}
	m.teardownMarks()
	m.applied = map[string]Client{}
	m.marks = map[string]uint32{}
	m.freed = nil
	m.nextMark = firstMark
	m.ifaceSet = map[string]struct{}{}
}

func (m *Manager) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprintf("ratelimit(egress=%s, clients=%d)", m.egress, len(m.applied))
}
