package ratelimit

import (
	"fmt"
	"os/exec"
	"strings"
)

// execRunner is the real implementation; tests swap in their own.
type execRunner struct{}

func (execRunner) run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (execRunner) output(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// classID is the tc handle for one (client, direction) pair, derived from the
// mark so a class is always recoverable from it. Minor 0 is the root handle
// (1:0 == 1:), so shift by one: the first client's download class is 1:2, its
// upload 1:3, and so on.
func classID(mark uint32, dir Direction) string {
	minor := ((mark & 0xffff) + 1) * 2
	if dir == Upload {
		minor++
	}
	return fmt.Sprintf("1:%x", minor)
}

// markValue folds the direction into the mark so one fw filter separates the
// two directions' classes.
func markValue(mark uint32, dir Direction) uint32 {
	v := mark
	if dir == Upload {
		v |= 0x8000
	}
	return v
}

func commentFor(addr string, dir Direction) string {
	return fmt.Sprintf("HPX_NODE_rl %s %s", addr, dir)
}

// ensureRoot makes sure an HTB root and its unlimited default class exist on an
// interface. `replace` makes this idempotent, so it can run every reconcile and
// pick up interfaces (e.g. an OpenVPN tun) that appeared after the last pass.
func (m *Manager) ensureRoot(iface string) error {
	// `add`, not `replace`: htb rejects changing its `default` option on an
	// existing root ("Change operation not supported"), and the root's options
	// never change, so an already-present root is success. Classes and filters
	// below still use replace, which htb does support.
	if err := m.runner.run("tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "1"); err != nil {
		if !alreadyExists(err) {
			return fmt.Errorf("install shaping root on %s: %w", iface, err)
		}
	}
	// Class 1:1 is the default: unshaped users and the node's own traffic pass
	// through it uncapped.
	return m.runner.run("tc", "class", "replace", "dev", iface, "parent", "1:", "classid", "1:1",
		"htb", "rate", "1000000mbit")
}

func (m *Manager) ensureClass(iface string, mark uint32, dir Direction, kbps uint32) error {
	rate := fmt.Sprintf("%dkbit", kbps)
	if err := m.runner.run("tc", "class", "replace", "dev", iface, "parent", "1:", "classid", classID(mark, dir),
		"htb", "rate", rate, "ceil", rate); err != nil {
		return err
	}
	// The fw filter maps a packet's mark (set by nft) to this class.
	return m.runner.run("tc", "filter", "replace", "dev", iface, "parent", "1:", "protocol", "all",
		"prio", "1", "handle", fmt.Sprintf("%d", markValue(mark, dir)), "fw", "flowid", classID(mark, dir))
}

func (m *Manager) delClass(iface string, mark uint32, dir Direction) {
	_ = m.runner.run("tc", "filter", "del", "dev", iface, "parent", "1:", "protocol", "all",
		"prio", "1", "handle", fmt.Sprintf("%d", markValue(mark, dir)), "fw")
	_ = m.runner.run("tc", "class", "del", "dev", iface, "classid", classID(mark, dir))
}

func (m *Manager) delRoot(iface string) {
	_ = m.runner.run("tc", "qdisc", "del", "dev", iface, "root")
}

// alreadyExists reports whether a tc/nft error just means the object was there.
func alreadyExists(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "file exists") || strings.Contains(s, "exclusivity flag")
}

// allocMark hands out a mark, reusing one from a departed client when possible.
func (m *Manager) allocMark(addr string) (uint32, error) {
	if mark, ok := m.marks[addr]; ok {
		return mark, nil
	}
	if n := len(m.freed); n > 0 {
		mark := m.freed[n-1]
		m.freed = m.freed[:n-1]
		m.marks[addr] = mark
		return mark, nil
	}
	if m.nextMark-firstMark >= maxClients {
		return 0, fmt.Errorf("too many shaped clients (max %d)", maxClients)
	}
	mark := m.nextMark
	m.nextMark++
	m.marks[addr] = mark
	return mark, nil
}
