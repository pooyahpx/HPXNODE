package ratelimit

import (
	"strings"
	"testing"
)

// fakeRunner records commands instead of touching the kernel.
type fakeRunner struct {
	cmds []string
	// failFor makes any command containing this substring fail.
	failFor string
}

func (f *fakeRunner) run(name string, args ...string) error {
	line := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, line)
	if f.failFor != "" && strings.Contains(line, f.failFor) {
		return errFake
	}
	// `iptables -C` must report "absent" so the add path is exercised.
	if strings.Contains(line, "iptables") && strings.Contains(line, " -C ") {
		return errFake
	}
	return nil
}

func (f *fakeRunner) output(string, ...string) (string, error) { return "", nil }

func (f *fakeRunner) contains(substr string) bool {
	for _, c := range f.cmds {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func (f *fakeRunner) count(substr string) int {
	n := 0
	for _, c := range f.cmds {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

type fakeErr struct{}

func (fakeErr) Error() string { return "fake failure" }

var errFake = fakeErr{}

func newTestManager() (*Manager, *fakeRunner) {
	r := &fakeRunner{}
	m := New("eth0")
	m.runner = r
	// Record nft invocations through the same recorder so tests can assert on
	// marking without a live nftables.
	m.nft = func(args ...string) error {
		r.cmds = append(r.cmds, "nft "+strings.Join(args, " "))
		return nil
	}
	// Pin the interface set so tests don't depend on the host's real NICs.
	m.interfaces = func() []string { return []string{"eth0"} }
	return m, r
}

func TestApplyShapesEachDirection(t *testing.T) {
	m, r := newTestManager()

	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 8000}}); err != nil {
		t.Fatal(err)
	}

	if !r.contains("tc qdisc add dev eth0 root handle 1: htb") {
		t.Fatal("expected the HTB root to be installed on first use")
	}
	// One class and one mark rule per direction.
	if got := r.count("tc class replace dev eth0"); got < 3 {
		t.Fatalf("expected a default class plus one per direction, got %d class adds", got)
	}
	if !r.contains("ip daddr 10.29.0.5") {
		t.Fatal("download traffic must be matched on the destination address")
	}
	if !r.contains("ip saddr 10.29.0.5") {
		t.Fatal("upload traffic must be matched on the source address")
	}
	if !r.contains("rate 8000kbit") {
		t.Fatal("the class rate must be the user's ceiling")
	}
	// Marking must go through nft (the node runs an nftables ruleset; legacy
	// iptables cannot touch its forward chain), in the forward hook where an
	// IPsec client's tunnel address is still readable.
	if !r.contains("nft add rule inet pg_shaper shape") {
		t.Fatal("marks must be set via an nft rule in the shaper chain")
	}
	if !r.contains("hook forward") {
		t.Fatal("the mark chain must hook forward")
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	m, _ := newTestManager()
	client := []Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 8000}}

	// Applying twice must converge to the same state; the commands are
	// declarative (replace), so re-running them is harmless.
	if err := m.Apply(client); err != nil {
		t.Fatal(err)
	}
	firstMarkVal := m.marks["10.29.0.5"]
	if err := m.Apply(client); err != nil {
		t.Fatal(err)
	}
	if len(m.applied) != 1 {
		t.Fatalf("re-applying an unchanged set must keep exactly one client, got %d", len(m.applied))
	}
	if m.marks["10.29.0.5"] != firstMarkVal {
		t.Fatal("a re-applied client must keep its mark")
	}
}

func TestApplyUpdatesChangedCeiling(t *testing.T) {
	m, r := newTestManager()
	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 8000}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 2000}}); err != nil {
		t.Fatal(err)
	}
	if !r.contains("rate 2000kbit") {
		t.Fatal("a changed ceiling should be re-applied at the new rate")
	}
}

func TestApplyRemovesDepartedClients(t *testing.T) {
	m, r := newTestManager()
	if err := m.Apply([]Client{
		{User: "alice", Address: "10.29.0.5", LimitKbps: 8000},
		{User: "bob", Address: "10.29.0.6", LimitKbps: 4000},
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 8000}}); err != nil {
		t.Fatal(err)
	}

	// The chain is rebuilt on removal; the departed address must not appear in
	// the last rebuild, while the remaining one must.
	last := lastFlushOnward(r.cmds)
	for _, c := range last {
		if strings.Contains(c, "10.29.0.6") {
			t.Fatal("the departed client must not be marked after removal")
		}
	}
	found := false
	for _, c := range last {
		if strings.Contains(c, "ip daddr 10.29.0.5") {
			found = true
		}
	}
	if !found {
		t.Fatal("the remaining client must still be marked")
	}
	if _, still := m.applied["10.29.0.6"]; still {
		t.Fatal("the departed client must be dropped from the applied set")
	}
}

func TestZeroLimitIsNotShaped(t *testing.T) {
	m, r := newTestManager()
	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 0}}); err != nil {
		t.Fatal(err)
	}
	if r.contains("tc class replace dev eth0 parent 1: classid 1:2") {
		t.Fatal("an unlimited user must not get a shaping class")
	}
	if len(m.applied) != 0 {
		t.Fatal("an unlimited user must not be recorded as shaped")
	}
}

func TestCloseRemovesEverything(t *testing.T) {
	m, r := newTestManager()
	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 8000}}); err != nil {
		t.Fatal(err)
	}
	m.Close()

	if !r.contains("tc qdisc del dev eth0 root") {
		t.Fatal("Close must remove the qdisc so no shaping is left behind")
	}
	if !r.contains("nft delete table inet pg_shaper") {
		t.Fatal("Close must remove the nft shaper table")
	}
	if len(m.applied) != 0 {
		t.Fatal("Close must clear the applied set")
	}
}

func TestMarksAreReusedAfterRemoval(t *testing.T) {
	m, _ := newTestManager()
	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 8000}}); err != nil {
		t.Fatal(err)
	}
	first := m.marks["10.29.0.5"]

	if err := m.Apply(nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply([]Client{{User: "bob", Address: "10.29.0.9", LimitKbps: 1000}}); err != nil {
		t.Fatal(err)
	}
	if got := m.marks["10.29.0.9"]; got != first {
		t.Fatalf("a freed mark should be handed to the next client: got %#x, want %#x", got, first)
	}
}

func TestDownloadAndUploadGetDistinctClasses(t *testing.T) {
	down := classID(firstMark, Download)
	up := classID(firstMark, Upload)
	if down == up {
		t.Fatal("the two directions must not share a class, or the cap would be halved")
	}
	// 1:0 is the root handle; a client class must never land on it.
	if down == "1:0" || up == "1:0" {
		t.Fatalf("the first client collided with the root handle: down=%s up=%s", down, up)
	}
	if markValue(firstMark, Download) == markValue(firstMark, Upload) {
		t.Fatal("the two directions must not share a mark, or one filter would catch both")
	}
}

// lastFlushOnward returns the commands from the last chain flush onward, i.e.
// the most recent rebuild of the mark chain.
func lastFlushOnward(cmds []string) []string {
	idx := -1
	for i, c := range cmds {
		if strings.Contains(c, "flush chain inet pg_shaper") {
			idx = i
		}
	}
	if idx < 0 {
		return cmds
	}
	return cmds[idx:]
}
