package egress

import (
	"strings"
	"testing"
)

func TestTableForIsStableAndInRange(t *testing.T) {
	a := tableFor("10.29.0.0/16")
	b := tableFor("10.29.0.0/16")
	if a != b {
		t.Fatalf("table id must be stable for a subnet: %d != %d", a, b)
	}
	if a < tableBase || a >= tableBase+tableSpan {
		t.Fatalf("table id %d out of range [%d,%d)", a, tableBase, tableBase+tableSpan)
	}
	if tableFor("10.40.0.0/16") == a {
		t.Skip("hash collision between the two sample subnets; not a failure, just unlucky")
	}
}

func withRecorder(t *testing.T) *[]string {
	t.Helper()
	var cmds []string
	prev := runCmd
	runCmd = func(name string, args ...string) error {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { runCmd = prev })
	return &cmds
}

func has(cmds []string, sub string) bool {
	for _, c := range cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func TestApplyInstallsRouteAndRule(t *testing.T) {
	cmds := withRecorder(t)
	table := tableFor("10.29.0.0/16")

	cleanup, err := Apply("10.29.0.0/16", "wg-de")
	if err != nil {
		t.Fatal(err)
	}
	if !has(*cmds, "ip route replace default dev wg-de table "+itoa(table)) {
		t.Fatalf("expected a default route via the egress iface, got: %v", *cmds)
	}
	if !has(*cmds, "ip rule add from 10.29.0.0/16 lookup "+itoa(table)) {
		t.Fatalf("expected an ip rule sending the subnet to its table, got: %v", *cmds)
	}

	*cmds = nil
	cleanup()
	if !has(*cmds, "ip rule del from 10.29.0.0/16 lookup "+itoa(table)) {
		t.Fatal("cleanup must remove the ip rule")
	}
	if !has(*cmds, "ip route flush table "+itoa(table)) {
		t.Fatal("cleanup must flush the routing table")
	}
}

func TestApplyNoopWhenUnset(t *testing.T) {
	cmds := withRecorder(t)
	cleanup, err := Apply("10.29.0.0/16", "")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if len(*cmds) != 0 {
		t.Fatalf("no egress interface must install nothing, got: %v", *cmds)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
