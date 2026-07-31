//go:build linux

package ikev2

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/pooyahpx/HPXNODE/backend/egress"
	"github.com/pooyahpx/HPXNODE/backend/hostroute"
)

const (
	envIKEv2HostRouting  = "HPX_NODE_IKEV2_HOST_ROUTING"
	envIKEv2NATInterface = "HPX_NODE_IKEV2_NAT_OUTPUT_INTERFACE"
	ipv4ForwardPath      = "/proc/sys/net/ipv4/ip_forward"
)

// setupNAT enables IPv4 forwarding and MASQUERADEs the client pool, storing a
// cleanup closure on the backend.
func (o *IKEv2) setupNAT() error {
	o.hostRouting = applyHostRouting(o.config.Pool, o.config.EgressInterface)
	return nil
}

func applyHostRouting(pool, egressIface string) func() {
	if v := strings.TrimSpace(os.Getenv(envIKEv2HostRouting)); v == "0" || strings.EqualFold(v, "false") {
		return nil
	}
	if strings.TrimSpace(pool) == "" {
		return nil
	}
	if err := ensureIPv4Forwarding(); err != nil {
		log.Printf("ikev2 host routing: enabling IPv4 forwarding failed: %v", err)
	}
	outIf := strings.TrimSpace(egressIface)
	if outIf == "" {
		outIf = strings.TrimSpace(os.Getenv(envIKEv2NATInterface))
	}
	egressCleanup, err := egress.Apply(pool, egressIface)
	if err != nil {
		log.Printf("ikev2 host routing: egress routing for %s via %s failed: %v", pool, egressIface, err)
	}
	masq := func(action string) error {
		args := []string{"-t", "nat", action, "POSTROUTING", "-s", pool}
		if outIf != "" {
			args = append(args, "-o", outIf)
		}
		args = append(args, "-j", "MASQUERADE")
		return runIptables(args...)
	}
	if err := masq("-C"); err != nil {
		if err := masq("-A"); err != nil {
			log.Printf("ikev2 host routing: iptables masquerade failed: %v", err)
		}
	}

	// Masquerade alone is not enough: Docker sets the FORWARD policy to drop, so
	// without an explicit accept the client's packets die in FORWARD before ever
	// reaching POSTROUTING — the tunnel connects and no traffic passes.
	owner := forwardOwnerID(pool)
	if rules, err := hostroute.EnsureForwardAcceptForSubnet(pool, owner); err != nil {
		log.Printf("ikev2 host routing: forward accept rules failed: %v", err)
	} else if len(rules) > 0 {
		log.Printf("ikev2 host routing: forward accept for %s in %v (owner %q)", pool, rules, owner)
	}

	return func() {
		if egressCleanup != nil {
			egressCleanup()
		}
		if err := masq("-D"); err != nil {
			log.Printf("ikev2 host routing: iptables cleanup failed: %v", err)
		}
		if err := hostroute.RemoveForwardRules(owner); err != nil {
			log.Printf("ikev2 host routing: forward cleanup failed: %v", err)
		}
	}
}

func forwardOwnerID(pool string) string {
	return "ikev2_" + strings.NewReplacer("/", "_", ".", "_", ":", "_").Replace(pool)
}

func ensureIPv4Forwarding() error {
	out, err := os.ReadFile(ipv4ForwardPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", ipv4ForwardPath, err)
	}
	if strings.TrimSpace(string(out)) == "1" {
		return nil
	}
	if err := os.WriteFile(ipv4ForwardPath, []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", ipv4ForwardPath, err)
	}
	return nil
}

func runIptables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
