//go:build linux

package l2tp

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
	envL2TPHostRouting  = "HPX_NODE_L2TP_HOST_ROUTING"
	envL2TPNATInterface = "HPX_NODE_L2TP_NAT_OUTPUT_INTERFACE"
	ipv4ForwardPath     = "/proc/sys/net/ipv4/ip_forward"
)

// setupNAT enables IPv4 forwarding and MASQUERADEs the client pool out the
// chosen egress interface, storing a cleanup closure on the backend.
func (o *L2TP) setupNAT() error {
	o.hostRouting = applyHostRouting(o.config.Pool, o.config.EgressInterface)
	return nil
}

func applyHostRouting(pool, egressIface string) func() {
	if v := strings.TrimSpace(os.Getenv(envL2TPHostRouting)); v == "0" || strings.EqualFold(v, "false") {
		return nil
	}
	if strings.TrimSpace(pool) == "" {
		return nil
	}
	if err := ensureIPv4Forwarding(); err != nil {
		log.Printf("l2tp host routing: enabling IPv4 forwarding failed: %v", err)
	}
	outIf := strings.TrimSpace(egressIface)
	if outIf == "" {
		outIf = strings.TrimSpace(os.Getenv(envL2TPNATInterface))
	}
	egressCleanup, err := egress.Apply(pool, egressIface)
	if err != nil {
		log.Printf("l2tp host routing: egress routing for %s via %s failed: %v", pool, egressIface, err)
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
			log.Printf("l2tp host routing: iptables masquerade failed: %v", err)
		}
	}

	// Docker sets the FORWARD policy to drop, so an explicit accept is needed or
	// the client's packets die in FORWARD before reaching POSTROUTING.
	owner := forwardOwnerID(pool)
	if rules, err := hostroute.EnsureForwardAcceptForSubnet(pool, owner); err != nil {
		log.Printf("l2tp host routing: forward accept rules failed: %v", err)
	} else if len(rules) > 0 {
		log.Printf("l2tp host routing: forward accept for %s in %v (owner %q)", pool, rules, owner)
	}

	return func() {
		if egressCleanup != nil {
			egressCleanup()
		}
		if err := masq("-D"); err != nil {
			log.Printf("l2tp host routing: iptables cleanup failed: %v", err)
		}
		if err := hostroute.RemoveForwardRules(owner); err != nil {
			log.Printf("l2tp host routing: forward cleanup failed: %v", err)
		}
	}
}

func forwardOwnerID(pool string) string {
	return "l2tp_" + strings.NewReplacer("/", "_", ".", "_", ":", "_").Replace(pool)
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
