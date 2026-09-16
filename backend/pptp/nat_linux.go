//go:build linux

package pptp

import (
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/pooyahpx/HPXNODE/backend/egress"
	"github.com/pooyahpx/HPXNODE/backend/hostroute"
)

const (
	envPPTPHostRouting  = "HPX_NODE_PPTP_HOST_ROUTING"
	envPPTPNATInterface = "HPX_NODE_PPTP_NAT_OUTPUT_INTERFACE"
	ipv4ForwardPath     = "/proc/sys/net/ipv4/ip_forward"
)

func (o *PPTP) setupNAT() error {
	o.hostRouting = applyHostRouting(o.config.Pool, o.config.EgressInterface)
	return nil
}

func applyHostRouting(pool, egressIface string) func() {
	if v := strings.TrimSpace(os.Getenv(envPPTPHostRouting)); v == "0" || strings.EqualFold(v, "false") {
		return nil
	}
	if strings.TrimSpace(pool) == "" {
		return nil
	}
	if err := ensureIPv4Forwarding(); err != nil {
		log.Printf("pptp host routing: enabling IPv4 forwarding failed: %v", err)
	}
	outIf := strings.TrimSpace(egressIface)
	if outIf == "" {
		outIf = strings.TrimSpace(os.Getenv(envPPTPNATInterface))
	}
	egressCleanup, err := egress.Apply(pool, egressIface)
	if err != nil {
		log.Printf("pptp host routing: egress routing for %s via %s failed: %v", pool, egressIface, err)
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
			log.Printf("pptp host routing: iptables masquerade failed: %v", err)
		}
	}
	owner := "pptp:" + pool
	if rules, err := hostroute.EnsureForwardAcceptForSubnet(pool, owner); err != nil {
		log.Printf("pptp host routing: forward accept rules failed: %v", err)
	} else if len(rules) > 0 {
		log.Printf("pptp host routing: forward accept for %s in %v (owner %q)", pool, rules, owner)
	}
	return func() {
		if egressCleanup != nil {
			egressCleanup()
		}
		if err := masq("-D"); err != nil {
			log.Printf("pptp host routing: iptables cleanup failed: %v", err)
		}
		if err := hostroute.RemoveForwardRules(owner); err != nil {
			log.Printf("pptp host routing: forward cleanup failed: %v", err)
		}
	}
}

func ensureIPv4Forwarding() error {
	return os.WriteFile(ipv4ForwardPath, []byte("1\n"), 0o644)
}

func runIptables(args ...string) error {
	return exec.Command("iptables", args...).Run()
}
