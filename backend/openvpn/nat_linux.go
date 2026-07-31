//go:build linux

package openvpn

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
	envOpenVPNHostRouting  = "HPX_NODE_OPENVPN_HOST_ROUTING"
	envOpenVPNNATInterface = "HPX_NODE_OPENVPN_NAT_OUTPUT_INTERFACE"
	ipv4ForwardPath        = "/proc/sys/net/ipv4/ip_forward"
)

// applyHostRouting enables IPv4 forwarding and installs an iptables MASQUERADE
// rule for the OpenVPN server subnet, returning a cleanup closure.
//
// Disable with HPX_NODE_OPENVPN_HOST_ROUTING=0.
func applyHostRouting(serverSubnet, egressIface string) func() {
	if v := strings.TrimSpace(os.Getenv(envOpenVPNHostRouting)); v == "0" || strings.EqualFold(v, "false") {
		return nil
	}
	if strings.TrimSpace(serverSubnet) == "" {
		return nil
	}

	if err := ensureIPv4Forwarding(); err != nil {
		log.Printf("openvpn host routing: enabling IPv4 forwarding failed: %v", err)
	}

	// A per-core egress interface wins over the global env override.
	outIf := strings.TrimSpace(egressIface)
	if outIf == "" {
		outIf = strings.TrimSpace(os.Getenv(envOpenVPNNATInterface))
	}

	// Steer this subnet out the egress interface (policy routing). NAT below
	// already targets outIf, so together they send the subnet's traffic there.
	egressCleanup, err := egress.Apply(serverSubnet, egressIface)
	if err != nil {
		log.Printf("openvpn host routing: egress routing for %s via %s failed: %v", serverSubnet, egressIface, err)
	}

	masq := func(action string) error {
		args := []string{"-t", "nat", action, "POSTROUTING", "-s", serverSubnet}
		if outIf != "" {
			args = append(args, "-o", outIf)
		}
		args = append(args, "-j", "MASQUERADE")
		return runIptables(args...)
	}

	// -C checks existence; add only if missing.
	if err := masq("-C"); err != nil {
		if err := masq("-A"); err != nil {
			log.Printf("openvpn host routing: iptables masquerade failed: %v", err)
		}
	}

	// Masquerade alone is not enough: Docker sets the FORWARD policy to drop, so
	// without an explicit accept the client's packets die in FORWARD before ever
	// reaching POSTROUTING — the tunnel connects and no traffic passes.
	owner := forwardOwnerID(serverSubnet)
	if rules, err := hostroute.EnsureForwardAcceptForSubnet(serverSubnet, owner); err != nil {
		log.Printf("openvpn host routing: forward accept rules failed: %v", err)
	} else if len(rules) > 0 {
		log.Printf("openvpn host routing: forward accept for %s in %v (owner %q)", serverSubnet, rules, owner)
	}

	return func() {
		if egressCleanup != nil {
			egressCleanup()
		}
		if err := masq("-D"); err != nil {
			log.Printf("openvpn host routing: iptables cleanup failed: %v", err)
		}
		if err := hostroute.RemoveForwardRules(owner); err != nil {
			log.Printf("openvpn host routing: forward cleanup failed: %v", err)
		}
	}
}

func forwardOwnerID(subnet string) string {
	return "openvpn_" + strings.NewReplacer("/", "_", ".", "_", ":", "_").Replace(subnet)
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
