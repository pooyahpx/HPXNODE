//go:build linux

// Package hostroute installs the host firewall rules a tunnel backend needs for
// its clients to actually reach the internet.
//
// Why this exists: Docker sets the FORWARD chain's policy to `drop`. A backend
// that only installs a NAT masquerade rule therefore has its clients' packets
// dropped in FORWARD *before* they ever reach POSTROUTING — the tunnel comes up,
// the handshake succeeds, and no traffic passes. That failure is silent and
// looks exactly like "connects but nothing works".
//
// So any backend that forwards client traffic must also add an explicit accept
// for its client subnet. Rules are matched on the client subnet rather than an
// interface because IPsec is policy-based and has no interface of its own.
//
// Rules are tagged with an owner comment so they can be removed on stop, and are
// inserted into every base chain hooked to `forward` (that's where Docker's
// FORWARD chain lives). nft is used rather than iptables because once any native
// nftables rule lands in that chain, iptables refuses to touch it
// ("chain FORWARD in table filter is incompatible, use 'nft' tool").
package hostroute

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

const commentPrefix = "HPX_NODE_fwd "

type baseChain struct {
	family string
	table  string
	name   string
}

type listRuleset struct {
	NFTables []map[string]json.RawMessage `json:"nftables"`
}

type listChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Hook   string `json:"hook"`
}

// EnsureForwardAcceptForSubnet allows forwarding for traffic to/from subnet in
// every base chain hooked to forward, replacing any rules previously installed
// under the same ownerID. Returns the rules it installed, for logging.
func EnsureForwardAcceptForSubnet(subnet, ownerID string) ([]string, error) {
	subnet = strings.TrimSpace(subnet)
	if subnet == "" {
		return nil, fmt.Errorf("empty subnet")
	}
	chains, err := forwardBaseChains()
	if err != nil {
		return nil, err
	}
	if len(chains) == 0 {
		// No forward base chain at all means nothing is filtering forwarded
		// traffic, so there is nothing to allow.
		return nil, nil
	}

	installed := make([]string, 0, len(chains)*2)
	for _, chain := range chains {
		if err := removeRulesWithComment(chain, ownerComment(ownerID)); err != nil {
			return nil, err
		}
		for _, outbound := range []bool{false, true} {
			if err := insertAcceptRule(chain, subnet, ownerID, outbound); err != nil {
				return nil, err
			}
			installed = append(installed, fmt.Sprintf("%s/%s/%s %s", chain.family, chain.table, chain.name, direction(outbound)))
		}
	}
	return installed, nil
}

// RemoveForwardRules deletes every rule tagged with ownerID.
func RemoveForwardRules(ownerID string) error {
	chains, err := forwardBaseChains()
	if err != nil {
		return err
	}
	for _, chain := range chains {
		if err := removeRulesWithComment(chain, ownerComment(ownerID)); err != nil {
			return err
		}
	}
	return nil
}

func insertAcceptRule(chain baseChain, subnet, ownerID string, outbound bool) error {
	args := []string{"insert", "rule", chain.family, chain.table, chain.name}
	if outbound {
		// client -> internet
		args = append(args, "ip", "saddr", subnet, "accept")
	} else {
		// internet -> client (replies only)
		args = append(args, "ip", "daddr", subnet, "ct", "state", "established,related", "accept")
	}
	args = append(args, "comment", quote(ruleComment(ownerID, subnet, outbound)))
	return runNFT(args...)
}

func ruleComment(ownerID, subnet string, outbound bool) string {
	return fmt.Sprintf("%sowner=%s type=forward subnet=%s direction=%s", commentPrefix, ownerID, subnet, direction(outbound))
}

func direction(outbound bool) string {
	if outbound {
		return "outbound"
	}
	return "return"
}

func ownerComment(ownerID string) string {
	return fmt.Sprintf("%sowner=%s ", commentPrefix, ownerID)
}

func forwardBaseChains() ([]baseChain, error) {
	out, err := exec.Command("nft", "-j", "list", "ruleset").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft -j list ruleset: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return parseForwardBaseChains(out)
}

func parseForwardBaseChains(data []byte) ([]baseChain, error) {
	var ruleset listRuleset
	if err := json.Unmarshal(data, &ruleset); err != nil {
		return nil, fmt.Errorf("parse nft ruleset: %w", err)
	}
	chains := make([]baseChain, 0)
	for _, item := range ruleset.NFTables {
		raw, ok := item["chain"]
		if !ok {
			continue
		}
		var c listChain
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("parse nft chain: %w", err)
		}
		if c.Hook != "forward" || (c.Family != "ip" && c.Family != "inet") {
			continue
		}
		chains = append(chains, baseChain{family: c.Family, table: c.Table, name: c.Name})
	}
	return chains, nil
}

func removeRulesWithComment(chain baseChain, prefix string) error {
	out, err := exec.Command("nft", "-a", "list", "chain", chain.family, chain.table, chain.name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -a list chain %s %s %s: %w: %s", chain.family, chain.table, chain.name, err, strings.TrimSpace(string(out)))
	}
	for _, handle := range ruleHandlesWithComment(out, prefix) {
		if err := runNFT("delete", "rule", chain.family, chain.table, chain.name, "handle", handle); err != nil {
			return err
		}
	}
	return nil
}

func ruleHandlesWithComment(data []byte, prefix string) []string {
	handles := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, prefix) {
			continue
		}
		before, handle, ok := strings.Cut(line, "# handle ")
		if !ok || strings.TrimSpace(before) == "" {
			continue
		}
		fields := strings.Fields(handle)
		if len(fields) == 0 {
			continue
		}
		handles = append(handles, fields[0])
	}
	return handles
}

func quote(s string) string { return fmt.Sprintf("%q", s) }

func runNFT(args ...string) error {
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
