//go:build linux

package hostroute

import "testing"

// Docker's FORWARD chain is the one we must land rules in; make sure we pick it
// (and any other forward base chain) out of a real-shaped nft ruleset, and skip
// non-forward hooks.
func TestParseForwardBaseChains(t *testing.T) {
	data := []byte(`{"nftables":[
      {"metainfo":{"version":"1.0.6"}},
      {"table":{"family":"ip","name":"filter"}},
      {"chain":{"family":"ip","table":"filter","name":"FORWARD","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
      {"chain":{"family":"ip","table":"filter","name":"INPUT","handle":1,"type":"filter","hook":"input","prio":0,"policy":"accept"}},
      {"chain":{"family":"ip","table":"filter","name":"DOCKER-USER","handle":5}},
      {"chain":{"family":"inet","table":"fw","name":"forward","handle":3,"type":"filter","hook":"forward","prio":0,"policy":"accept"}},
      {"chain":{"family":"bridge","table":"br","name":"fwd","handle":9,"type":"filter","hook":"forward","prio":0}},
      {"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":7}}
    ]}`)

	chains, err := parseForwardBaseChains(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(chains) != 2 {
		t.Fatalf("want 2 forward base chains (ip/filter/FORWARD, inet/fw/forward), got %d: %+v", len(chains), chains)
	}
	if chains[0] != (baseChain{family: "ip", table: "filter", name: "FORWARD"}) {
		t.Errorf("first chain = %+v, want Docker's ip/filter/FORWARD", chains[0])
	}
	if chains[1] != (baseChain{family: "inet", table: "fw", name: "forward"}) {
		t.Errorf("second chain = %+v", chains[1])
	}
}

// A regular (non-base) chain has no hook and must never be touched.
func TestParseForwardBaseChainsSkipsNonBase(t *testing.T) {
	data := []byte(`{"nftables":[{"chain":{"family":"ip","table":"filter","name":"DOCKER","handle":4}}]}`)
	chains, err := parseForwardBaseChains(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(chains) != 0 {
		t.Fatalf("want no chains, got %+v", chains)
	}
}

// Cleanup keys off the owner comment, so only our own rules' handles come back.
func TestRuleHandlesWithComment(t *testing.T) {
	listing := []byte(`table ip filter {
	chain FORWARD {
		type filter hook forward priority filter; policy drop;
		ip saddr 10.30.0.0/24 accept comment "HPX_NODE_fwd owner=ikev2_10_30_0_0_24 type=forward subnet=10.30.0.0/24 direction=outbound" # handle 12
		ip daddr 10.30.0.0/24 ct state established,related accept comment "HPX_NODE_fwd owner=ikev2_10_30_0_0_24 type=forward subnet=10.30.0.0/24 direction=return" # handle 13
		iifname "wg-main" oifname "eth0" accept comment "HPX_NODE_wg owner=wg-main_1 type=forward" # handle 14
		counter packets 1 bytes 2 jump DOCKER-USER # handle 15
	}
}`)

	got := ruleHandlesWithComment(listing, ownerComment("ikev2_10_30_0_0_24"))
	if len(got) != 2 || got[0] != "12" || got[1] != "13" {
		t.Fatalf("want handles [12 13] for our owner only, got %v", got)
	}

	// A different owner (wireguard's rules) must not be collected.
	if h := ruleHandlesWithComment(listing, ownerComment("someone-else")); len(h) != 0 {
		t.Fatalf("want no handles for a foreign owner, got %v", h)
	}
}

func TestRuleCommentAndOwnerRoundTrip(t *testing.T) {
	c := ruleComment("ikev2_10_30_0_0_24", "10.30.0.0/24", true)
	if want := ownerComment("ikev2_10_30_0_0_24"); !contains(c, want) {
		t.Fatalf("comment %q must start with owner prefix %q so cleanup can find it", c, want)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && s[:len(sub)] == sub
}
