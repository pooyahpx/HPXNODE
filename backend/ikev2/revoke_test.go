package ikev2

import (
	"testing"

	"github.com/pooyahpx/HPXNODE/common"
)

func ikeUser(id, username, password string, inbounds []string) *common.User {
	return &common.User{
		Email:    id,
		Inbounds: inbounds,
		Proxies: &common.Proxy{
			Ikev2: &common.Ikev2{Username: username, Password: password},
		},
	}
}

// The whole bug was that this signal existed and nobody read it: a user who is
// no longer wanted must come back as removed, carrying the username whose SAs
// and EAP secret have to go.
func TestApplyUserReportsRemoval(t *testing.T) {
	s := newUserStore("ikev2-main")

	username, changed, removed := s.applyUser(ikeUser("2", "2", "pw", []string{"ikev2-main"}))
	if username != "2" || !changed || removed {
		t.Fatalf("adding: got (%q, changed=%v, removed=%v), want (\"2\", true, false)", username, changed, removed)
	}

	// Panel serialises a disabled/expired user with no inbounds.
	username, _, removed = s.applyUser(ikeUser("2", "2", "pw", nil))
	if !removed {
		t.Fatal("dropping a user out of the inbound must report removed=true")
	}
	if username != "2" {
		t.Fatalf("removal must name the user to revoke, got %q", username)
	}
	if _, ok := s.snapshot()["2"]; ok {
		t.Fatal("user must be gone from the store, so writeSwanctl stops emitting the secret")
	}
}

// Removing a user we never had must not be reported as a removal, or every
// unrelated sync would fire pointless terminate/unload calls.
func TestApplyUserUnknownUserIsNotARemoval(t *testing.T) {
	s := newUserStore("ikev2-main")
	if _, _, removed := s.applyUser(ikeUser("9", "9", "pw", nil)); removed {
		t.Fatal("removing an unknown user must report removed=false")
	}
}

// A user missing IKEv2 credentials isn't ours; treating it as a removal would be
// harmless but noisy, and it must never linger in the store.
func TestApplyUserWithoutCredentialsIsNotWanted(t *testing.T) {
	s := newUserStore("ikev2-main")
	u := &common.User{Email: "3", Inbounds: []string{"ikev2-main"}, Proxies: &common.Proxy{}}
	if _, _, _ = s.applyUser(u); len(s.snapshot()) != 0 {
		t.Fatal("a user without ikev2 creds must not be stored")
	}
}

// replaceAll drives the bulk path (SyncUsers); it must name everyone who fell
// out of the authoritative list.
func TestReplaceAllReportsRemoved(t *testing.T) {
	s := newUserStore("ikev2-main")
	s.applyUser(ikeUser("1", "1", "pw", []string{"ikev2-main"}))
	s.applyUser(ikeUser("2", "2", "pw", []string{"ikev2-main"}))
	s.applyUser(ikeUser("3", "3", "pw", []string{"ikev2-main"}))

	// Only user 2 survives the resync.
	removed := s.replaceAll([]*common.User{ikeUser("2", "2", "pw", []string{"ikev2-main"})})

	if len(removed) != 2 {
		t.Fatalf("want 2 removed users, got %v", removed)
	}
	got := map[string]bool{removed[0]: true, removed[1]: true}
	if !got["1"] || !got["3"] {
		t.Fatalf("want users 1 and 3 revoked, got %v", removed)
	}
	if _, ok := s.snapshot()["2"]; !ok {
		t.Fatal("user 2 must still be authorized")
	}
	if len(s.snapshot()) != 1 {
		t.Fatalf("store must hold only the surviving user, got %v", s.snapshot())
	}
}

// unload-shared keys off the section name writeSwanctl emits; if these drift the
// secret silently survives the reload and a revoked user can log back in.
func TestEapSecretIDMatchesSwanctlSectionName(t *testing.T) {
	if got, want := eapSecretID("2"), "eap-2"; got != want {
		t.Fatalf("eapSecretID(2) = %q, want %q (serverconf writes \"eap-%%s\")", got, want)
	}
}

// revokeUsers is best-effort and runs on every sync — with nothing to do, or no
// vici session yet, it must be a no-op rather than panic.
func TestRevokeUsersNoopWithoutWork(t *testing.T) {
	o := &IKEv2{}
	o.revokeUsers(nil)           // nothing removed
	o.revokeUsers([]string{""})  // empty username
	o.revokeUsers([]string{"2"}) // vici == nil (not started)
}
