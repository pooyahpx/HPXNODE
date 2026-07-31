package l2tp

import (
	"slices"
	"sync"

	"github.com/pooyahpx/HPXNODE/common"
)

// L2TP authenticates PPP clients with username/password (CHAP). Those are the
// same credentials the IKEv2 backend uses, so v1 reuses the user's IKEv2 proxy
// (GetIkev2) rather than introducing a second identical proxy message in the
// protocol. A user is an L2TP user when they carry those credentials and belong
// to this backend's inbound tag.

type userEntry struct {
	password   string
	ipLimit    uint32 // max simultaneous client IPs; 0 = unlimited
	speedLimit uint32 // per-direction throughput cap kbit/s; 0 = unlimited
}

type userStore struct {
	inboundTag string
	mu         sync.RWMutex
	users      map[string]userEntry
}

func newUserStore(inboundTag string) *userStore {
	return &userStore{inboundTag: inboundTag, users: make(map[string]userEntry)}
}

func credsFor(u *common.User) (username, password string, ok bool) {
	ik := u.GetProxies().GetIkev2()
	if ik == nil || ik.GetUsername() == "" || ik.GetPassword() == "" {
		return "", "", false
	}
	return ik.GetUsername(), ik.GetPassword(), true
}

func (s *userStore) wantsInterface(u *common.User) bool {
	if _, _, ok := credsFor(u); !ok {
		return false
	}
	return slices.Contains(u.GetInbounds(), s.inboundTag)
}

// replaceAll rebuilds the store from an authoritative user list and returns the
// usernames no longer present (so their chap-secrets entries can be removed).
func (s *userStore) replaceAll(users []*common.User) (removed []string) {
	next := make(map[string]userEntry)
	for _, u := range users {
		if !s.wantsInterface(u) {
			continue
		}
		username, password, _ := credsFor(u)
		next[username] = userEntry{password: password, ipLimit: u.GetIpLimit(), speedLimit: u.GetSpeedLimit()}
	}

	s.mu.Lock()
	for username := range s.users {
		if _, ok := next[username]; !ok {
			removed = append(removed, username)
		}
	}
	s.users = next
	s.mu.Unlock()
	return removed
}

func (s *userStore) applyUser(u *common.User) (username string, changed bool, removed bool) {
	if !s.wantsInterface(u) {
		username = u.GetEmail()
		if username == "" {
			return "", false, false
		}
		s.mu.Lock()
		_, existed := s.users[username]
		delete(s.users, username)
		s.mu.Unlock()
		return username, false, existed
	}
	username, password, _ := credsFor(u)
	entry := userEntry{password: password, ipLimit: u.GetIpLimit(), speedLimit: u.GetSpeedLimit()}
	s.mu.Lock()
	prev, existed := s.users[username]
	s.users[username] = entry
	s.mu.Unlock()
	return username, !existed || prev != entry, false
}

func (s *userStore) snapshot() map[string]userEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]userEntry, len(s.users))
	for k, v := range s.users {
		out[k] = v
	}
	return out
}

func (s *userStore) limitFor(username string) uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[username].ipLimit
}

// limitKnown returns the user's device limit and whether this backend serves the
// user at all, so the cross-protocol limiter can skip users it does not own.
func (s *userStore) limitKnown(username string) (uint32, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.users[username]
	return e.ipLimit, ok
}

func (s *userStore) speedLimitFor(username string) uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[username].speedLimit
}
