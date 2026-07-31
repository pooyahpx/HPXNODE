package ikev2

import (
	"slices"
	"sync"

	"github.com/pooyahpx/HPXNODE/common"
)

// userEntry is the authorization record for one user (keyed by username = user id).
type userEntry struct {
	password   string
	ipLimit    uint32 // max simultaneous IKE SAs; 0 = unlimited
	speedLimit uint32 // per-direction throughput cap kbit/s; 0 = unlimited
}

// userStore holds the desired EAP credentials for this backend's inbound. The
// backend reconciles this set into charon via VICI (load-shared/unload-shared).
type userStore struct {
	inboundTag string
	mu         sync.RWMutex
	users      map[string]userEntry
}

func newUserStore(inboundTag string) *userStore {
	return &userStore{inboundTag: inboundTag, users: make(map[string]userEntry)}
}

// wantsInterface reports whether a synced user belongs to this backend's inbound
// and carries IKEv2 credentials.
func (s *userStore) wantsInterface(u *common.User) bool {
	ik := u.GetProxies().GetIkev2()
	if ik == nil || ik.GetUsername() == "" || ik.GetPassword() == "" {
		return false
	}
	return slices.Contains(u.GetInbounds(), s.inboundTag)
}

// applyUser upserts or removes a single user. Returns the username plus whether
// the credential changed and whether the user was removed, so the caller can
// reconcile charon.
func (s *userStore) applyUser(u *common.User) (username string, changed bool, removed bool) {
	if !s.wantsInterface(u) {
		// A user we do not want: drop it if present (email = user id).
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

	ik := u.GetProxies().GetIkev2()
	username = ik.GetUsername()
	entry := userEntry{password: ik.GetPassword(), ipLimit: u.GetIpLimit(), speedLimit: u.GetSpeedLimit()}

	s.mu.Lock()
	prev, existed := s.users[username]
	s.users[username] = entry
	s.mu.Unlock()
	return username, !existed || prev != entry, false
}

// replaceAll rebuilds the store from an authoritative user list and returns the
// usernames that are no longer present (so their charon creds/SAs can be removed).
func (s *userStore) replaceAll(users []*common.User) (removed []string) {
	next := make(map[string]userEntry)
	for _, u := range users {
		if !s.wantsInterface(u) {
			continue
		}
		ik := u.GetProxies().GetIkev2()
		next[ik.GetUsername()] = userEntry{password: ik.GetPassword(), ipLimit: u.GetIpLimit(), speedLimit: u.GetSpeedLimit()}
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

// snapshot returns a copy of the desired credentials.
func (s *userStore) snapshot() map[string]userEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]userEntry, len(s.users))
	for k, v := range s.users {
		out[k] = v
	}
	return out
}

// limitFor returns the device limit for a user (0 = unlimited).
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

// speedLimitFor returns the per-direction cap for a user (0 = unlimited).
func (s *userStore) speedLimitFor(username string) uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[username].speedLimit
}

func (s *userStore) usernames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.users))
	for k := range s.users {
		names = append(names, k)
	}
	return names
}
