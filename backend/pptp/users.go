package pptp

import (
	"slices"
	"sync"

	"github.com/pooyahpx/HPXNODE/common"
)

type userEntry struct {
	password   string
	ipLimit    uint32
	speedLimit uint32
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
	c := u.GetProxies().GetPptp()
	if c == nil || c.GetUsername() == "" || c.GetPassword() == "" {
		return "", "", false
	}
	return c.GetUsername(), c.GetPassword(), true
}

func (s *userStore) wantsInterface(u *common.User) bool {
	if _, _, ok := credsFor(u); !ok {
		return false
	}
	return slices.Contains(u.GetInbounds(), s.inboundTag)
}

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
