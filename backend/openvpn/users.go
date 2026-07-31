package openvpn

import (
	"slices"
	"sync"

	"github.com/pooyahpx/HPXNODE/common"
)

// userEntry is the authorization record for one user (keyed by common name = user id).
type userEntry struct {
	serial      string
	fingerprint string
	ipLimit     uint32 // max simultaneous sessions; 0 = unlimited
	speedLimit  uint32 // per-direction throughput cap kbit/s; 0 = unlimited
}

// speedLimitFor returns the per-direction cap for a common name (0 = unlimited).
func (s *userStore) speedLimitFor(commonName string) uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[commonName].speedLimit
}

// userStore is the authorized-user allowlist consulted by the management client.
// Membership is positive: a common name absent from the map is denied.
type userStore struct {
	inboundTag string
	mu         sync.RWMutex
	users      map[string]userEntry
	// sessions tracks the live client IDs per common name so the device limit
	// can be enforced at connect time.
	sessions map[string]map[string]struct{}
}

func newUserStore(inboundTag string) *userStore {
	return &userStore{
		inboundTag: inboundTag,
		users:      make(map[string]userEntry),
		sessions:   make(map[string]map[string]struct{}),
	}
}

// authorize implements authDecider: the CN must be present and, when a serial
// is pinned, must match the connecting certificate's serial.
func (s *userStore) authorize(commonName, serial string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authorizedLocked(commonName, serial)
}

func (s *userStore) authorizedLocked(commonName, serial string) bool {
	entry, ok := s.users[commonName]
	if !ok {
		return false
	}
	if entry.serial != "" && entry.serial != serial {
		return false
	}
	return true
}

// tryConnect authorizes a connecting session and enforces the per-user device
// limit. It returns allowed=false with a reason for an over-limit or unknown
// user. A session id already counted (REAUTH of the same client) is idempotent.
func (s *userStore) tryConnect(commonName, serial, clientID string) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.authorizedLocked(commonName, serial) {
		return false, "unauthorized"
	}
	set := s.sessions[commonName]
	if set == nil {
		set = make(map[string]struct{})
		s.sessions[commonName] = set
	}
	if _, exists := set[clientID]; exists {
		return true, "" // REAUTH of a session we already count
	}
	limit := s.users[commonName].ipLimit
	if limit > 0 && uint32(len(set)) >= limit {
		return false, "device limit reached"
	}
	set[clientID] = struct{}{}
	return true, ""
}

// excessSessions returns live session client ids that exceed the user's device
// limit, removing them from the tracked set so the caller can kill them. This
// enforces the limit retroactively — e.g. when it is lowered while the user is
// already connected on more devices than allowed.
func (s *userStore) excessSessions(commonName string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.users[commonName]
	if !ok || entry.ipLimit == 0 {
		return nil
	}
	set := s.sessions[commonName]
	if uint32(len(set)) <= entry.ipLimit {
		return nil
	}
	var excess []string
	var kept uint32
	for cid := range set {
		if kept < entry.ipLimit {
			kept++
			continue
		}
		excess = append(excess, cid)
	}
	for _, cid := range excess {
		delete(set, cid)
	}
	if len(s.sessions[commonName]) == 0 {
		delete(s.sessions, commonName)
	}
	return excess
}

// releaseSession drops a client id from the live-session set (on disconnect).
func (s *userStore) releaseSession(commonName, clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if set := s.sessions[commonName]; set != nil {
		delete(set, clientID)
		if len(set) == 0 {
			delete(s.sessions, commonName)
		}
	}
}

// wantsInterface reports whether a synced user belongs to this backend's inbound.
func (s *userStore) wantsInterface(u *common.User) bool {
	if u.GetProxies().GetOpenvpn() == nil {
		return false
	}
	return slices.Contains(u.GetInbounds(), s.inboundTag)
}

// upsert adds or updates a user. Returns (changedSerial, removed) so the caller
// can decide whether to kill an existing session.
func (s *userStore) applyUser(u *common.User) (cn string, changedSerial bool, removed bool) {
	cn = u.GetEmail()
	if cn == "" {
		return "", false, false
	}

	if !s.wantsInterface(u) {
		s.mu.Lock()
		_, existed := s.users[cn]
		delete(s.users, cn)
		delete(s.sessions, cn)
		s.mu.Unlock()
		return cn, false, existed
	}

	ov := u.GetProxies().GetOpenvpn()
	entry := userEntry{serial: ov.GetSerial(), fingerprint: ov.GetFingerprint(), ipLimit: u.GetIpLimit(), speedLimit: u.GetSpeedLimit()}

	s.mu.Lock()
	prev, existed := s.users[cn]
	s.users[cn] = entry
	s.mu.Unlock()

	return cn, existed && prev.serial != entry.serial, false
}

// replaceAll rebuilds the store from an authoritative user list and returns the
// set of common names that are no longer present (so their sessions can be killed).
func (s *userStore) replaceAll(users []*common.User) (removed []string) {
	next := make(map[string]userEntry)
	for _, u := range users {
		if !s.wantsInterface(u) {
			continue
		}
		cn := u.GetEmail()
		if cn == "" {
			continue
		}
		ov := u.GetProxies().GetOpenvpn()
		next[cn] = userEntry{serial: ov.GetSerial(), fingerprint: ov.GetFingerprint(), ipLimit: u.GetIpLimit(), speedLimit: u.GetSpeedLimit()}
	}

	s.mu.Lock()
	for cn := range s.users {
		if _, ok := next[cn]; !ok {
			removed = append(removed, cn)
			delete(s.sessions, cn)
		}
	}
	s.users = next
	s.mu.Unlock()
	return removed
}

func (s *userStore) commonNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.users))
	for cn := range s.users {
		names = append(names, cn)
	}
	return names
}

func (s *userStore) has(commonName string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.users[commonName]
	return ok
}
