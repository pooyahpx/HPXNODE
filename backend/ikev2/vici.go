package ikev2

import (
	"fmt"

	"github.com/strongswan/govici/vici"
)

// --- load-conn config structs (marshaled to VICI messages) ---

type childConf struct {
	ESPProposals []string `vici:"esp_proposals"`
	LocalTS      []string `vici:"local_ts"`
	RekeyTime    string   `vici:"rekey_time"`
	DPDAction    string   `vici:"dpd_action"`
}

type localAuth struct {
	Auth  string   `vici:"auth"`
	Certs []string `vici:"certs"`
	ID    string   `vici:"id"`
}

type remoteAuth struct {
	Auth  string `vici:"auth"`
	EAPID string `vici:"eap_id"`
}

type connConf struct {
	Version     int                  `vici:"version"`
	Proposals   []string             `vici:"proposals"`
	Encap       string               `vici:"encap"`
	DPDDelay    string               `vici:"dpd_delay"`
	Pools       []string             `vici:"pools"`
	SendCertReq string               `vici:"send_certreq"`
	Local       localAuth            `vici:"local"`
	Remote      remoteAuth           `vici:"remote"`
	Children    map[string]childConf `vici:"children"`
}

type poolConf struct {
	Addrs string   `vici:"addrs"`
	DNS   []string `vici:"dns"`
}

// viciSession wraps a govici session with the operations the backend needs.
type viciSession struct {
	sock string
}

func newViciSession(sock string) *viciSession { return &viciSession{sock: sock} }

func (v *viciSession) open() (*vici.Session, error) {
	return vici.NewSession(vici.WithSocketPath(v.sock))
}

func (v *viciSession) command(cmd string, msg *vici.Message) error {
	s, err := v.open()
	if err != nil {
		return err
	}
	defer s.Close()
	resp, err := s.CommandRequest(cmd, msg)
	if err != nil {
		return err
	}
	if resp != nil && resp.Get("success") == "no" {
		return fmt.Errorf("%s failed: %v", cmd, resp.Get("errmsg"))
	}
	return nil
}

// loadCert loads a PEM certificate (type "x509"). flag is "" or "ca".
func (v *viciSession) loadCert(pem, flag string) error {
	msg := vici.NewMessage()
	_ = msg.Set("type", "x509")
	if flag != "" {
		_ = msg.Set("flag", flag)
	}
	_ = msg.Set("data", pem)
	return v.command("load-cert", msg)
}

// loadKey loads a PEM private key (type "any").
func (v *viciSession) loadKey(pem string) error {
	msg := vici.NewMessage()
	_ = msg.Set("type", "any")
	_ = msg.Set("data", pem)
	return v.command("load-key", msg)
}

// loadPool loads an address pool for client virtual IPs.
func (v *viciSession) loadPool(name string, conf poolConf) error {
	sub, err := vici.MarshalMessage(conf)
	if err != nil {
		return err
	}
	msg := vici.NewMessage()
	_ = msg.Set(name, sub)
	return v.command("load-pool", msg)
}

// loadConn loads (or replaces) the named IKEv2 connection.
func (v *viciSession) loadConn(name string, conf connConf) error {
	sub, err := vici.MarshalMessage(conf)
	if err != nil {
		return err
	}
	msg := vici.NewMessage()
	_ = msg.Set(name, sub)
	return v.command("load-conn", msg)
}

// loadSharedEAP loads an EAP secret owned by username with the given password.
func (v *viciSession) loadSharedEAP(id, username, password string) error {
	msg := vici.NewMessage()
	_ = msg.Set("id", id)
	_ = msg.Set("type", "eap")
	_ = msg.Set("owners", []string{username})
	_ = msg.Set("data", password)
	return v.command("load-shared", msg)
}

func (v *viciSession) unloadShared(id string) error {
	msg := vici.NewMessage()
	_ = msg.Set("id", id)
	return v.command("unload-shared", msg)
}

// terminate closes IKE SAs matching the given IKE connection child/name by ike id.
func (v *viciSession) terminateIKE(ikeID uint32) error {
	msg := vici.NewMessage()
	_ = msg.Set("ike-id", fmt.Sprintf("%d", ikeID))
	return v.command("terminate", msg)
}

// saInfo is one active IKE SA relevant to accounting/limits.
type saInfo struct {
	IKEID      uint32
	Identity   string   // remote EAP identity = username
	Remote     string   // remote host (client IP)
	VirtualIPs []string // addresses assigned to the client from the pool
	BytesIn    int64
	BytesOut   int64
}

// listSAs streams active IKE SAs and returns per-SA accounting info.
func (v *viciSession) listSAs() ([]saInfo, error) {
	s, err := v.open()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	messages, err := s.StreamedCommandRequest("list-sas", "list-sa", vici.NewMessage())
	if err != nil {
		return nil, err
	}

	var out []saInfo
	for _, m := range messages {
		for _, connName := range m.Keys() {
			ike, ok := m.Get(connName).(*vici.Message)
			if !ok {
				continue
			}
			info := saInfo{
				Identity: msgString(ike, "remote-eap-id"),
				Remote:   msgString(ike, "remote-host"),
				IKEID:    uint32(parseInt64(msgString(ike, "uniqueid"))),
			}
			// EAP-MSCHAPv2 SAs frequently omit remote-eap-id; the client sends its
			// username (= user id) as the IKE identity instead, so fall back to
			// remote-id. Without this the SA is dropped and the user shows no
			// online IP and escapes the device limit.
			if info.Identity == "" {
				info.Identity = msgString(ike, "remote-id")
			}
			info.VirtualIPs = msgStringList(ike, "remote-vips")
			// Sum child SA byte counters.
			if childs, ok := ike.Get("child-sas").(*vici.Message); ok {
				for _, ck := range childs.Keys() {
					if cm, ok := childs.Get(ck).(*vici.Message); ok {
						info.BytesIn += parseInt64(msgString(cm, "bytes-in"))
						info.BytesOut += parseInt64(msgString(cm, "bytes-out"))
					}
				}
			}
			if info.Identity != "" {
				out = append(out, info)
			}
		}
	}
	return out, nil
}

func msgString(m *vici.Message, key string) string {
	if v, ok := m.Get(key).(string); ok {
		return v
	}
	return ""
}

// msgStringList reads a vici list value (e.g. remote-vips) as []string. vici
// decodes lists as []string, but a single value can arrive as a bare string.
func msgStringList(m *vici.Message, key string) []string {
	switch v := m.Get(key).(type) {
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}

func parseInt64(s string) int64 {
	var n int64
	_, _ = fmt.Sscan(s, &n)
	return n
}
