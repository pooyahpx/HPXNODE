package openvpn

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// Config is the OpenVPN backend configuration decoded from Backend.config
// (an opaque JSON string produced by the panel's OpenVPNConfig.to_str()).
type Config struct {
	InboundTag   string `json:"inbound_tag"`
	Port         int    `json:"port"`
	Proto        string `json:"proto"`
	Device       string `json:"device"`
	ServerSubnet string `json:"server_subnet"`
	// EgressInterface, if set, routes this subnet out that interface (see egress).
	EgressInterface string   `json:"egress_interface"`
	DNS             []string `json:"dns"`
	Cipher          string   `json:"cipher"`
	DataCiphers     []string `json:"data_ciphers"`
	Auth            string   `json:"auth"`
	Keepalive       string   `json:"keepalive"`
	MaxClients      int      `json:"max_clients"`
	DuplicateCN     bool     `json:"duplicate_cn"`
	Push            []string `json:"push"`
	// ExtraServerDirectives are raw server.conf lines appended verbatim. They
	// let operators tune the server (mssfix, sndbuf, compress, …) without the
	// panel modelling every option. Critical lines (management, status, certs)
	// are always emitted by the node and cannot be overridden from here.
	ExtraServerDirectives []string `json:"extra_server_directives"`
	CACert                string   `json:"ca_cert"`
	ServerCert            string   `json:"server_cert"`
	ServerKey             string   `json:"server_key"`
	TLSCryptKey           string   `json:"tls_crypt_key"`

	// Listeners lets one core serve several endpoints. A single OpenVPN process
	// can only bind one port/protocol, so offering both UDP and TCP means
	// running one server per entry — the node does that from this one config
	// instead of needing a second core. Empty means a single listener built
	// from Port/Proto.
	Listeners []Listener `json:"listeners"`

	workDir string
}

// Listener is one endpoint of an OpenVPN core.
type Listener struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
}

// NewConfig parses the config string and applies defaults.
func NewConfig(configStr string) (*Config, error) {
	cfg := &Config{}
	if strings.TrimSpace(configStr) == "" {
		return nil, fmt.Errorf("openvpn config string must not be empty")
	}
	if err := json.Unmarshal([]byte(configStr), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse openvpn config: %w", err)
	}

	if cfg.InboundTag == "" {
		return nil, fmt.Errorf("inbound_tag is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	if cfg.Proto == "" {
		cfg.Proto = "udp"
	}
	if cfg.Device == "" {
		cfg.Device = "tun"
	}
	if cfg.ServerSubnet == "" {
		return nil, fmt.Errorf("server_subnet is required")
	}
	if cfg.Cipher == "" {
		cfg.Cipher = "AES-256-GCM"
	}
	if cfg.Auth == "" {
		cfg.Auth = "SHA256"
	}
	if cfg.Keepalive == "" {
		cfg.Keepalive = "10 60"
	}
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = 1024
	}
	if cfg.CACert == "" || cfg.ServerCert == "" || cfg.ServerKey == "" {
		return nil, fmt.Errorf("ca_cert, server_cert and server_key are required")
	}

	if err := cfg.normalizeListeners(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// normalizeListeners fills in defaults and rejects endpoints that would clash.
// A config without an explicit list keeps behaving exactly as before: one
// listener on Port/Proto.
func (c *Config) normalizeListeners() error {
	if len(c.Listeners) == 0 {
		c.Listeners = []Listener{{Port: c.Port, Proto: c.Proto}}
		return nil
	}

	seen := make(map[string]struct{}, len(c.Listeners))
	for i := range c.Listeners {
		l := &c.Listeners[i]
		if l.Port == 0 {
			l.Port = c.Port
		}
		if l.Port <= 0 || l.Port > 65535 {
			return fmt.Errorf("listener port must be between 1 and 65535, got %d", l.Port)
		}
		l.Proto = strings.ToLower(strings.TrimSpace(l.Proto))
		if l.Proto == "" {
			l.Proto = c.Proto
		}
		switch l.Proto {
		case "udp", "tcp", "udp4", "udp6", "tcp4", "tcp6":
		default:
			return fmt.Errorf("listener proto must be udp or tcp, got %q", l.Proto)
		}
		key := fmt.Sprintf("%s/%d", l.Proto, l.Port)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("duplicate listener %s", key)
		}
		seen[key] = struct{}{}
	}

	// Port/Proto stay in sync with the first listener so anything still reading
	// them (logs, the single-listener path) sees a consistent value.
	c.Port = c.Listeners[0].Port
	c.Proto = c.Listeners[0].Proto
	return nil
}

func (c *Config) mgmtSocketPath() string {
	return filepath.Join(c.workDir, "mgmt.sock")
}
