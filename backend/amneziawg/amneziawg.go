package amneziawg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pooyahpx/HPXNODE/backend/wireguard"
	"github.com/pooyahpx/HPXNODE/common"
	"github.com/pooyahpx/HPXNODE/config"
)

// Config extends wireguard config with Amnezia obfuscation parameters.
type Config struct {
	wireguard.Config
	JC   int `json:"jc,omitempty"`
	JMin int `json:"jmin,omitempty"`
	JMax int `json:"jmax,omitempty"`
	S1   int `json:"s1,omitempty"`
	S2   int `json:"s2,omitempty"`
	H1   int `json:"h1,omitempty"`
	H2   int `json:"h2,omitempty"`
	H3   int `json:"h3,omitempty"`
	H4   int `json:"h4,omitempty"`
}

func NewConfig(configStr string) (*Config, error) {
	if strings.TrimSpace(configStr) == "" {
		return nil, fmt.Errorf("amneziawg config string must not be empty")
	}
	cfg := &Config{}
	if err := json.Unmarshal([]byte(configStr), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse amneziawg config: %w", err)
	}
	// Re-parse via wireguard.NewConfig for key validation/defaults.
	wgCfg, err := wireguard.NewConfig(configStr)
	if err != nil {
		return nil, err
	}
	cfg.Config = *wgCfg
	cfg.ProxyField = "amneziawg"
	return cfg, nil
}

func CheckDeps() error {
	if _, err := exec.LookPath("awg"); err == nil {
		return nil
	}
	if _, err := exec.LookPath("awg-quick"); err == nil {
		return nil
	}
	return wireguard.CheckDeps()
}

func DetectVersion() string {
	if out, err := exec.Command("awg", "version").CombinedOutput(); err == nil {
		fields := strings.Fields(string(out))
		if len(fields) > 0 {
			return fields[len(fields)-1]
		}
	}
	return wireguard.DetectVersion()
}

func hasAWG() bool {
	if _, err := exec.LookPath("awg"); err == nil {
		return true
	}
	if _, err := exec.LookPath("awg-quick"); err == nil {
		return true
	}
	return false
}

// New starts AmneziaWG. When awg tools are present it writes an amnezia conf
// fragment under the generated path; peer sync always uses the wireguard backend
// with ProxyField=amneziawg (falling back to standard wg netlink when awg is absent).
func New(cfg *config.Config, aConfig *Config, users []*common.User) (*wireguard.WireGuard, error) {
	if aConfig == nil {
		return nil, errors.New("amneziawg config must not be nil")
	}
	aConfig.ProxyField = "amneziawg"
	if hasAWG() {
		if err := writeAmneziaConf(cfg, aConfig); err != nil {
			return nil, err
		}
	}
	return wireguard.New(cfg, &aConfig.Config, users)
}

func writeAmneziaConf(cfg *config.Config, a *Config) error {
	dir := filepath.Join(cfg.GeneratedConfigPath, "amneziawg")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", a.PrivateKey)
	fmt.Fprintf(&b, "ListenPort = %d\n", a.ListenPort)
	for _, addr := range a.Address {
		fmt.Fprintf(&b, "Address = %s\n", addr)
	}
	if a.JC > 0 {
		fmt.Fprintf(&b, "Jc = %d\n", a.JC)
	}
	if a.JMin > 0 {
		fmt.Fprintf(&b, "Jmin = %d\n", a.JMin)
	}
	if a.JMax > 0 {
		fmt.Fprintf(&b, "Jmax = %d\n", a.JMax)
	}
	if a.S1 > 0 {
		fmt.Fprintf(&b, "S1 = %d\n", a.S1)
	}
	if a.S2 > 0 {
		fmt.Fprintf(&b, "S2 = %d\n", a.S2)
	}
	if a.H1 > 0 {
		fmt.Fprintf(&b, "H1 = %d\n", a.H1)
	}
	if a.H2 > 0 {
		fmt.Fprintf(&b, "H2 = %d\n", a.H2)
	}
	if a.H3 > 0 {
		fmt.Fprintf(&b, "H3 = %d\n", a.H3)
	}
	if a.H4 > 0 {
		fmt.Fprintf(&b, "H4 = %d\n", a.H4)
	}
	path := filepath.Join(dir, a.InterfaceName+".conf")
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
