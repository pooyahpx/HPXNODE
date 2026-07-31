//go:build linux

package ratelimit

import (
	"fmt"
	"os/exec"
	"strings"
)

// defaultNFT runs the real nft binary in production.
var defaultNFT = func(args ...string) error {
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
