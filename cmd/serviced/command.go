package main

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func runCommand(ctx context.Context, name string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		exitCode := 1
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		}
		return stderr.String(), exitCode, err
	}

	return "", 0, nil
}

func cleanANSI(s string) string {
	return ansiRegexp.ReplaceAllString(s, "")
}

var (
	cliSupportMu    sync.Mutex
	cliSupportCache = map[string]bool{}
)

// cliSupports reports whether the node CLI advertises the given subcommand
// (e.g. "update", "core-update", "geofiles") in its help/usage output.
func cliSupports(app, sub string) bool {
	key := app + "\x00" + sub
	cliSupportMu.Lock()
	if v, ok := cliSupportCache[key]; ok {
		cliSupportMu.Unlock()
		return v
	}
	cliSupportMu.Unlock()

	supported := probeCLISubcommand(app, sub)

	cliSupportMu.Lock()
	cliSupportCache[key] = supported
	cliSupportMu.Unlock()
	return supported
}

func probeCLISubcommand(app, sub string) bool {
	if _, err := exec.LookPath(app); err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Prefer -h / --help; fall back to bare invocation (install.sh prints usage).
	for _, args := range [][]string{{"-h"}, {"--help"}, {}} {
		cmd := exec.CommandContext(ctx, app, args...)
		out, _ := cmd.CombinedOutput()
		text := strings.ToLower(string(out))
		if strings.Contains(text, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
