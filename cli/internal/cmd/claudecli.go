package cmd

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/deliver"
)

// claudeOnPath runs the claude CLI found on PATH, nil when there is none. Only
// the subcommand and server name reach an error: add-json carries the
// server's env, which may hold secrets.
func claudeOnPath() deliver.ClaudeCLI {
	path, err := exec.LookPath("claude")
	if err != nil {
		return nil
	}
	return func(ctx context.Context, args ...string) error {
		out, err := exec.CommandContext(ctx, path, args...).CombinedOutput() //nolint:gosec // fixed binary, amctl-built arguments
		if err != nil {
			return fmt.Errorf("claude %s: %w: %s", strings.Join(args[:min(3, len(args))], " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}
