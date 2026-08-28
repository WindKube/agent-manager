package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEveryRoleIsASubcommand(t *testing.T) {
	// Principle I: roles are selected at run time by subcommand. If one of these
	// paths disappears, a deployable unit has silently moved to another build.
	paths := [][]string{
		{"serve", "api"},
		{"serve", "web"},
		{"worker", "run"},
		{"migrate", "queue"},
		{"seed"},
		{"healthcheck"},
		{"version"},
	}

	for _, path := range paths {
		cmd, _, err := newRootCmd().Find(path)
		require.NoError(t, err, "path %v", path)
		require.Equal(t, path[len(path)-1], cmd.Name(), "path %v", path)
	}
}

func TestVersionCommandPrints(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"version"})

	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "agent-manager")
}
