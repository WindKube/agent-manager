package checks

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLaunchedPackagesAndTheirPins(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		spec     string
		unpinned bool
	}{
		{"npx", []string{"-y", "@acme/mcp"}, "@acme/mcp", true},
		{"npx", []string{"-y", "@acme/mcp@1.2.3"}, "@acme/mcp@1.2.3", false},
		{"npx", []string{"--package=@acme/mcp@^1", "acme-mcp"}, "@acme/mcp@^1", true},
		{"npx", []string{"-y", "pkg@latest"}, "pkg@latest", true},
		{"bunx", []string{"pkg@2.0.0"}, "pkg@2.0.0", false},
		{"pnpm", []string{"dlx", "pkg"}, "pkg", true},
		{"pnpm", []string{"install"}, "", false},
		{"uvx", []string{"--python", "3.12", "mcp-server-git"}, "mcp-server-git", true},
		{"uvx", []string{"mcp-server-git==0.6.2"}, "mcp-server-git==0.6.2", false},
		{"uvx", []string{"--from", "git+https://github.com/acme/x", "x"}, "git+https://github.com/acme/x", true},
		{"pipx", []string{"run", "--spec", "tool==1.0", "tool"}, "tool==1.0", false},
		{"docker", []string{"run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/acme/db"}, "ghcr.io/acme/db", true},
		{"docker", []string{"run", "-i", "localhost:5000/db:latest"}, "localhost:5000/db:latest", true},
		{"docker", []string{"run", "ghcr.io/acme/db:1.4"}, "ghcr.io/acme/db:1.4", false},
		{"docker", []string{"run", "ghcr.io/acme/db@sha256:abc"}, "ghcr.io/acme/db@sha256:abc", false},
		{"docker", []string{"ps"}, "", false},
		{"npx", []string{"$PKG"}, "$PKG", true},
	} {
		spec := launchedPackage(tc.name, tc.args)
		require.Equal(t, tc.spec, spec, "%s %v", tc.name, tc.args)
		if spec != "" {
			require.Equal(t, tc.unpinned, launcherUnpinned(tc.name+" "+spec), "%s %s", tc.name, spec)
		}
	}
}
