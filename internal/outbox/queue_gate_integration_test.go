//go:build integration

package outbox_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/outbox"
)

// With River fully migrated, Atlas diffing the checked-in migrations against the
// live application database must produce nothing. A non-empty diff means River's
// tables landed in `agent_manager` (where Atlas could drop them) or schema drift.
func TestAtlasSeesNothingItDoesNotOwnAfterRiverHasMigrated(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()

	root := repoRoot(t)
	atlasBin := filepath.Join(root, ".bin", "atlas")
	if _, err := os.Stat(atlasBin); err != nil {
		t.Skipf("skipping the R11 gate: %s is absent (run `task atlas:install`)", atlasBin)
	}

	// An unmigrated queue would make this gate pass for the wrong reason.
	requireRiverIsMigrated(t, ctx)

	// `atlas migrate diff` writes to the directory, so work on a copy.
	dir := copyMigrations(t, filepath.Join(root, "internal", "store", "migrations"))
	before := sqlFiles(t, dir)

	cmd := exec.CommandContext(ctx, atlasBin, "migrate", "diff", "r11_gate",
		"--dir", "file://"+dir,
		// Desired state is the live database, not the model loader.
		"--to", withSearchPath(appURL),
		"--dev-url", withSearchPath(atlasDevDB),
	)
	cmd.Dir = root

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "atlas migrate diff failed:\n%s", out)

	after := sqlFiles(t, dir)
	extra := added(before, after)

	if len(extra) > 0 {
		generated, readErr := os.ReadFile(filepath.Join(dir, extra[0]))
		require.NoError(t, readErr)
		t.Fatalf(`atlas migrate diff generated a migration, so the live application database is not what
internal/store/migrations says it is.

The usual cause is that AGENT_MANAGER_DATABASE_URL and AGENT_MANAGER_RIVER_DATABASE_URL
have been collapsed onto one database, which puts River's tables in front of a tool that
can DROP them.

%s:
%s`, extra[0], generated)
	}

	require.Contains(t, string(out), "no changes",
		"atlas reported neither a change nor a synced directory, so this gate did not actually run")
}

func requireRiverIsMigrated(t *testing.T, ctx context.Context) {
	t.Helper()

	// TestMain already migrated, so a second run must apply nothing.
	applied, err := outbox.MigrateQueue(ctx, queueURL, nil)
	require.NoError(t, err)
	require.Empty(t, applied, "the queue database must already be fully migrated")

	var jobTables int
	require.NoError(t, queuePool.QueryRow(ctx,
		`select count(*) from information_schema.tables
		 where table_schema = 'public' and table_name like 'river%'`).Scan(&jobTables))
	require.Positive(t, jobTables, "river migrated nothing into its own database")

	var strays int
	require.NoError(t, appPool.QueryRow(ctx,
		`select count(*) from information_schema.tables
		 where table_schema = 'public' and table_name like 'river%'`).Scan(&strays))
	require.Zero(t, strays, "river tables must not exist in the application database")
}

// withSearchPath scopes Atlas to the public schema; otherwise it compares whole
// databases and the sides differ by name alone.
func withSearchPath(url string) string {
	if strings.Contains(url, "search_path=") {
		return url
	}
	if strings.Contains(url, "?") {
		return url + "&search_path=public"
	}
	return url + "?search_path=public"
}

func repoRoot(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(root, "atlas.hcl"), "the repository root must hold atlas.hcl")

	return root
}

func copyMigrations(t *testing.T, from string) string {
	t.Helper()

	dir := t.TempDir()
	entries, err := os.ReadDir(from)
	require.NoError(t, err)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") && name != "atlas.sum" {
			continue
		}
		content, readErr := os.ReadFile(filepath.Join(from, name))
		require.NoError(t, readErr)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), content, 0o600))
	}

	require.NotEmpty(t, sqlFiles(t, dir), "no migrations were copied")
	require.FileExists(t, filepath.Join(dir, "atlas.sum"))

	return dir
}

func sqlFiles(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var out []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sql") {
			out = append(out, entry.Name())
		}
	}
	return out
}

func added(before, after []string) []string {
	seen := make(map[string]struct{}, len(before))
	for _, name := range before {
		seen[name] = struct{}{}
	}

	var out []string
	for _, name := range after {
		if _, ok := seen[name]; !ok {
			out = append(out, name)
		}
	}
	return out
}
