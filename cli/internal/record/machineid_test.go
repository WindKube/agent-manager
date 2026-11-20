package record_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

func TestAMachineIDIsGeneratedOnceAndKept(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hub")

	first, err := record.LoadMachineID(dir)
	require.NoError(t, err)
	again, err := record.LoadMachineID(dir)
	require.NoError(t, err)
	require.Equal(t, first, again)

	info, err := os.Stat(filepath.Join(dir, record.MachineIDFileName))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	require.NoError(t, os.WriteFile(filepath.Join(dir, record.MachineIDFileName), []byte("not a uuid\n"), 0o600))
	replaced, err := record.LoadMachineID(dir)
	require.NoError(t, err)
	require.NotEqual(t, first, replaced, "an unreadable id is replaced, not reported")
	kept, err := record.LoadMachineID(dir)
	require.NoError(t, err)
	require.Equal(t, replaced, kept)
}
