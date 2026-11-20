package cmd

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/credentials"
	"github.com/WindKube/agent-manager/cli/internal/output"
)

func withEnvToken(env *syncEnv, token string) {
	env.deps.lookupEnv = func(name string) (string, bool) {
		if name == credentials.TokenEnvVar {
			return token, true
		}
		return "", false
	}
}

func TestAServiceTokenInTheEnvironmentSyncsItsProfileAndIsNeverWritten(t *testing.T) {
	tg := startSyncFake(t)
	token, err := tg.Control.MintServiceToken(tg.Fixtures.Profile)
	require.NoError(t, err)
	env := newSyncEnv(t, tg)
	withEnvToken(env, token)

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)

	reports, err := tg.Control.SyncReports()
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Equal(t, tg.Fixtures.Profile, reports[0].Profile)

	require.NoError(t, filepath.WalkDir(env.home, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return err
		}
		body, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		require.False(t, bytes.Contains(body, []byte(token)), "%s holds the service token", path)
		return nil
	}))
}

func TestAServiceTokenScopedToAnotherProfileIsRefusedNamingTheScope(t *testing.T) {
	tg := startSyncFake(t)
	token, err := tg.Control.MintServiceToken(tg.Fixtures.BothTargets)
	require.NoError(t, err)
	env := newSyncEnv(t, tg)
	withEnvToken(env, token)

	code, _, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.True(t, IsRefusal(err))
	require.Equal(t, CodeRefused, code)
	require.ErrorContains(t, err, "not scoped")
	require.ErrorContains(t, err, "sync:profile/"+tg.Fixtures.Profile)
	require.ErrorContains(t, err, credentials.TokenEnvVar)
	require.NoDirExists(t, env.skillsRoot(), "nothing is installed")
}

func TestARevokedServiceTokenIsNamedAsSuch(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	withEnvToken(env, "amst_not-a-token-this-hub-issued")

	_, _, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.True(t, IsRefusal(err))
	require.ErrorContains(t, err, "expired, revoked or unknown")
}
