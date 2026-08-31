package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/stretchr/testify/require"
)

// exploding is an Open that fails the test if it is ever called. FR-005's
// "takes precedence" is only worth something if the store is never OPENED, not
// merely never preferred.
func exploding(t *testing.T) func() (*Store, error) {
	t.Helper()
	return func() (*Store, error) {
		t.Errorf("the credential store was opened while %s was set", TokenEnvVar)
		return nil, errors.New("must not be reached")
	}
}

func envLookup(pairs map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := pairs[key]
		return v, ok
	}
}

func TestAnEnvironmentTokenNeverOpensTheStore(t *testing.T) {
	r := Resolver{
		Open:      exploding(t),
		LookupEnv: envLookup(map[string]string{TokenEnvVar: sentinelToken}),
	}
	got, found, err := r.Resolve(hubA)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, SourceEnvironment, got.Source)
	require.Equal(t, TokenEnvVar, got.Location)
	require.Equal(t, sentinelToken, got.Credential.Token)
	require.Equal(t, hubA, got.Credential.Hub)
	require.True(t, got.Credential.FromEnvironment())
	// The environment states no lifetime, and there is nothing in an opaque
	// token to read one out of. Inventing one would refuse a token that works.
	require.True(t, got.Credential.ExpiresAt.IsZero())
	require.False(t, got.Credential.Expired(time.Now()))
}

func TestAnEnvironmentTokenLeavesNoTraceOnDisk(t *testing.T) {
	// The strongest form of the same claim, through the PRODUCTION wiring:
	// opening a store creates <state root>/credentials, so if that directory
	// does not exist afterwards then nothing opened one.
	root := t.TempDir()
	credDir := filepath.Join(root, DirName)
	t.Setenv(TokenEnvVar, sentinelToken)

	r := NewResolver(Options{StateRoot: root, Warnf: func(string, ...any) {
		t.Error("FR-003's fallback warning fired on a machine that supplied a token from the environment")
	}})
	got, found, err := r.Resolve(hubA)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, sentinelToken, got.Credential.Token)

	_, statErr := os.Stat(credDir)
	require.ErrorIs(t, statErr, os.ErrNotExist, "%s must not exist: nothing may open a store when %s is set", credDir, TokenEnvVar)
}

func TestWithoutTheEnvironmentTokenTheStoreIsOpened(t *testing.T) {
	// The negative control for the test above. Without it, an assertion that a
	// directory does not exist proves nothing about whether the store would
	// otherwise have been opened.
	root := t.TempDir()
	credDir := filepath.Join(root, DirName)
	t.Setenv(TokenEnvVar, "")

	r := NewResolver(Options{StateRoot: root})
	_, found, err := r.Resolve(hubA)
	require.NoError(t, err)
	require.False(t, found, "an empty variable is not a token, and nothing is stored yet")
	require.DirExists(t, credDir, "the store must have been opened once the environment supplied nothing")
}

func TestAnEnvironmentTokenBeatsAStoredOne(t *testing.T) {
	root := t.TempDir()
	store, err := Open(Options{StateRoot: root, Backends: []keyring.BackendType{keyring.FileBackend}})
	require.NoError(t, err)
	require.NoError(t, store.Save(Issued(hubA, "stored-token", 3600, time.Now())))

	opens := 0
	r := Resolver{
		Open: func() (*Store, error) { opens++; return store, nil },
		LookupEnv: envLookup(map[string]string{
			TokenEnvVar: sentinelToken,
		}),
	}
	got, found, err := r.Resolve(hubA)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, sentinelToken, got.Credential.Token)
	require.Zero(t, opens)

	// And the stored one is untouched: the environment overrides, it does not
	// overwrite.
	stored, found, err := store.Load(hubA)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "stored-token", stored.Token)
}

func TestResolveFallsBackToTheStore(t *testing.T) {
	root := t.TempDir()
	store, err := Open(Options{StateRoot: root, Backends: []keyring.BackendType{keyring.FileBackend}})
	require.NoError(t, err)

	r := Resolver{
		Open:      func() (*Store, error) { return store, nil },
		LookupEnv: envLookup(nil),
	}

	got, found, err := r.Resolve(hubA)
	require.NoError(t, err)
	require.False(t, found, "no credential is not an error: a machine that never logged in is a valid state")
	require.Equal(t, Resolved{}, got)

	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	require.NoError(t, store.Save(Issued(hubA, sentinelToken, 3600, now)))

	got, found, err = r.Resolve(hubA)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, SourceStore, got.Source)
	require.Equal(t, store.Location(), got.Location)
	require.Equal(t, sentinelToken, got.Credential.Token)
	require.True(t, now.Add(time.Hour).Equal(got.Credential.ExpiresAt))
	require.False(t, got.Credential.FromEnvironment(), "a stored credential is savable; an environment one is not")
}

func TestResolveDoesNotRejectAnExpiredCredential(t *testing.T) {
	// Whose problem an expiry is belongs to the verb: `status` must report it,
	// and `sync` must be able to say "your token expired at X" rather than "no
	// credential". So Resolve returns it and Credential.Expired is how a caller
	// asks.
	root := t.TempDir()
	store, err := Open(Options{StateRoot: root, Backends: []keyring.BackendType{keyring.FileBackend}})
	require.NoError(t, err)
	issued := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	require.NoError(t, store.Save(Issued(hubA, sentinelToken, 60, issued)))

	r := Resolver{Open: func() (*Store, error) { return store, nil }, LookupEnv: envLookup(nil)}
	got, found, err := r.Resolve(hubA)
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, got.Credential.Expired(issued.Add(2*time.Minute)))
}

func TestResolveRefusesWithoutAHubOrAStore(t *testing.T) {
	_, _, err := Resolver{}.Resolve("")
	require.ErrorContains(t, err, "without a hub")

	_, _, err = Resolver{LookupEnv: envLookup(nil)}.Resolve(hubA)
	require.ErrorContains(t, err, TokenEnvVar)
	require.ErrorContains(t, err, "no store")
}

func TestResolvePropagatesAStoreThatWillNotOpen(t *testing.T) {
	boom := errors.New("no credential store on this machine")
	_, _, err := Resolver{
		Open:      func() (*Store, error) { return nil, boom },
		LookupEnv: envLookup(nil),
	}.Resolve(hubA)
	require.ErrorIs(t, err, boom)
}

func TestTokenEnvVarIsTheOneDocumentedName(t *testing.T) {
	// Pinned deliberately. The variable is part of the CLI's contract with CI
	// (SC-006: no TTY, no credential store, a token from the environment), so
	// renaming it silently breaks every pipeline that sets it.
	require.Equal(t, "AMCTL_TOKEN", TokenEnvVar)
}
