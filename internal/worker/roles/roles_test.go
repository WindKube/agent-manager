package roles_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/outbox"
	"agent-manager/internal/worker"
	"agent-manager/internal/worker/roles"
)

func TestTheRegistryIsTheOnlyPlaceARoleIsNamed(t *testing.T) {
	require.Equal(t, len(roles.Definitions()), len(roles.Names()))
	require.NotEmpty(t, roles.Definitions(), "the registry ships with at least the fetcher")

	for _, def := range roles.Definitions() {
		found, err := roles.Lookup(def.Name)
		require.NoError(t, err)
		require.Equal(t, def.Name, found.Name)
	}

	_, err := roles.Lookup("no-such-worker")
	require.Error(t, err)
	require.Contains(t, err.Error(), `unknown worker "no-such-worker"`)

	var out strings.Builder
	require.NoError(t, roles.List(&out))
	for _, name := range roles.Names() {
		require.Contains(t, out.String(), name)
	}
}

// worker.Build hands out a blob.Writer only for AccessReadWrite, so this
// declaration is the whole mechanism keeping bundle writes in the fetcher.
func TestTheFetcherIsRegisteredAsTheOnlyRoleThatMayWriteBundleBytes(t *testing.T) {
	found, err := roles.Lookup("fetcher")
	require.NoError(t, err)

	require.Equal(t, worker.Needs{
		DB:       worker.AccessReadWrite,
		Blob:     worker.AccessReadWrite,
		Outbound: true,
	}, found.Needs)
	require.Equal(t, map[string]int{outbox.QueueFetch: 4}, found.Queues)
	require.NotNil(t, found.Register)

	for _, def := range roles.Definitions() {
		if def.Name == "fetcher" {
			continue
		}
		require.NotEqual(t, worker.AccessReadWrite, def.Needs.Blob,
			"role %q declares Blob: AccessReadWrite, which hands it a blob.Writer", def.Name)
	}
}

func TestTheNotifierReachesTheNetworkButHoldsNoObjectStoreCredential(t *testing.T) {
	found, err := roles.Lookup("notifier")
	require.NoError(t, err)

	require.Equal(t, worker.Needs{
		DB:       worker.AccessReadWrite,
		Blob:     worker.AccessNone,
		Outbound: true,
	}, found.Needs)
	require.Contains(t, found.Queues, outbox.QueueNotify)
	require.NotNil(t, found.Register)
	require.NotNil(t, found.Periodic)
}
