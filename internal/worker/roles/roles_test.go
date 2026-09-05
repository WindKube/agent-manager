package roles_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/outbox"
	"agent-manager/internal/worker"
	"agent-manager/internal/worker/roles"
)

// ---------------------------------------------------------------------------
// Principle VII — the registry is the only file a new role touches
// ---------------------------------------------------------------------------

func TestTheRegistryIsTheOnlyPlaceARoleIsNamed(t *testing.T) {
	// What must hold is that the lookup and the listing read the one list rather
	// than a second copy of the names.
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

// The declaration that makes "only the fetcher may write bundle bytes"
// structural: worker.Build hands out a blob.Writer for AccessReadWrite and for no
// other value, so this line is the whole mechanism (principle II). It is asserted
// through the registry because the registry is what the bootstrap reads.
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
