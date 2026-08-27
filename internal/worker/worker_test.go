// These tests are container-free: every case here declares Blob and/or Outbound
// and leaves DB at AccessNone, so Build touches memblob and nothing else. The
// database paths are asserted through their failure modes, which is where the
// guarantee lives.
package worker_test

import (
	"context"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/blob"
	"agent-manager/internal/worker"
)

func definition(name string, needs worker.Needs) worker.Definition {
	return worker.Definition{Name: name, Needs: needs}
}

func build(t *testing.T, def worker.Definition, cfg worker.Config) *worker.Built {
	t.Helper()

	built, err := worker.Build(context.Background(), def, cfg, zerolog.Nop())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, built.Close()) })

	return built
}

// ---------------------------------------------------------------------------
// contracts/worker.md — an undeclared capability is nil
// ---------------------------------------------------------------------------

// The scanner's shape. Its BlobWrite must be nil, and — the half a nil check
// alone would miss — the reader it does get must not be assertable to a writer.
// Together those two are what makes the contract's claim that the Go type system
// enforces this boundary true rather than aspirational.
func TestARoleDeclaringBlobReadGetsANilBlobWriteAndNoWriterInScope(t *testing.T) {
	built := build(t,
		definition("scanner-shaped", worker.Needs{Blob: worker.AccessRead}),
		worker.Config{BlobURL: "mem://"})

	require.NotNil(t, built.Deps.BlobRead, "a declared read capability must be constructed")
	require.Nil(t, built.Deps.BlobWrite,
		"a role that did not declare Blob: AccessReadWrite must be handed a nil writer")

	_, isWriter := built.Deps.BlobRead.(blob.Writer)
	require.False(t, isWriter,
		"the reader handed to the role must not satisfy blob.Writer, or a nil BlobWrite is one type assertion from irrelevant")

	// Everything else it did not declare is nil too, not a zero-value stub.
	require.Nil(t, built.Deps.DB)
	require.Nil(t, built.Deps.Fetch)
	require.Nil(t, built.Queue(), "no database access means no queue pool")
}

func TestARoleDeclaringBlobReadWriteGetsBothHalves(t *testing.T) {
	built := build(t,
		definition("fetcher-shaped", worker.Needs{Blob: worker.AccessReadWrite}),
		worker.Config{BlobURL: "mem://"})

	require.NotNil(t, built.Deps.BlobRead)
	require.NotNil(t, built.Deps.BlobWrite, "the fetcher is the one role with object-store write access")

	// The two halves are usable together, which is what the commit-last publisher
	// needs, and they are still separate values.
	committer := blob.NewCommitter(built.Deps.BlobRead, built.Deps.BlobWrite)
	require.NotNil(t, committer)
}

func TestARoleDeclaringNoBlobAccessGetsNeitherHalf(t *testing.T) {
	built := build(t,
		definition("blobless", worker.Needs{}),
		worker.Config{BlobURL: "mem://"})

	require.Nil(t, built.Deps.BlobRead,
		"a bucket URL in the environment must not be enough: the Needs declaration is what decides")
	require.Nil(t, built.Deps.BlobWrite)
}

func TestOutboundIsConstructedOnlyWhenDeclared(t *testing.T) {
	withOutbound := build(t,
		definition("fetcher-shaped", worker.Needs{Outbound: true}),
		worker.Config{})
	require.NotNil(t, withOutbound.Deps.Fetch, "a declared outbound need must produce the SSRF-hardened client")

	without := build(t, definition("scanner-shaped", worker.Needs{}), worker.Config{})
	require.Nil(t, without.Deps.Fetch,
		"the scanner never gets an outbound client: a check that reached the network would not be static analysis")
}

// ---------------------------------------------------------------------------
// contracts/worker.md — a declared credential that is missing fails fast
// ---------------------------------------------------------------------------

// A missing credential must stop the process at startup. The alternative is a
// container that comes up and silently does half its job, which is the failure
// mode nothing ever notices.
func TestBuildFailsFastWhenConfigLacksADeclaredCredential(t *testing.T) {
	for _, tc := range []struct {
		name  string
		needs worker.Needs
		cfg   worker.Config
		want  string
	}{
		{
			name:  "blob declared, no bucket url",
			needs: worker.Needs{Blob: worker.AccessRead},
			cfg:   worker.Config{},
			want:  "AGENT_MANAGER_BLOB_URL is empty",
		},
		{
			name:  "blob write declared, no bucket url",
			needs: worker.Needs{Blob: worker.AccessReadWrite},
			cfg:   worker.Config{},
			want:  "AGENT_MANAGER_BLOB_URL is empty",
		},
		{
			name:  "db declared, no application url",
			needs: worker.Needs{DB: worker.AccessReadWrite},
			cfg:   worker.Config{RiverDatabaseURL: "postgres://u:p@127.0.0.1:5432/river"},
			want:  "AGENT_MANAGER_DATABASE_URL is empty",
		},
		{
			// The queue URL is a separate credential, and a worker that could start
			// without it would be a worker that never works a job.
			name:  "db declared, no queue url",
			needs: worker.Needs{DB: worker.AccessRead},
			cfg:   worker.Config{DatabaseURL: "postgres://u:p@127.0.0.1:5432/agent_manager"},
			want:  "AGENT_MANAGER_RIVER_DATABASE_URL is empty",
		},
		{
			name:  "blob declared with an unusable url",
			needs: worker.Needs{Blob: worker.AccessRead},
			cfg:   worker.Config{BlobURL: "nosuchdriver://bucket"},
			want:  "open bucket",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			built, err := worker.Build(context.Background(), definition("under-test", tc.needs), tc.cfg, zerolog.Nop())
			require.Error(t, err)
			require.Nil(t, built, "a failed Build must hand back nothing partially constructed")
			require.Contains(t, err.Error(), tc.want)
			require.Contains(t, err.Error(), "under-test", "the failure must name the role that declared the need")
		})
	}
}

func TestBuildRejectsANamelessDefinition(t *testing.T) {
	_, err := worker.Build(context.Background(), worker.Definition{}, worker.Config{}, zerolog.Nop())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Principle VII — registry.go is the only file a new role touches
// ---------------------------------------------------------------------------

func TestTheRegistryIsTheOnlyPlaceARoleIsNamed(t *testing.T) {
	// fetcher and scanner arrive with their own layers, so the shipped registry is
	// empty. What must hold now is that the lookup and the listing read the list
	// rather than a second copy of the names.
	require.Equal(t, len(worker.Definitions()), len(worker.Names()))

	for _, def := range worker.Definitions() {
		found, err := worker.Lookup(def.Name)
		require.NoError(t, err)
		require.Equal(t, def.Name, found.Name)
	}

	_, err := worker.Lookup("no-such-worker")
	require.Error(t, err)
	require.Contains(t, err.Error(), `unknown worker "no-such-worker"`)

	var out strings.Builder
	require.NoError(t, worker.List(&out))
	if len(worker.Definitions()) == 0 {
		require.Equal(t, "no workers registered yet\n", out.String())
		return
	}
	for _, name := range worker.Names() {
		require.Contains(t, out.String(), name)
	}
}

func TestRunRefusesADefinitionThatCouldNeverWorkAJob(t *testing.T) {
	// Both of these are startup failures rather than a process that idles forever
	// looking busy.
	err := worker.Run(context.Background(), definition("queueless", worker.Needs{}), worker.Config{})
	require.ErrorContains(t, err, "declares no queues")

	err = worker.Run(context.Background(),
		worker.Definition{Name: "dbless", Queues: map[string]int{"default": 1}},
		worker.Config{})
	require.ErrorContains(t, err, "no queue pool")
}

func TestAccessNamesItself(t *testing.T) {
	for _, tc := range []struct {
		access worker.Access
		want   string
	}{
		{worker.AccessNone, "none"},
		{worker.AccessRead, "read"},
		{worker.AccessReadWrite, "read-write"},
		{worker.Access(42), "unknown"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			require.Equal(t, tc.want, tc.access.String())
		})
	}
}
