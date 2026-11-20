package notifier

import (
	"io"
	"testing"

	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/blob"
	"agent-manager/internal/fetch"
	"agent-manager/internal/worker"
)

func TestTheNotifierRefusesDependenciesItDidNotDeclare(t *testing.T) {
	client, err := fetch.New(fetch.Options{})
	require.NoError(t, err)
	bucket, err := blob.Open(t.Context(), "mem://")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bucket.Close()) })

	base := worker.Deps{DB: bun.NewDB(nil, pgdialect.New()), Fetch: client, Log: zerolog.New(io.Discard)}

	withBlob := base
	withBlob.BlobRead = bucket.Reader()
	require.ErrorContains(t, register(withBlob, river.NewWorkers()), "object-store credential")

	noFetch := base
	noFetch.Fetch = nil
	require.ErrorContains(t, register(noFetch, river.NewWorkers()), "no outbound client")

	noDB := base
	noDB.DB = nil
	require.ErrorContains(t, register(noDB, river.NewWorkers()), "no database handle")

	require.NoError(t, register(base, river.NewWorkers()))
}
