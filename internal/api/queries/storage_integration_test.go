//go:build integration

package queries

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/blob"
	"agent-manager/internal/store/models"
)

// Shares benchDB, the container catalog_bench_integration_test.go's TestMain
// already starts and migrates, rather than a second container this test needs
// nothing more than.
//
// memblob is the point of the bucket half: it cannot produce an *s3.Client, so
// it is the same answer a real bucket gives the api's read-only key when a
// setting call is refused, proving the unknown path with no live S3 account
// needed.
func TestStorageCountsByPrefixAndReportsUnknownSettingsOverAPlainBucket(t *testing.T) {
	ctx := t.Context()

	bucket, err := blob.Open(ctx, "mem://")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bucket.Close()) })

	writer := bucket.Writer()
	for _, key := range []string{
		"skills/acme/code-review/2.4.1/bundle.tar.zst",
		"skills/acme/code-review/2.4.1/plugin.json",
		"profiles/acme/platform-engineer/r1.json",
	} {
		_, writeErr := writer.Write(ctx, key, strings.NewReader("bytes"))
		require.NoError(t, writeErr)
	}

	attempt := &models.FetchAttempt{
		ID:           models.NewID(),
		SourceKind:   models.FetchSourceGit,
		RequestedRef: "https://example.dev/acme/code-review",
		Outcome:      models.FetchOutcomeOK,
	}
	_, err = benchDB.NewInsert().Model(attempt).Exec(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		// context.Background(), not ctx: t.Context() is already cancelled by the
		// time Cleanup runs.
		_, delErr := benchDB.NewDelete().Model((*models.FetchAttempt)(nil)).
			Where("id = ?", attempt.ID).Exec(context.Background())
		require.NoError(t, delErr)
	})

	report, err := Storage(ctx, benchDB, bucket.Inspector())
	require.NoError(t, err)

	require.EqualValues(t, 3, report.ObjectCount)
	require.False(t, report.Truncated)
	require.Empty(t, report.Region, "memblob carries no region")

	counts := map[string]int64{}
	for _, row := range report.KeyLayout {
		counts[row.Prefix] = row.Objects
	}
	require.EqualValues(t, 2, counts["skills"])
	require.EqualValues(t, 1, counts["profiles"])

	// A setting the bucket cannot answer is Known: false, never a guessed default
	// (Value left empty and never, say, "disabled").
	require.False(t, report.Bucket.Versioning.Known)
	require.Empty(t, report.Bucket.Versioning.Value)
	require.False(t, report.Bucket.ObjectLock.Known)
	require.False(t, report.Bucket.Encryption.Known)
	require.False(t, report.Bucket.Retention.Known)
	// WriteAccess is this role's own credential, not the bucket's report, so it is
	// always known — even here, where nothing else is.
	require.True(t, report.Bucket.WriteAccess.Known)
	require.NotEmpty(t, report.Bucket.WriteAccess.Value)

	// sync_event carries no cache-hit column, so this is unknown and not zero.
	require.Nil(t, report.ReadCacheHitRate)

	var found bool
	for _, fetch := range report.RecentFetches {
		if fetch.ID == attempt.ID.String() {
			found = true
			require.Equal(t, "ok", fetch.Outcome)
			require.Equal(t, "git", fetch.SourceKind)
			require.Equal(t, attempt.RequestedRef, fetch.RequestedRef)
		}
	}
	require.True(t, found, "the inserted fetch attempt did not appear in the recent-fetches page")
}
