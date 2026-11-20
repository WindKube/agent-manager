package fetcher

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/fetch"
	"agent-manager/internal/metrics"
)

func TestFetchOutcomesAreCountedBySourceAndResult(t *testing.T) {
	count := func(source fetch.SourceKind, result string) float64 {
		return testutil.ToFloat64(metrics.FetchesTotal.WithLabelValues(string(source), result))
	}
	stored := count(fetch.SourceGit, "stored")
	unchanged := count(fetch.SourceUpload, "unchanged")
	tooLarge := count(fetch.SourceArchiveURL, string(ReasonArchiveTooLarge))
	unclassified := count(fetch.SourceGit, "error")

	fetched(fetch.SourceGit, Result{}, nil)
	fetched(fetch.SourceUpload, Result{AlreadyStored: true}, nil)
	fetched(fetch.SourceArchiveURL, Result{}, &Error{Reason: ReasonArchiveTooLarge})
	fetched(fetch.SourceGit, Result{}, errors.New("not classified"))

	require.Equal(t, stored+1, count(fetch.SourceGit, "stored"))
	require.Equal(t, unchanged+1, count(fetch.SourceUpload, "unchanged"))
	require.Equal(t, tooLarge+1, count(fetch.SourceArchiveURL, string(ReasonArchiveTooLarge)))
	require.Equal(t, unclassified+1, count(fetch.SourceGit, "error"))
}
