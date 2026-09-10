package hub_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/hub"
)

// TestRuntimeIsMappedFromTheApisAnswer asserts on the WIRE, like the rest of
// this package: a mapping bug here must not be able to cancel out against
// the same bug in the test.
func TestRuntimeIsMappedFromTheApisAnswer(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		writeCatalog(w, `{
		  "queues": [
		    {"queue":"fetch","counts":{"available":3,"scheduled":0,"running":1,"retryable":1,
		      "completed":900,"discarded":0,"cancelled":0,"other":0}},
		    {"queue":"scan","counts":{"available":0,"scheduled":0,"running":0,"retryable":0,
		      "completed":880,"discarded":1,"cancelled":2,"other":0}}
		  ],
		  "errors": {
		    "discarded": [
		      {"id":48213,"queue":"scan","kind":"scan","attempt":5,"maxAttempts":5,
		       "scheduledAt":"2026-09-10T08:00:00Z","finalizedAt":"2026-09-10T08:05:00Z",
		       "errors":[{"at":"2026-09-10T08:05:00Z","attempt":5,"error":"signature mismatch"}]}
		    ],
		    "retrying": [
		      {"id":48310,"queue":"fetch","kind":"fetch","attempt":2,"maxAttempts":5,
		       "scheduledAt":"2026-09-10T09:00:00Z",
		       "errors":[{"at":"2026-09-10T08:45:00Z","attempt":2,"error":"connection reset"}]}
		    ]
		  },
		  "runHistory": [{"startsAt":"2026-09-10T08:00:00Z","fetch":4,"scan":1}],
		  "bucketMinutes": 60
		}`)
	})

	report, err := client.Runtime(t.Context())
	require.NoError(t, err)

	require.Len(t, report.Queues, 2)
	require.Equal(t, "fetch", report.Queues[0].Queue)
	require.EqualValues(t, 3, report.Queues[0].Available)
	require.EqualValues(t, 1, report.Queues[0].Retryable)
	require.Equal(t, "scan", report.Queues[1].Queue)
	require.EqualValues(t, 1, report.Queues[1].Discarded)
	require.EqualValues(t, 2, report.Queues[1].Cancelled)

	require.Len(t, report.Discarded, 1)
	require.EqualValues(t, 48213, report.Discarded[0].ID)
	require.Equal(t, "scan", report.Discarded[0].Queue)
	require.Contains(t, report.Discarded[0].When, "2026-09-10")
	require.Equal(t, "signature mismatch", report.Discarded[0].LatestError())

	require.Len(t, report.Retrying, 1)
	require.EqualValues(t, 48310, report.Retrying[0].ID)
	// The retrying job's When is the api's scheduledAt (the next attempt),
	// never its finalizedAt — a job still retrying has none.
	require.Contains(t, report.Retrying[0].When, "2026-09-10 09:00")
	require.Equal(t, "connection reset", report.Retrying[0].LatestError())

	require.Len(t, report.History, 1)
	require.EqualValues(t, 4, report.History[0].Fetch)
	require.EqualValues(t, 1, report.History[0].Scan)
	require.Equal(t, 60, report.BucketMinutes)
}

// TestRuntimeRefusalIsDistinctFromAnUnreachableApi mirrors the other
// governance reads: a 403 must map to ErrForbidden specifically, never to
// the generic transport error a screen would render as "unavailable" —
// signing in again does not acquire a role.
func TestRuntimeRefusalIsDistinctFromAnUnreachableApi(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		writeCatalog(w, `{"title":"forbidden","status":403}`)
	})

	_, err := client.Runtime(t.Context())
	require.ErrorIs(t, err, hub.ErrForbidden)
}
