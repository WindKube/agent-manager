package outbox

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The sweep is what recovers a NOTIFY lost to a dropped connection, and the
// integration suite shortens it, so the shipped default is pinned here.
func TestTheSweepIntervalDefaultsToTenSeconds(t *testing.T) {
	require.Equal(t, 10*time.Second, DefaultSweepInterval)

	filled := RelayConfig{}.withDefaults()
	require.Equal(t, DefaultSweepInterval, filled.SweepInterval)
	require.Equal(t, DefaultPruneInterval, filled.PruneInterval)
	require.Equal(t, 24*time.Hour, filled.Retention, "delivered rows are pruned after 24 h")
	require.Equal(t, DefaultBatch, filled.Batch)

	explicit := RelayConfig{Batch: 7, SweepInterval: time.Second, PruneInterval: 2 * time.Second, Retention: 3 * time.Second}.withDefaults()
	require.Equal(t, explicit, RelayConfig{Batch: 7, SweepInterval: time.Second, PruneInterval: 2 * time.Second, Retention: 3 * time.Second})
}

// River's default of 25 attempts turns a persistently failing job into noise
// and makes the "retryable" count meaningless.
func TestMaxJobAttemptsIsThreeNotRiversDefaultTwentyFive(t *testing.T) {
	require.Equal(t, 3, MaxJobAttempts)
}

func TestAQueuedJobCarriesTheOutboxRowThrough(t *testing.T) {
	for _, tc := range []struct {
		name    string
		job     queuedJob
		want    string
		wantKey string
	}{
		{
			name:    "a payload passes through byte for byte",
			job:     queuedJob{kind: "scan", payload: json.RawMessage(`{"versionId":"abc","packVersion":"2026.08.1"}`)},
			want:    `{"versionId":"abc","packVersion":"2026.08.1"}`,
			wantKey: "scan",
		},
		{
			name:    "an empty payload becomes an empty object",
			job:     queuedJob{kind: "rescan-sweep"},
			want:    `{}`,
			wantKey: "rescan-sweep",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.wantKey, tc.job.Kind())

			encoded, err := json.Marshal(tc.job)
			require.NoError(t, err)
			require.JSONEq(t, tc.want, string(encoded))
		})
	}
}

func TestANotifyJobGetsTheWebhookRetryBudgetAndEveryOtherKindThree(t *testing.T) {
	require.Equal(t, 10, MaxAttempts(KindNotify))
	require.Equal(t, QueueNotify, Queue(KindNotify))
	for _, k := range []Kind{KindFetch, KindScan, KindRescanSweep} {
		require.Equal(t, MaxJobAttempts, MaxAttempts(k))
	}
}
