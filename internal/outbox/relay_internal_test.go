package outbox

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The sweep interval is a guarantee, not a tuning knob: LISTEN/NOTIFY is
// fire-and-forget, so the sweep is the only thing that turns a notification lost
// to a dropped connection into seconds of delay rather than a job that never
// runs (R5). The integration suite shortens it to keep the tests fast, which is
// exactly why the shipped default is pinned here.
func TestTheSweepIntervalDefaultsToTenSeconds(t *testing.T) {
	require.Equal(t, 10*time.Second, DefaultSweepInterval)

	filled := RelayConfig{}.withDefaults()
	require.Equal(t, DefaultSweepInterval, filled.SweepInterval)
	require.Equal(t, DefaultPruneInterval, filled.PruneInterval)
	require.Equal(t, 24*time.Hour, filled.Retention, "data-model.md: delivered rows pruned after 24 h")
	require.Equal(t, DefaultBatch, filled.Batch)

	// An explicit value survives, so the defaults cannot silently override a
	// deployment that tuned one.
	explicit := RelayConfig{Batch: 7, SweepInterval: time.Second, PruneInterval: 2 * time.Second, Retention: 3 * time.Second}.withDefaults()
	require.Equal(t, explicit, RelayConfig{Batch: 7, SweepInterval: time.Second, PruneInterval: 2 * time.Second, Retention: 3 * time.Second})
}

// The relay is generic over job types: it hands River the payload exactly as the
// outbox stored it, so a new job kind needs no relay change.
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
